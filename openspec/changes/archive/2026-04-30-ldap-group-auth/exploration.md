# Exploration: ldap-group-auth

## Context

Engram Cloud currently authenticates every request with a single static bearer token (`ENGRAM_CLOUD_TOKEN`) compared via plain string equality in `internal/cloud/auth/auth.go:Authorize`. Authorization to specific projects is handled by an in-memory allowlist (`SetAllowedProjects` / `AuthorizeProject`) that the operator configures via `ENGRAM_CLOUD_ALLOWED_PROJECTS`. The model is **one token, one global allowlist** — there is no concept of users, groups, or per-user project access.

This does not scale to multiple teams sharing the same cloud instance. The user wants LDAP-backed authentication where the directory is the source of truth for identity and group membership, and group membership maps to a set of accessible projects. The change must be **opt-in via feature flag** so existing token-based deployments continue to work unchanged.

## Constraints (user-confirmed)

1. **Library**: `github.com/go-ldap/ldap/v3` only. No OIDC/Keycloak indirection.
2. **Coexistence**: Feature flag — the static-token path is the default and must keep working when LDAP is off.
3. **Group→project mapping storage**: environment variables only. No database table, no YAML in repo.
4. **Authorization model in v1**: project owner stays as admin (unchanged); LDAP-authenticated users get **contributor** by default. No reader/admin elevation through groups in v1.

## Current State (verified in code)

- `internal/cloud/auth/auth.go`
  - `Service.Authorize(r)` — extracts `Authorization: Bearer …` and compares to `s.expectedToken` via `==` (line 279).
  - `Service.AuthorizeProject(project)` — checks the project against `s.allowed` map (or `allowAll` for `*`).
  - `ProjectScopeAuthorizer` — alternate object exposing the same allowlist semantics; used independently of `Service`.
  - The auth/authz boundary is **already split into two interfaces** (`Authorizer` and `ProjectAuthorizer`) consumed by `cloudserver` (line 32–36 of `cloudserver.go`). This is the cleanest seam to extend for LDAP.
- `internal/cloud/cloudserver/cloudserver.go`
  - Wires authorizer at construction via `WithProjectAuthorizer` and calls `s.auth.Authorize(req)` in middleware (lines 208, 220, 249).
  - `s.projectAuth.AuthorizeProject(project)` enforced at handler level (line 505).
- `internal/cloud/config.go`
  - All config from env. `ENGRAM_CLOUD_ALLOWED_PROJECTS` is the closest analog to what LDAP-mode will replace per-user.
- `internal/cloud/cloudstore/cloudstore.go`
  - **No `owner_id` / `Owner` field exists on the project model today.** The user's statement *"owner se mantiene, es el admin"* assumes a concept that is not in the code yet. **This is the most important open question** — see below.

## Affected Areas

- `internal/cloud/auth/auth.go` — new LDAP authenticator implementing `Authorizer`; new per-request `ProjectAuthorizer` resolved from groups.
- `internal/cloud/auth/ldap.go` *(new)* — LDAP client, bind, group resolution.
- `internal/cloud/auth/groupmap.go` *(new)* — parser for env-encoded group→projects mapping.
- `internal/cloud/auth/session.go` *(new)* — internal-JWT issuance after successful LDAP bind, embedding resolved groups + projects as claims.
- `internal/cloud/config.go` — new env vars (`ENGRAM_AUTH_MODE`, `ENGRAM_LDAP_*`, `ENGRAM_LDAP_GROUP_MAP`).
- `internal/cloud/cloudserver/cloudserver.go` — new `/auth/ldap/login` endpoint; auth middleware must support **per-request authorizer resolution** (because each request now has its own user-scoped allowlist), not the global one used today.
- `cmd/engram/cloud.go` — wire new env vars into `Config` and `Service` factories.
- `cmd/engram/main.go` — possibly a new `engram cloud login --ldap` UX flow on the client side.
- `docker/cloud/Dockerfile` / `entrypoint.sh` — document new env vars.

## Approach Options

### A. Bind strategy: user-DN-template vs search-then-bind

| Aspect | DN template (`uid=%s,ou=people,dc=corp,dc=com`) | Search-then-bind (anonymous or service-account search → user bind) |
|---|---|---|
| LDAP roundtrips | 1 (bind only) | 2 (search + bind) |
| Schema flexibility | Fails when DN structure varies (people in multiple OUs) | Handles arbitrary tree shapes |
| Setup complexity | Just a template string | Service account creds + search base + filter |
| Production fit | OK for flat directories | Industry default — works with AD, FreeIPA, OpenLDAP |

**Recommendation**: **search-then-bind**. AD almost always requires it (sAMAccountName lookup → DN). Adds one env var (`ENGRAM_LDAP_BIND_DN` + `ENGRAM_LDAP_BIND_PASSWORD` for the service account) but covers >95% of real deployments. Optionally allow DN template as a fallback for simple cases.

### B. Credential delivery: basic-auth-per-request vs login-endpoint-issues-JWT

| Aspect | Basic auth on every request | Login endpoint → server-issued internal JWT |
|---|---|---|
| LDAP load | One bind per request | One bind per session (~hours) |
| Latency added | LDAP roundtrip on hot path | Only on `/auth/ldap/login` |
| Credential exposure | Password in every header | Password sent once over TLS |
| Revocation granularity | Immediate (next request re-binds) | JWT lifetime (typical: short-lived + refresh) |
| Reuses existing infra | Duplicates bearer parsing | Uses `s.jwtSecret` already in `Service` |
| Maps to user's mental model | Mismatch — they said "decode the JWT for groups" | Direct match |

**Recommendation**: **login endpoint issues internal JWT**. The user phrased the requirement as *"decodifica el JWT y obtiene los grupos a los que pertenece el usuario"*. With pure LDAP there is no incoming JWT — but we can flip it: after successful LDAP bind, the cloud server **mints its own JWT** with `groups` and `projects` claims, signed with the existing `JWTSecret`. The client then sends this JWT as `Authorization: Bearer …`. This (a) matches the user's mental model, (b) reuses existing JWT infrastructure (`MintDashboardSession` follows the same pattern), and (c) avoids hammering the LDAP server.

### C. Group source: `memberOf` attribute vs explicit group-search filter

| Aspect | Read `memberOf` from user entry | Search `(&(objectClass=group)(member={userDN}))` |
|---|---|---|
| AD support | Native (`memberOf` is overlay) | Native |
| OpenLDAP support | Requires memberOf overlay enabled | Always works |
| Nested groups | Only direct in OpenLDAP; AD has `LDAP_MATCHING_RULE_IN_CHAIN` | Manual recursion or extension OID |
| Extra roundtrip | No (came back with user search) | Yes |

**Recommendation**: **prefer `memberOf` attribute**, fall back to group-search if `ENGRAM_LDAP_GROUP_FILTER` is set. AD users get the fast path; OpenLDAP without memberOf overlay can opt into the search-based path. v1 ships with `memberOf` only and documents the fallback as future work if a user reports an issue.

### D. Group→project mapping schema

Two candidate env-var formats:

**Option D1** — single var with separators:
```
ENGRAM_LDAP_GROUP_MAP="cn=ops,ou=groups,dc=corp,dc=com:proj-a,proj-b;cn=devs,ou=groups,dc=corp,dc=com:proj-c,proj-d"
```
- Pros: one variable, easy to set in compose/k8s.
- Cons: ugly with full DNs; semicolons inside DNs are illegal but still error-prone visually.

**Option D2** — per-group prefixed vars:
```
ENGRAM_LDAP_GROUP_MAP_OPS="cn=ops,ou=groups,dc=corp,dc=com=proj-a,proj-b"
ENGRAM_LDAP_GROUP_MAP_DEVS="cn=devs,ou=groups,dc=corp,dc=com=proj-c,proj-d"
```
- Pros: each group gets its own var; easier to manage in secret stores.
- Cons: reading needs a prefix scan over `os.Environ()`.

**Recommendation**: **D1 (single var)** for v1. Simpler to parse, simpler to document, simpler to test. The format matches the precedent set by `ENGRAM_CLOUD_ALLOWED_PROJECTS`. Switch to D2 only if a real deployment hits the limit.

Edge cases:
- **User in multiple groups** → union of their projects (with dedup).
- **User in zero mapped groups** → deny login (401 + clear message). Authentication succeeds in LDAP but there is nothing to authorize, which is operator misconfiguration.
- **Wildcard group → `*`** → grants `WildcardProject` (already supported by `ProjectScopeAuthorizer`). Useful for `cn=admins`.
- **Reload semantics**: parsed once at boot (matches every other config var). Hot reload is out of scope for v1; document `kill -HUP` / restart as the way to refresh.

### E. Authorization integration

The existing `Service.Authorize` returns identity-only (token matches). The existing `ProjectScopeAuthorizer.AuthorizeProject` is a **process-global** singleton. With LDAP, each request has a **user-scoped** allowlist derived from their groups, so the global singleton model breaks.

Two options:

**Option E1** — Per-request `ProjectAuthorizer` carried via `context.Context`. The LDAP-aware `Authorizer` decodes the internal JWT, builds a `ProjectScopeAuthorizer` from the JWT's `projects` claim, attaches it to context, and the existing handler-level check at `cloudserver.go:505` reads it from context.
- Pros: keeps the existing two-stage check (auth then authz). Minimal middleware changes.
- Cons: requires plumbing `ctx` through the call site that today gets the global authorizer.

**Option E2** — Combined `Authorize(r) → (UserCtx, error)` that returns identity + allowed projects in one struct, and rewrite the handler check to call the user-scoped object.
- Pros: cleaner data flow.
- Cons: bigger refactor of the `Authorizer` interface contract; touches more code than v1 needs.

**Recommendation**: **E1**. Smaller blast radius, keeps the dual-interface design intact.

Layering on owner check: when (and if) the project model gains an `owner_id`, the handler check becomes:
1. If `user_id == project.owner_id` → admin (full access).
2. Else if `project ∈ ctx.AllowedProjects` → contributor (the v1 default for everyone non-owner).
3. Else → 403.

Today step 2 is the only check that exists; step 1 and the role distinction are **deferred to a later change** unless the user wants them in scope (see open questions).

HTTP codes:
- `401` → no/invalid credentials (LDAP bind failed, token invalid).
- `403` → authenticated but not authorized for this project.
- `404` → only when the project genuinely does not exist; do **not** mask 403 as 404 in v1 (the existing behavior in `AuthorizeProject` returns an error that bubbles up — preserve current semantics).

### F. Backwards compatibility

- `ENGRAM_AUTH_MODE` env var: `token` (default) | `ldap` | `both`.
  - `token` — current behavior, no LDAP code paths exercised.
  - `ldap` — only LDAP-issued JWTs accepted; `ENGRAM_CLOUD_TOKEN` ignored.
  - `both` — both accepted (token continues to work, LDAP also works). **Recommended default migration path.**
- Existing `eng_*` API keys (the SHA-256 hashed kind) are an orthogonal mechanism. They keep working in all modes — they are not LDAP-bound. Document this clearly.
- Migration path for a team enabling LDAP:
  1. Set `ENGRAM_AUTH_MODE=both` + LDAP env vars + group map.
  2. Verify users can log in via `/auth/ldap/login` and access their projects.
  3. Flip to `ENGRAM_AUTH_MODE=ldap` once everyone has migrated. The static token stops working from that point.

### G. CLI UX (`engram cloud login`)

Current: client reads `ENGRAM_CLOUD_TOKEN` and stores it in a config file.

Proposed: when the server is in LDAP mode, the client gains `engram cloud login --ldap`:
1. Prompt for username + password.
2. POST to `/auth/ldap/login`.
3. Store the returned internal JWT in the same config file slot the static token uses today.
4. On 401, prompt re-login. No automatic refresh in v1 (keep tokens long-lived ~24h to minimize friction).

## Recommended Direction

For `sdd-propose` and downstream phases, carry forward:
- **Library**: `go-ldap/ldap/v3` with **search-then-bind** (service account in `ENGRAM_LDAP_BIND_DN` / `…_PASSWORD`).
- **Flow**: client posts credentials to `/auth/ldap/login` → server binds → reads `memberOf` → resolves group→projects → mints internal JWT signed with existing `JWTSecret` carrying `sub` (user DN), `groups`, `projects`, `exp` claims (~24h) → returns JWT. Subsequent requests send `Authorization: Bearer <internal-jwt>`.
- **Feature flag**: `ENGRAM_AUTH_MODE=token|ldap|both`, default `token`. `both` is the recommended migration mode.
- **Group map env**: single `ENGRAM_LDAP_GROUP_MAP="<group-dn>:<proj1>,<proj2>;<group-dn>:<proj>"`. Wildcard `*` supported. Multi-group = union. No mapped groups = deny.
- **Authz integration**: per-request `ProjectAuthorizer` attached to `context.Context` by an LDAP-aware middleware variant. Existing handler check at `cloudserver.go:505` switches to reading from context when LDAP is active.
- **Backwards compat**: token mode unchanged; API keys (`eng_*`) orthogonal to all of this.

## Risks

1. **Owner concept does not exist in the project model today.** The user said "owner se mantiene, es el admin" — but cloudstore has no `owner_id`. Either (a) we add it as part of this change, or (b) we treat "owner=admin" as aspirational and v1 ships with everyone-is-contributor. **This must be answered before propose.**
2. **LDAP availability becomes a hard dependency in `ldap` mode.** If the directory goes down, no one can log in. Mitigation: dual-mode (`both`) and JWTs with multi-hour TTLs so existing sessions survive a brief LDAP outage.
3. **Per-request authorizer plumbing through `context.Context`** is a behavioral change in the cloudserver — risk of regressing existing token-mode handlers if the lookup falls back incorrectly. Mitigation: explicit branch in middleware; thorough tests for token-mode after the change.
4. **Group→project mapping in env vars caps the practical size.** ~30 KB of env is the typical OS limit; ~10–50 groups times typical project counts fit easily, but a 1000-team deployment will not. Document this and recommend DB-backed mapping as a v2 if it ever becomes real.
5. **AD vs OpenLDAP behavioral differences** (memberOf overlay, paging, referrals). Mitigation: ship with AD-tested defaults, document OpenLDAP-specific knobs.
6. **TLS/LDAPS configuration is non-trivial** (CA bundles, hostname verification, StartTLS upgrades). Mitigation: support LDAPS via `ldaps://` URL and StartTLS via `ENGRAM_LDAP_STARTTLS=true`, default to **requiring** TLS unless `ENGRAM_LDAP_INSECURE=true` is explicitly set.

## Open Questions for User

These need answers before `sdd-propose`:

1. **Owner concept**: cloudstore today has no `owner_id` on projects. Options:
   - **(a)** Add `owner_id` to the project model in this change. Owner becomes admin per your statement; everyone else from LDAP becomes contributor. Bigger scope but matches your description literally.
   - **(b)** Defer owner/role split. v1 LDAP just grants contributor-equivalent access (the same access the bearer token has today) to anyone in a mapped group. "Owner=admin" lands in a follow-up change. Smaller scope.
   - Which one?
2. **`ENGRAM_AUTH_MODE` values**: are `token | ldap | both` correct, or do you want LDAP exclusive (`token | ldap`) without the dual-mode option? Recommend `both` for safe migration.
3. **JWT TTL**: I'm proposing 24h for the LDAP-issued internal JWT. Acceptable, or shorter (e.g. 8h with refresh tokens)?
4. **CLI UX**: do you want `engram cloud login --ldap` (interactive prompt) in this change, or is the API endpoint enough for v1 (clients can curl it)?
5. **Audit logging**: should successful LDAP binds + group resolution be logged (which user, which groups, which resolved projects)? Recommend yes — minimal cost, big debug value.
6. **TLS posture**: confirm "TLS required by default, opt-out via `ENGRAM_LDAP_INSECURE=true`" — I want to flag this loudly because it diverges from many tutorials that default to plain LDAP.
7. **Pool/timeouts**: connection pool size and dial timeout for LDAP. Sensible defaults (pool=10, dial=5s, op=10s) or do you have org-specific values?

## Ready for Proposal

**Partially**. The technical direction is clear and ready to spec. Question #1 (owner concept) is **load-bearing for scope** — it changes the size of the change from "auth feature" to "auth feature + project model migration". Resolve it before launching `sdd-propose`. Questions 2–7 can be answered during propose without re-doing this exploration.
