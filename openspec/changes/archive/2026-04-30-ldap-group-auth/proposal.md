# Proposal: LDAP Group-Based Authorization

## Intent

Engram Cloud authenticates every request with a single static `ENGRAM_CLOUD_TOKEN` and uses one global project allowlist. This does not scale to multiple teams sharing one cloud instance. Add an opt-in, feature-flagged authentication path that delegates LDAP work to a pre-existing 3rd-party auth service and uses the JWT it returns to derive per-user, per-group project authorization inside Engram Cloud.

## Scope

### In Scope
- Feature flag `ENGRAM_AUTH_MODE=token|ldap` (mutually exclusive, default `token`).
- Proxy endpoint `POST /auth/ldap/login` that forwards credentials to `<ENGRAM_AUTH_URL>` and returns the upstream JWT verbatim.
- Per-request authorizer derived from the JWT's `groups` claim, attached via `context.Context`.
- Env-encoded group→projects mapping `ENGRAM_LDAP_GROUP_MAP`, parsed once at boot. Wildcard `*` supported via existing `WildcardProject` sentinel. Multi-group users get the union of mapped projects.
- CLI `engram cloud login --ldap` (interactive prompt, stores JWT in the same config slot as the static token).
- HTTP timeout (10s, hardcoded) on calls to the 3rd-party service.

### Out of Scope
- Any in-process LDAP client — `go-ldap` is **not** a dependency. The 3rd-party service handles all LDAP.
- JWT signature verification (decode-only in v1; flagged for future hardening).
- Owner/admin/contributor role split, project `owner_id` schema migration.
- Audit logging of authentications.
- Hot-reload of the group map.
- `both` auth mode (token + LDAP simultaneously).

## Capabilities

### New Capabilities
- `ldap-group-authorization`: feature-flagged auth path, login proxy, JWT claim extraction, group→project mapping, per-request authorizer, CLI login.

### Modified Capabilities
None. (Existing `Authorizer` / `ProjectAuthorizer` interfaces in `cloudserver` are extended via new implementations, not modified at the spec level.)

## Approach

The cloud server gains a second `Authorizer`/`ProjectAuthorizer` pair selected by `ENGRAM_AUTH_MODE`. In `ldap` mode: incoming `Authorization: Bearer <jwt>` is decoded (no signature check), `groups` claim resolves through the env-loaded map to a set of projects, and a per-request `ProjectScopeAuthorizer` is attached to `r.Context()`. The handler-level project check at `cloudserver.go:505` reads the authorizer from context when present, otherwise falls back to the global one (preserves token-mode behavior). The login proxy is a thin `httputil.ReverseProxy`-style forwarder.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `internal/cloud/auth/auth.go` | Modified | New `LDAPAuthorizer`, JWT decode helper, context key for per-request authorizer. |
| `internal/cloud/auth/groupmap.go` | New | Parser for `ENGRAM_LDAP_GROUP_MAP`. |
| `internal/cloud/auth/loginproxy.go` | New | `POST /auth/ldap/login` forwarder. |
| `internal/cloud/config.go` | Modified | Read `ENGRAM_AUTH_MODE`, `ENGRAM_AUTH_URL`, `ENGRAM_LDAP_GROUP_MAP`. |
| `internal/cloud/cloudserver/cloudserver.go` | Modified | Mount login route; middleware attaches per-request authorizer; handler check prefers context authorizer. |
| `cmd/engram/cloud.go` | Modified | Wire new config into `Service` factory; pick authorizer by mode. |
| `cmd/engram/main.go` | Modified | Add `engram cloud login --ldap` subcommand. |
| `docker/cloud/entrypoint.sh` | Modified | Document new env vars. |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Decode-only JWT trusts payload integrity. | Med | Document as v1 accepted risk; signature verification listed as future hardening. JWTs only enter through our own proxy, narrowing exposure. |
| `ENGRAM_LDAP_GROUP_MAP` hits OS env-var size limits at scale. | Low | Document ~30KB practical cap; DB-backed mapping is v2 if needed. |
| Switching `ENGRAM_AUTH_MODE` invalidates all in-flight sessions on restart. | Med | Operationally expected; document in upgrade notes. |
| Per-request authorizer plumbing regresses token mode. | Low | Explicit branch in middleware + token-mode integration tests. |
| 3rd-party auth service downtime blocks logins. | Med | Existing JWTs (long-lived) keep working until expiry; document recovery. |

## Rollback Plan

Set `ENGRAM_AUTH_MODE=token`, unset LDAP env vars, restart `engram cloud serve`. The static `ENGRAM_CLOUD_TOKEN` path is the default branch and resumes immediately. New code paths are dormant when the flag is off — no DB migration to revert, no on-disk state created by this change.

## Dependencies

- Pre-existing 3rd-party LDAP auth service reachable at `<ENGRAM_AUTH_URL>`. Operator's responsibility, not built here.
- `github.com/golang-jwt/jwt/v5` (verify presence in `go.mod`; add if missing for payload decoding).

## Open Decisions

- `ENGRAM_AUTH_URL` semantics: full login URL (`https://idp/api/v1/ldap/auth/login`) vs base URL (`https://idp`) with hardcoded path suffix. Recommend **full URL** for flexibility.
- CLI persistence: reuse existing token config file, or new section. Recommend **same slot** so handlers stay generic.

## Success Criteria

- [ ] `ENGRAM_AUTH_MODE=token` (default) keeps every existing test green; no behavior change.
- [ ] `ENGRAM_AUTH_MODE=ldap` + valid `ENGRAM_AUTH_URL` + `ENGRAM_LDAP_GROUP_MAP` allows a user with a mapped group to access exactly the listed projects; 403 on others.
- [ ] User with no mapped groups → 403 with clear message.
- [ ] `*` wildcard grants all projects.
- [ ] `engram cloud login --ldap` round-trips against a stub 3rd-party endpoint and stores the returned JWT.
- [ ] `go test ./...` passes; integration tests cover both modes.
