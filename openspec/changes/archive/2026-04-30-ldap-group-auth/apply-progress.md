# Apply Progress: ldap-group-auth

## Batch 1 — Phase 1 (Foundation: config + parsing)

**Mode**: Strict TDD
**Status**: success

### Completed Tasks
- [x] 1.1 go.mod verified: `golang.org/x/term v0.42.0` already present; added `github.com/golang-jwt/jwt/v5 v5.3.1` via `go get`.
- [x] 1.2 RED tests written for `ENGRAM_AUTH_MODE` / `ENGRAM_AUTH_URL` / `ENGRAM_LDAP_GROUP_MAP` (compile failed, confirming RED).
- [x] 1.3 GREEN: added `AuthMode`, `AuthURL`, `LDAPGroupMap` fields + `AuthModeToken/AuthModeLDAP` constants + env parsing in `ConfigFromEnv`.
- [x] 1.4 RED tests written for `ParseGroupMap` (12 cases) and `ProjectsFor` (6 cases) — build failed (RED).
- [x] 1.5 GREEN: `groupmap.go` implements `ParseGroupMap` + `parseProjectList` + `ProjectsFor`. All 18 cases pass.

### Files Changed
| File | Action | What Was Done |
|------|--------|---------------|
| `go.mod` / `go.sum` | Modified | Added `github.com/golang-jwt/jwt/v5 v5.3.1`. |
| `internal/cloud/config.go` | Modified | Added `AuthMode`, `AuthURL`, `LDAPGroupMap` fields; `AuthModeToken`/`AuthModeLDAP` constants; env parsing with invalid-mode validation; `DefaultConfig` defaults `AuthMode` to `"token"`. |
| `internal/cloud/config_test.go` | Modified | Added `TestConfigFromEnvAuthMode` (4 sub-tests), `TestConfigFromEnvAuthURL` (2), `TestConfigFromEnvLDAPGroupMap` (2). |
| `internal/cloud/auth/groupmap.go` | Created | `ParseGroupMap` (BNF grammar enforcement) + `ProjectsFor` (union+dedup). |
| `internal/cloud/auth/groupmap_test.go` | Created | 12 cases for `ParseGroupMap`, 6 cases for `ProjectsFor`. |

### TDD Cycle Evidence
| Task | Test File | Layer | Safety Net | RED | GREEN | TRIANGULATE | REFACTOR |
|------|-----------|-------|------------|-----|-------|-------------|----------|
| 1.1 | N/A (dep mgmt) | N/A | ✅ baseline pass | ➖ no test | ➖ verified via `go list -m` | ➖ N/A | ➖ N/A |
| 1.2 | `config_test.go` | Unit | ✅ existing tests green | ✅ Written (compile fail) | ➖ deferred to 1.3 | ✅ 4 sub-cases | ➖ none needed |
| 1.3 | `config_test.go` | Unit | ✅ existing tests green | ✅ from 1.2 | ✅ Passed | ✅ default/ldap/invalid/whitespace | ➖ minimal impl |
| 1.4 | `groupmap_test.go` | Unit | ✅ N/A (new file) | ✅ Written (build fail) | ➖ deferred to 1.5 | ✅ 12 + 6 cases | ➖ none needed |
| 1.5 | `groupmap_test.go` | Unit | ✅ N/A (new file) | ✅ from 1.4 | ✅ All 18 pass | ✅ wildcard, dup, missing-colon, empty-projects, multi-group union, unmapped | ✅ extracted `parseProjectList` helper |

### Test Summary
- Total tests written this batch: 18 (12 ParseGroupMap + 6 ProjectsFor + 8 config sub-tests = 26 sub-tests)
- All passing: ✅
- Layers used: Unit (all)
- Pure functions created: 2 (`ParseGroupMap`, `ProjectsFor`) + 1 helper (`parseProjectList`)
- Safety net `go test ./internal/cloud/...`: all green, no regressions.

### Deviations from Design
None — implementation matches design BNF grammar. One minor enhancement: `ProjectsFor` deduplicates projects-within-group (defensive; design only required cross-group dedup).

### Issues Found
None.

### Remaining Tasks
- [ ] Phase 2: Auth core (loginproxy, ldap authorizer, ctx helpers) — tasks 2.1–2.5
- [ ] Phase 3: Cloudserver wiring — tasks 3.1–3.3
- [ ] Phase 4: Boot + CLI — tasks 4.1–4.4
- [ ] Phase 5: Docs + integration — tasks 5.1–5.3

### Status (after Batch 1)
5/20 tasks complete.

---

## Batch 2 — Phase 2 (Auth core)

**Mode**: Strict TDD
**Status**: success

### Completed Tasks
- [x] 2.1 RED: `loginproxy_test.go` — 4 cases (200 passthrough with body forwarding, 401 passthrough, 504 on timeout, 502 on connection refused). Build failed → real RED.
- [x] 2.2 GREEN: `loginproxy.go` — `LoginProxy{UpstreamURL,Client}` + `NewLoginProxy(url, timeout)`; `ServeHTTP` builds upstream POST with ctx, forwards `Content-Type`, copies body; distinguishes timeout (504) vs connect failure (502); copies upstream headers + status + body verbatim.
- [x] 2.5 GREEN: `auth.go` — `ctxKey` private type, `requestAuthorizerKey`, `WithRequestAuthorizer(ctx, *PSA) ctx`, `RequestAuthorizerFromContext(ctx) (*PSA, bool)`. (Ordered before 2.4 to satisfy 2.3's test imports.)
- [x] 2.3 RED: `ldap_test.go` — 10 cases covering valid+groups→ctx PSA attached, multi-group union, wildcard claim, missing bearer → `ErrLDAPMissingBearer`, malformed JWT → `ErrLDAPInvalidJWT`, empty/missing groups → `ErrLDAPNoAuthorizedGroups`, unmapped-only group → `ErrLDAPNoAuthorizedGroups`, non-Bearer scheme rejected, satisfies Authenticator. Build failed → real RED.
- [x] 2.4 GREEN: `ldap.go` — `LDAPAuthorizer{groupMap, parser}` + `NewLDAPAuthorizer(map)`. `Authorize(r) error` delegates to `AuthorizeRequest`. `AuthorizeRequest(r) (*http.Request, error)` does: bearer extract → `ParseUnverified` → coerce groups claim ([]interface{} or []string) → `ProjectsFor` → `NewProjectScopeAuthorizer` → `WithRequestAuthorizer` ctx → returns mutated request. Sentinel errors `ErrLDAPMissingBearer`, `ErrLDAPInvalidJWT`, `ErrLDAPNoAuthorizedGroups`. Inline SECURITY comment documents decode-only by design.

### Files Changed (Batch 2)
| File | Action | What Was Done |
|------|--------|---------------|
| `internal/cloud/auth/auth.go` | Modified | Added `context` import, private `ctxKey`/`requestAuthorizerKey`, `WithRequestAuthorizer`, `RequestAuthorizerFromContext`. |
| `internal/cloud/auth/loginproxy.go` | Created | `LoginProxy` + `NewLoginProxy` + `ServeHTTP` with timeout-vs-connect distinction. |
| `internal/cloud/auth/loginproxy_test.go` | Created | 4 cases. |
| `internal/cloud/auth/ldap.go` | Created | `LDAPAuthorizer` + sentinel errors + `bearerToken` + `decodeGroupsClaim`. SECURITY comment. |
| `internal/cloud/auth/ldap_test.go` | Created | 10 cases including `mintTestJWT` helper. |

### TDD Cycle Evidence (Batch 2)
| Task | Test File | Layer | Safety Net | RED | GREEN | TRIANGULATE | REFACTOR |
|------|-----------|-------|------------|-----|-------|-------------|----------|
| 2.1 | `loginproxy_test.go` | Unit | N/A (new) | ✅ Written | (paired w/ 2.2) | ✅ 4 distinct error paths | ➖ |
| 2.2 | `loginproxy_test.go` | Unit | N/A (new) | ✅ from 2.1 | ✅ All 4 pass | ✅ 200/401/504/502 | ✅ extracted `isTimeoutError` |
| 2.5 | (consumed by 2.3) | Unit | ✅ existing green | (covered indirectly) | ✅ via 2.3/2.4 | N/A | ➖ |
| 2.3 | `ldap_test.go` | Unit | N/A (new) | ✅ Written | (paired w/ 2.4) | ✅ 10 cases | ➖ |
| 2.4 | `ldap_test.go` | Unit | N/A (new) | ✅ from 2.3 | ✅ All 10 pass | ✅ valid/multi/wildcard/missing/malformed/empty-groups/missing-claim/unmapped/wrong-scheme/iface-conformance | ✅ extracted `bearerToken`, `decodeGroupsClaim` |

### Test Summary (Batch 2)
- Tests written: 14 cases across 2 new files
- Total cumulative: 32 cases passing
- Layers: Unit (all)
- Pure functions added: 4 (`bearerToken`, `decodeGroupsClaim`, `isTimeoutError`, `NewLoginProxy`)
- Safety net `go test ./internal/cloud/...`: all green, no regressions.

### Deviations from Design
- **Order**: implemented 2.5 (ctx helpers) BEFORE 2.4 because 2.3's test (RED for ldap.go) imports `RequestAuthorizerFromContext`. Tasks reflect logical sequencing; functional outcome identical.
- **Implementation enhancement**: `decodeGroupsClaim` accepts both `[]interface{}` (jwt/v5 default) and `[]string` (test-mintable) for ergonomic test setup. Spec scenarios still hold because production JWTs come through `ParseUnverified` which produces `[]interface{}`.

### Issues Found
None.

### Status (after Batch 2)
10/20 tasks complete.

---

## Batch 3 — Phase 3 (Cloudserver wiring)

**Mode**: Strict TDD
**Status**: success

### Completed Tasks
- [x] 3.1 RED: `cloudserver_ldap_test.go` — 7 cases (proxy forward verbatim, 404 in token mode, mapped→200, unmapped→403, no-groups→403, malformed→401, wildcard→all). Build failed (`undefined: WithLoginProxy`) → real RED.
- [x] 3.2 GREEN: `cloudserver.go` — added `RequestAuthorizer` interface; `loginProxy http.Handler` field on `CloudServer`; `WithLoginProxy(h)` Option; route mount conditional `if s.loginProxy != nil`; `runAuthMiddleware(w, r) (mutated, ok)` extracted; both `withAuth`/`withAuthHandler` rewritten to use it; `writeAuthError` maps `cloudauth.ErrLDAPNoAuthorizedGroups` → 403, else 401; `authorizeProjectScopeForRequest(w, r, project)` ctx-first with global fallback (preserves token-mode); existing `authorizeProjectScope(w, project)` kept as `(w, nil, project)` shim. Updated 3 handler call sites: `handlePullManifest`, `handlePullChunk`, `handlePushChunk` to pass `r`.
- [x] 3.3 Full `go test ./...` whole-repo run: all 21 packages green. Token-mode regression preserved bit-for-bit.

### Files Changed (Batch 3)
| File | Action | What Was Done |
|------|--------|---------------|
| `internal/cloud/cloudserver/cloudserver.go` | Modified | Added `RequestAuthorizer` interface, `WithLoginProxy` Option, `loginProxy` field, conditional route mount, `runAuthMiddleware` helper, `writeAuthError` (LDAP 403 mapping), `authorizeProjectScopeForRequest` ctx-first variant. Imported `cloudauth`. |
| `internal/cloud/cloudserver/cloudserver_ldap_test.go` | Created | 7 cases + `mintTestJWTForCloud` helper. |

### TDD Cycle Evidence (Batch 3)
| Task | Test File | Layer | Safety Net | RED | GREEN | TRIANGULATE | REFACTOR |
|------|-----------|-------|------------|-----|-------|-------------|----------|
| 3.1 | `cloudserver_ldap_test.go` | Integration (httptest) | ✅ existing token-mode tests green | ✅ Written (compile fail) | (paired w/ 3.2) | ✅ 7 cases | ➖ |
| 3.2 | `cloudserver_ldap_test.go` | Integration | ✅ ran existing tests post-change → all green | ✅ from 3.1 | ✅ All 7 + token-mode regression pass | ✅ login-proxy/404-token/mapped/unmapped/no-groups/malformed/wildcard | ✅ extracted `runAuthMiddleware`, `writeAuthError`, `authorizeProjectScopeForRequest` |
| 3.3 | `go test ./...` | Suite-wide | N/A | N/A | ✅ 21 pkgs green | N/A | N/A |

### Test Summary (Batch 3)
- Tests written: 7 integration cases
- Cumulative across all batches: **39 cases** passing
- Layers: Integration via `httptest.NewServer` for upstream + `httptest.NewRecorder` for cloud server
- Pure functions: `runAuthMiddleware`, `writeAuthError`, `authorizeProjectScopeForRequest` are not pure (they write to ResponseWriter) but are now isolated, single-responsibility helpers.
- Whole-repo `go test ./...` GREEN.

### Deviations from Design
- **Naming**: design said `effectiveProjectAuthorizer(r)`. I used `authorizeProjectScopeForRequest(w, r, project)` instead — same intent (ctx-first → global fallback) but encapsulates the response-writing path so call sites stay tiny. Functionally identical to design.
- **Backward compat shim**: kept the old `authorizeProjectScope(w, project)` as a thin wrapper calling the new function with `r=nil`. Avoids touching call sites that don't need ctx (none currently, but defensive). Could be removed later — flagged for `simplify` review if needed.

### Issues Found
None.

### Status (after Batch 3)
13/20 tasks complete.

---

## Batch 4 — Phase 4 (Boot + CLI)

**Mode**: Strict TDD
**Status**: success

### Completed Tasks
- [x] 4.1 RED: `cloud_ldap_test.go` — 6 cases for `validateCloudServeAuthConfig` in ldap mode (URL required, GROUP_MAP required, CLOUD_TOKEN rejected, malformed map rejected, happy path, token-mode regression). Tests failed initially → real RED.
- [x] 4.2 GREEN: `cmd/engram/cloud.go` — Added LDAP-mode branch at top of `validateCloudServeAuthConfig`: validates URL + group map presence, rejects co-existing CLOUD_TOKEN/INSECURE, parses map at boot via `auth.ParseGroupMap` to surface grammar errors early. `newCloudRuntime` branches on `cfg.AuthMode`: in `ldap` mode, builds `auth.NewLDAPAuthorizer(parsedMap)` + `auth.NewLoginProxy(cfg.AuthURL, 10s)`, wires via `WithLoginProxy`. Token path unchanged.
- [x] 4.3 RED: `cloud_login_test.go` — 4 cases against `httptest` stub: persists token from confirmed `{status,token}` shape, surfaces `{error}` message on 4xx, returns error on connection refused, returns error when response lacks token field. Build failed (`undefined: runLDAPLogin`) → real RED.
- [x] 4.4 GREEN: `cmd/engram/cloud_login.go` — extracted testable core `runLDAPLogin(cfg, url, user, pass) error` (POST JSON, 10s client timeout, parse `token`/`error`, persist to `cloud.json` via existing `saveCloudConfig`). `cmdCloudLogin` wraps with interactive prompts (`bufio` username, `golang.org/x/term.ReadPassword` no-echo password), `--ldap`/`--server` flags, `--help` text. Registered `login` in `cmdCloud` dispatcher.

### Files Changed (Batch 4)
| File | Action | What Was Done |
|------|--------|---------------|
| `cmd/engram/cloud.go` | Modified | LDAP branch in `validateCloudServeAuthConfig`; `newCloudRuntime` mode-branch; `login` subcommand in `cmdCloud` dispatcher; updated help text. |
| `cmd/engram/cloud_login.go` | Created | `runLDAPLogin` (testable HTTP+persistence core), `cmdCloudLogin`, `promptUsername`, `promptPassword`. |
| `cmd/engram/cloud_ldap_test.go` | Created | 6 validation cases + `clearAuthEnv` helper. |
| `cmd/engram/cloud_login_test.go` | Created | 4 login-flow cases. |
| `go.sum` | Modified | `go mod tidy` added `golang.org/x/term` checksums (already direct dep, just had no consumer until now). |

### TDD Cycle Evidence (Batch 4)
| Task | Test File | Layer | Safety Net | RED | GREEN | TRIANGULATE | REFACTOR |
|------|-----------|-------|------------|-----|-------|-------------|----------|
| 4.1 | `cloud_ldap_test.go` | Unit | ✅ existing token-mode tests green | ✅ Written (assertions failed) | (paired w/ 4.2) | ✅ 6 cases | ➖ |
| 4.2 | `cloud_ldap_test.go` | Unit | ✅ existing pass post-change | ✅ from 4.1 | ✅ All 6 pass | ✅ URL/map/token-conflict/malformed/happy/token-regression | ➖ minimal branch addition |
| 4.3 | `cloud_login_test.go` | Integration (httptest) | N/A (new) | ✅ Written (compile fail) | (paired w/ 4.4) | ✅ 4 cases | ➖ |
| 4.4 | `cloud_login_test.go` | Integration | N/A (new) | ✅ from 4.3 | ✅ All 4 pass | ✅ persist/upstream-err/conn-refused/missing-token | ✅ extracted `runLDAPLogin` from interactive flow |

### Test Summary (Batch 4)
- Tests written: 10 cases (6 validation + 4 login)
- **Cumulative: 49 cases passing**
- Layers: Unit (validation) + Integration (login via `httptest`)
- Pure-ish core: `runLDAPLogin` is the testable seam — interactive prompts isolated in `cmdCloudLogin`.
- Whole-repo `go test ./...` GREEN; cmd/engram suite passes including all pre-existing tests.

### Deviations from Design
- **CLI flag**: design said `engram cloud login --ldap`. I added `--server <url>` as an optional override (falls back to existing `cloud.json:ServerURL` set by `engram cloud config --server`). Cleaner UX — user doesn't need to retype the URL if they already configured one.
- **Login URL composition**: `runLDAPLogin` accepts the FULL login URL (e.g. `https://idp/api/v1/ldap/auth/login`). The CLI `cmdCloudLogin` composes it from `cloud.json:ServerURL` + `/auth/ldap/login` suffix. This means the `--server` flag points to the cloud server, not the upstream IdP — the cloud server's proxy handles the upstream call (architecturally consistent with proposal: client never talks to upstream directly).

### Issues Found
None.

### Status (after Batch 4)
17/20 tasks complete.

---

## Batch 5 — Phase 5 (Docs + Smoke) — FINAL

**Mode**: Strict TDD (where applicable)
**Status**: success

### Completed Tasks
- [x] 5.1 `docker/cloud/entrypoint.sh` — added comment header documenting all auth env vars: `ENGRAM_AUTH_MODE`, token-mode requirements (`ENGRAM_CLOUD_TOKEN`, `ENGRAM_CLOUD_ALLOWED_PROJECTS`, `ENGRAM_JWT_SECRET`), ldap-mode requirements (`ENGRAM_AUTH_URL`, `ENGRAM_LDAP_GROUP_MAP`, `ENGRAM_CLOUD_TOKEN` MUST be unset), common bind/port/db vars.
- [x] 5.2 `go test ./...` — full repo green, all 21 packages pass, zero regressions.
- [x] 5.3 E2E smoke test in `cmd/engram/cloud_ldap_e2e_test.go`:
  - `TestCloudServeLDAPModeEndToEnd`: boots real `cloudserver.New(...)` in LDAP mode against an `httptest.Server` upstream that mints JWTs with the confirmed `{status, token}` contract. Drives the actual `runLDAPLogin` code path (same as `engram cloud login --ldap` after credential collection). Verifies: upstream hit exactly once, JWT persisted to `cloud.json:Token`, mapped project request → 200, unmapped project → 403, bad credentials → upstream error message surfaced.
  - `TestCloudServeLDAPModeUsesEnvConfig`: validates `ConfigFromEnv` → `validateCloudServeAuthConfig` chain end-to-end with the new env vars.

### Files Changed (Batch 5)
| File | Action | What Was Done |
|------|--------|---------------|
| `docker/cloud/entrypoint.sh` | Modified | Comment header documenting auth modes + required env vars per mode. |
| `cmd/engram/cloud_ldap_e2e_test.go` | Created | 2 E2E tests + `fakeStoreForE2E` satisfying `cloudserver.ChunkStore`. |

### TDD Cycle Evidence (Batch 5)
| Task | Test File | Layer | Safety Net | RED | GREEN | TRIANGULATE | REFACTOR |
|------|-----------|-------|------------|-----|-------|-------------|----------|
| 5.1 | N/A (docs) | N/A | N/A | ➖ comment-only change | ➖ | ➖ | ➖ |
| 5.2 | N/A (suite-wide) | All | ✅ via 5.3's run | N/A | ✅ 21 pkgs green | N/A | N/A |
| 5.3 | `cloud_ldap_e2e_test.go` | E2E (httptest cloud + httptest upstream) | ✅ existing tests still green | ✅ Written | ✅ Both pass | ✅ 2 E2E + happy/sad paths | ➖ |

### Final Test Summary
- **Cumulative: 51 tests passing** across 8 test files
  - config (8) + groupmap (18) + loginproxy (4) + ldap (10) + cloudserver-ldap (7) + cmd-validate (6) + cmd-login (4) + cmd-e2e (2)
  - Note: prior count of 49 + 2 new E2E tests = 51
- All 21 packages in repo green; zero regressions across token-mode tests
- Layers covered: Unit + Integration + E2E (full proxy → auth → authz chain)

### Deviations from Design
None for Phase 5. The "manual smoke" task in the original plan was replaced by an automated E2E test that exercises the same chain — this is more reproducible and runs in CI.

### Issues Found
None.

### FINAL STATUS
**20/20 tasks complete.** Implementation done. Ready for `sdd-verify` and `sdd-archive`.
