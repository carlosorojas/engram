# Tasks: LDAP Group-Based Authorization

> **Strict TDD**: each implementation task pair is RED (failing test first) → GREEN (make it pass). Refactor inline if needed.

## Phase 1: Foundation (config + parsing)

- [x] 1.1 Verify `go.mod`: ensure `github.com/golang-jwt/jwt/v5` and `golang.org/x/term` are present; `go get` if absent.
- [x] 1.2 RED: `internal/cloud/config_test.go` — table tests for `ENGRAM_AUTH_MODE` (`token` default, `ldap`, invalid), `ENGRAM_AUTH_URL`, `ENGRAM_LDAP_GROUP_MAP` env reading.
- [x] 1.3 GREEN: `internal/cloud/config.go` — add `AuthMode`, `AuthURL`, `LDAPGroupMap` fields + env parsing in `ConfigFromEnv()`.
- [x] 1.4 RED: `internal/cloud/auth/groupmap_test.go` — table-driven covering spec scenarios: standard parse with whitespace trim, duplicate group → error, wildcard `*`, empty entries ignored, missing colon → error, empty projects list → error, `ProjectsFor` union+dedup across multi-group, unmapped group returns empty.
- [x] 1.5 GREEN: `internal/cloud/auth/groupmap.go` — `ParseGroupMap(raw string) (map[string][]string, error)` + `ProjectsFor(groups []string, m map[string][]string) []string`.

## Phase 2: Auth core (proxy + LDAP authorizer)

- [x] 2.1 RED: `internal/cloud/auth/loginproxy_test.go` — `httptest` upstream returns `{"status","token"}` (200 passthrough), `{"error":...}` (401 passthrough), upstream sleep > 10s → 504, connection refused → 502.
- [x] 2.2 GREEN: `internal/cloud/auth/loginproxy.go` — `LoginProxy{UpstreamURL string, Client *http.Client}` with `ServeHTTP`; `Client.Timeout = 10*time.Second`; copy request body, propagate upstream status + body verbatim.
- [x] 2.3 RED: `internal/cloud/auth/ldap_test.go` — build JWTs with `jwt/v5` in-test; assert: valid token + groups → request mutated with ctx authorizer; missing bearer → 401-class error; malformed JWT → 401-class error; empty/missing `groups` claim → 403-class error; multi-group resolves union of mapped projects.
- [x] 2.4 GREEN: `internal/cloud/auth/ldap.go` — `LDAPAuthorizer{groupMap}` implementing `Authenticator.Authorize` + new `RequestAuthorizer.AuthorizeRequest(r) (*http.Request, error)`; uses `jwt.NewParser().ParseUnverified` with security comment.
- [x] 2.5 GREEN: `internal/cloud/auth/auth.go` — add private ctx key + `WithRequestAuthorizer(ctx, *ProjectScopeAuthorizer) context.Context` and `RequestAuthorizerFromContext(ctx) (*ProjectScopeAuthorizer, bool)`.

## Phase 3: Cloudserver wiring

- [x] 3.1 RED: `internal/cloud/cloudserver/cloudserver_ldap_test.go` — 7 cases including login proxy verbatim forwarding, /auth/ldap/login 404 in token mode, mapped→200, unmapped→403, no-groups→403, malformed→401, wildcard→all.
- [x] 3.2 GREEN: `internal/cloud/cloudserver/cloudserver.go` — `RequestAuthorizer` interface; `runAuthMiddleware` type-asserts; `authorizeProjectScopeForRequest(w, r, project)` ctx-first; `WithLoginProxy(h)` Option; conditional route mount; `writeAuthError` maps `ErrLDAPNoAuthorizedGroups` → 403, others → 401.
- [x] 3.3 `go test ./...` whole repo: green; cloudserver token-mode tests pass unchanged.

## Phase 4: Boot + CLI

- [x] 4.1 RED: `cmd/engram/cloud_ldap_test.go` — 6 cases: ldap requires URL + GROUP_MAP, rejects CLOUD_TOKEN, rejects malformed map (duplicate group), happy path, token-mode regression.
- [x] 4.2 GREEN: `cmd/engram/cloud.go` — `newCloudRuntime` branches on `cfg.AuthMode`: ldap → `auth.NewLDAPAuthorizer(parsedMap)` + `auth.NewLoginProxy(URL, 10s)` + `WithLoginProxy`. `validateCloudServeAuthConfig` adds ldap-mode rules (URL+map required, no CLOUD_TOKEN/INSECURE).
- [x] 4.3 RED: `cmd/engram/cloud_login_test.go` — 4 cases against httptest stub returning the confirmed `{status,token}` / `{error}` shapes: persist token, surface upstream error, connection refused, missing token field.
- [x] 4.4 GREEN: `cmd/engram/cloud_login.go` — extracted `runLDAPLogin(cfg, url, user, pass)` (testable core); `cmdCloudLogin` wires `--ldap`/`--server`/`--help` flags + `bufio` username prompt + `term.ReadPassword`; registered `login` in `cmdCloud` dispatcher.

## Phase 5: Docs + integration verification

- [x] 5.1 `docker/cloud/entrypoint.sh` — env-var doc block added covering token mode + ldap mode + common vars.
- [x] 5.2 `go test ./...` — all 21 packages green, zero regressions.
- [x] 5.3 E2E smoke (`cmd/engram/cloud_ldap_e2e_test.go`): boots cloud server in ldap mode against httptest stub upstream, drives `runLDAPLogin` (the same code path as `engram cloud login --ldap`), exercises mapped project → 200 + unmapped → 403 + bad-creds → upstream error surfaced. Plus env-config wiring test.
