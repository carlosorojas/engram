# Design: LDAP Group-Based Authorization

## Technical Approach

Engram Cloud gains a second authenticator pair selected at boot by `ENGRAM_AUTH_MODE`. The new `LDAPAuthorizer` proxies login requests to a 3rd-party service, decodes incoming JWTs (decode-only), resolves their `groups` claim through an env-loaded mapping, and attaches a per-request `ProjectScopeAuthorizer` to `r.Context()`. The cloudserver's existing project-check site reads from context first and falls back to the global `ProjectAuthorizer` — which keeps token-mode behavior bit-for-bit identical. No `go-ldap` dependency is added; the upstream service handles all LDAP.

## Architecture Decisions

### Decision: Optional context-aware authorizer interface (Go-idiomatic type assertion)

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Modify `Authenticator.Authorize` to return `(context.Context, error)` | Breaks every existing implementer; touches every test | ❌ |
| Add a NEW optional interface `RequestAuthorizer` and type-assert it in middleware (matches existing `auth.(ProjectAuthorizer)` pattern at `cloudserver.go:104`) | Zero impact on `token` mode; LDAP authenticator opts in | ✅ |

```go
// internal/cloud/cloudserver/cloudserver.go (new optional interface)
type RequestAuthorizer interface {
    AuthorizeRequest(r *http.Request) (*http.Request, error) // returns r with ctx mutated
}
```

The middleware does `if ra, ok := s.auth.(RequestAuthorizer); ok { r, err = ra.AuthorizeRequest(r) } else { err = s.auth.Authorize(r) }`. Token mode: `*auth.Service` does NOT implement `RequestAuthorizer`, falls through. LDAP mode: `*auth.LDAPAuthorizer` implements both `Authenticator` (delegates to `AuthorizeRequest`) and `RequestAuthorizer`.

### Decision: JWT decode via `golang-jwt/jwt/v5` ParseUnverified

| Option | Tradeoff | Decision |
|--------|----------|----------|
| Hand-roll base64 decode of payload | One less dep; reinvents claim parsing | ❌ |
| `jwt.NewParser().ParseUnverified(token, &claims)` | Battle-tested, explicit "no-verify" semantics | ✅ |

`ParseUnverified` returns parsed claims without checking signature. Documented inline with `// SECURITY: decode-only by design — see openspec/changes/ldap-group-auth/proposal.md decision 5`.

### Decision: Per-request authorizer carried via private context key

Single typed key `type ctxKey int; const ldapAuthorizerKey ctxKey = iota`. The handler check at `cloudserver.go:505` calls a helper `effectiveProjectAuthorizer(r) ProjectAuthorizer` that prefers ctx, falls back to `s.projectAuth`. Helper lives in `cloudserver` package — does not leak ctx key out of `auth`.

### Decision: Group map grammar (precise)

Grammar (BNF-ish):
```
map     := entry (';' entry)*
entry   := group ':' projects
group   := non-empty-string-without-colon-or-semicolon (whitespace trimmed)
projects:= project (',' project)*
project := non-empty-string (whitespace trimmed)
```
Edge rules:
- Empty `entry` (consecutive `;;`) → ignored.
- Duplicate `group` → boot-time error.
- Group names with `:` or `;` → unsupported in v1; documented. (LDAP CN names rarely contain these.)
- `*` as a project token → uses existing `auth.WildcardProject`; granted as the entire allowlist.
- Empty projects list (e.g. `ops:`) → boot-time error.

### Decision: `engram cloud login --ldap` persists into existing `cloud.json:Token`

Reuses `loadCloudConfig` / `saveCloudConfig` and the existing `cloudConfig.Token` field — handlers stay agnostic. No new config schema.

## Data Flow

```
Client                    Engram Cloud                 3rd-Party Auth Service
  │                            │                                │
  │ POST /auth/ldap/login      │                                │
  │ {"username","password"}    │                                │
  ├───────────────────────────►│                                │
  │                            │ POST <ENGRAM_AUTH_URL>         │
  │                            ├───────────────────────────────►│
  │                            │           200 OK               │
  │                            │ {"jwt":"eyJ..."}               │
  │                            │◄───────────────────────────────┤
  │  200 OK {"jwt":"eyJ..."}   │                                │
  │◄───────────────────────────┤                                │

(later, authenticated request)
  │ GET /api/... Bearer eyJ... │
  ├───────────────────────────►│
  │                            │ ParseUnverified → groups
  │                            │ groups → projects (env map)
  │                            │ attach ProjectScopeAuthorizer to r.Context()
  │                            │ handler reads ctx-authorizer; AuthorizeProject(p)
  │  200/403                   │
  │◄───────────────────────────┤
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `internal/cloud/auth/groupmap.go` | Create | `ParseGroupMap(raw string) (map[string][]string, error)`; helper `ProjectsFor(groups []string) []string` (union+dedup). |
| `internal/cloud/auth/loginproxy.go` | Create | `LoginProxy{UpstreamURL, Client}` with `ServeHTTP`. 10s `http.Client.Timeout`. Forwards body, propagates upstream status + body verbatim. |
| `internal/cloud/auth/ldap.go` | Create | `LDAPAuthorizer{groupMap, jwtParser}` implementing `Authenticator` + `RequestAuthorizer`. `AuthorizeRequest(r)` extracts bearer, `ParseUnverified`, builds per-request `ProjectScopeAuthorizer`, returns `r.WithContext(ctx)`. |
| `internal/cloud/auth/auth.go` | Modify | Export `ctxAuthorizerKey` accessor; small helper `WithRequestAuthorizer(ctx, *ProjectScopeAuthorizer)` and `RequestAuthorizerFromContext(ctx)`. |
| `internal/cloud/cloudserver/cloudserver.go` | Modify | Add `RequestAuthorizer` interface; middleware branches on type-assert; helper `effectiveProjectAuthorizer(r)` for handler check. Mount `/auth/ldap/login` route only if `ldap.LoginProxy` was wired in via new `WithLoginProxy(...)` option. |
| `internal/cloud/config.go` | Modify | Add `AuthMode`, `AuthURL`, `LDAPGroupMap` fields. Read `ENGRAM_AUTH_MODE`, `ENGRAM_AUTH_URL`, `ENGRAM_LDAP_GROUP_MAP`. |
| `cmd/engram/cloud.go` | Modify | `newCloudRuntime` branches on `cfg.AuthMode`. `validateCloudServeAuthConfig` adds `ldap`-mode validation (URL+map required; `ENGRAM_CLOUD_TOKEN` must be unset). |
| `cmd/engram/main.go` | Modify | Register `engram cloud login --ldap` subcommand. |
| `docker/cloud/entrypoint.sh` | Modify | Document `ENGRAM_AUTH_MODE`, `ENGRAM_AUTH_URL`, `ENGRAM_LDAP_GROUP_MAP`. |
| `go.mod` | Modify | Add `github.com/golang-jwt/jwt/v5` if absent (verify before adding). |

## Interfaces / Contracts

### HTTP: `POST /auth/ldap/login`
Request body (proxied verbatim, contract confirmed with 3rd party):
```json
{"username": "alice", "password": "s3cret"}
```
Response 200 (upstream body verbatim):
```json
{"status": "Login successful", "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
```
Response error (upstream body verbatim, propagated with upstream status code):
```json
{"error": "An error occurred"}
```
The CLI extracts `token` (NOT `jwt`) from the success response. Errors: status code passes through; 504 only for our own 10s timeout to upstream; 502 only if upstream connection fails entirely.

### Go: new types

```go
// internal/cloud/auth/ldap.go
type LDAPAuthorizer struct {
    groupMap map[string][]string // boot-parsed
}
func (a *LDAPAuthorizer) Authorize(r *http.Request) error
func (a *LDAPAuthorizer) AuthorizeRequest(r *http.Request) (*http.Request, error)

// internal/cloud/auth/groupmap.go
func ParseGroupMap(raw string) (map[string][]string, error)
func ProjectsFor(groups []string, m map[string][]string) []string

// internal/cloud/cloudserver/cloudserver.go (new)
type RequestAuthorizer interface {
    AuthorizeRequest(r *http.Request) (*http.Request, error)
}
type LoginProxyHandler interface { http.Handler }
func WithLoginProxy(h http.Handler) Option
```

### JWT claims expected
```json
{"sub": "alice", "groups": ["ops","devs"], "exp": 1714521600}
```
Only `groups` is consumed; `sub` is logged at debug level (no audit table). `exp` is stored in claims but NOT checked (decode-only, per proposal decision 5).

## Testing Strategy

| Layer | What | Approach |
|-------|------|----------|
| Unit | `ParseGroupMap` happy paths, edge cases (whitespace, dup, wildcard, empty entries, missing colon, empty projects). | Table-driven tests in `auth/groupmap_test.go`. |
| Unit | `ProjectsFor` (union+dedup, multi-group, unmapped group). | Table-driven. |
| Unit | `LDAPAuthorizer.AuthorizeRequest` — valid/empty/missing groups, malformed JWT, missing bearer. | Table-driven; build JWTs in-test with `jwt/v5`. |
| Unit | `LoginProxy.ServeHTTP` — 200 passthrough, 401 passthrough, 504 on timeout. | `httptest.NewServer` upstream; assert response codes/bodies. |
| Integration | Full token-mode regression — every existing `cloudserver` test green unchanged. | Existing tests, no modification. |
| Integration | LDAP-mode end-to-end — boot with `AUTH_MODE=ldap`, stub upstream, valid JWT → 200; unmapped group → 403; wildcard → all pass. | New `cloudserver_ldap_test.go`; stub `http.Server`. |
| Integration | Boot validation — missing `AUTH_URL` rejects start; duplicate group rejects parse. | `validateCloudServeAuthConfig` table-driven test. |
| CLI | `engram cloud login --ldap` against stub server; persists JWT, error path on 401. | `cmd/engram/main_extra_test.go` style; httptest stub. |

## Migration / Rollout

No migration. Feature is dormant when `ENGRAM_AUTH_MODE` is unset (default). Operators flip to `ldap` mode by setting all three env vars and restarting. Flip-back is identical: set mode to `token` (or unset) plus the original `ENGRAM_CLOUD_TOKEN`, restart. Existing JWTs become invalid on flip-back since the bearer comparison is exact-string against the static token.

## Open Questions

None — 3rd-party contract confirmed (`{"status","token"}` success, `{"error"}` failure). CLI uses `bufio` + `golang.org/x/term` for no-echo password (verify `go.mod`, add if absent).
