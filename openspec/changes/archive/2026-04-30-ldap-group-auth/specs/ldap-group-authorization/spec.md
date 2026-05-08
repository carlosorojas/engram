# LDAP Group Authorization Specification

## Purpose

Defines the behavior of Engram Cloud when configured to delegate authentication to a pre-existing 3rd-party LDAP auth service and to derive per-user project authorization from the JWT's `groups` claim. This capability is mutually exclusive with the static `ENGRAM_CLOUD_TOKEN` path and is selected at boot via `ENGRAM_AUTH_MODE`.

## Requirements

### Requirement: Auth Mode Selection

The cloud server SHALL select its authentication path at boot from the env var `ENGRAM_AUTH_MODE`. Accepted values are `token` (default) and `ldap`. The two modes are mutually exclusive.

#### Scenario: Default mode is token

- GIVEN `ENGRAM_AUTH_MODE` is unset
- WHEN the server starts
- THEN the static `ENGRAM_CLOUD_TOKEN` authenticator is used and behavior is identical to the current implementation

#### Scenario: LDAP mode requires upstream URL and group map

- GIVEN `ENGRAM_AUTH_MODE=ldap`
- WHEN `ENGRAM_AUTH_URL` or `ENGRAM_LDAP_GROUP_MAP` is empty
- THEN the server SHALL refuse to start with a clear error naming the missing variable

#### Scenario: Invalid mode value is rejected

- GIVEN `ENGRAM_AUTH_MODE=both`
- WHEN the server starts
- THEN the server SHALL refuse to start with an error listing accepted values

### Requirement: Login Proxy Endpoint

In `ldap` mode the cloud server SHALL expose `POST /auth/ldap/login` that forwards the request body to `ENGRAM_AUTH_URL` and returns the upstream response verbatim with a 10-second HTTP timeout. This endpoint MUST NOT be exposed in `token` mode.

#### Scenario: Successful upstream login

- GIVEN `ENGRAM_AUTH_MODE=ldap` and a valid `ENGRAM_AUTH_URL`
- WHEN a client POSTs valid credentials to `/auth/ldap/login`
- THEN the cloud server forwards them to the upstream URL and returns the upstream response verbatim with status 200, body shape `{"status":"Login successful","token":"<jwt>"}`

#### Scenario: Upstream returns 401

- GIVEN bad credentials are submitted
- WHEN the upstream service returns 401
- THEN the cloud server returns 401 to the client and does not retry

#### Scenario: Upstream timeout

- GIVEN the upstream service is unreachable for >10 seconds
- WHEN a login is attempted
- THEN the cloud server returns 504 with a clear message; no retry

#### Scenario: Endpoint absent in token mode

- GIVEN `ENGRAM_AUTH_MODE=token`
- WHEN any client calls `/auth/ldap/login`
- THEN the server returns 404

### Requirement: JWT Decoding (Decode-Only)

The cloud server SHALL decode the JWT payload of incoming `Authorization: Bearer <jwt>` requests in `ldap` mode without verifying the signature or rechecking `exp`. Malformed JWTs MUST be rejected with 401.

#### Scenario: Valid JWT with groups claim

- GIVEN a JWT whose payload includes `"groups": ["devs"]`
- WHEN the request reaches the auth middleware
- THEN the payload is decoded, `groups` is extracted, and the request proceeds to authorization

#### Scenario: Malformed JWT

- GIVEN an `Authorization: Bearer not.a.jwt` header
- WHEN the request is received
- THEN the server returns 401

#### Scenario: Missing or empty groups claim

- GIVEN a decoded JWT with `"groups": []` or no `groups` field
- WHEN the request is received
- THEN the server returns 403 with a "no authorized groups" message

### Requirement: Group→Project Mapping Parsing

The env var `ENGRAM_LDAP_GROUP_MAP` SHALL be parsed once at boot using the grammar `<group>:<proj1>,<proj2>;<group>:<proj>`. Whitespace around any token MUST be trimmed. Empty entries MUST be ignored. Duplicate group entries MUST result in a startup error.

#### Scenario: Standard mapping parses

- GIVEN `ENGRAM_LDAP_GROUP_MAP="ops:proj-a,proj-b; devs : proj-c "`
- WHEN parsed at boot
- THEN the resulting map is `{ops:[proj-a,proj-b], devs:[proj-c]}`

#### Scenario: Duplicate group rejected

- GIVEN `ENGRAM_LDAP_GROUP_MAP="ops:a;ops:b"`
- WHEN parsed at boot
- THEN the server SHALL refuse to start with a "duplicate group" error

#### Scenario: Wildcard project

- GIVEN `ENGRAM_LDAP_GROUP_MAP="admins:*"`
- WHEN a user in `admins` is authorized
- THEN the resulting allowlist authorizes every project (uses existing `WildcardProject` sentinel)

### Requirement: Per-Request Project Authorization

In `ldap` mode the auth middleware SHALL build a per-request allowlist as the union of the projects mapped from each of the user's groups, attach a `ProjectScopeAuthorizer` over that allowlist to `r.Context()`, and proceed. The handler-level project check SHALL prefer the context-attached authorizer over the global one.

#### Scenario: Multi-group user

- GIVEN a JWT with `groups=[ops,devs]` and the map `ops:a,b;devs:b,c`
- WHEN the user accesses project `b`
- THEN the request is authorized (200)
- AND the user accessing project `d` returns 403

#### Scenario: User in group with no mapping

- GIVEN a JWT with `groups=[unmapped]`
- WHEN any project is requested
- THEN the response is 403

#### Scenario: Token mode preserves global authorizer

- GIVEN `ENGRAM_AUTH_MODE=token`
- WHEN a request hits any project handler
- THEN the global `ProjectScopeAuthorizer` is used unchanged (no context lookup)

### Requirement: CLI Login

The `engram cloud login --ldap` command SHALL prompt for username and password (password not echoed), POST them as JSON to the configured cloud server's `/auth/ldap/login`, and on success persist the returned JWT into the existing cloud config file under the same `Token` field used by the static-token flow.

#### Scenario: Successful login persists JWT

- GIVEN a configured cloud server running in `ldap` mode
- WHEN the user runs `engram cloud login --ldap` and enters valid credentials
- THEN the `token` field from the upstream response body is written to `cloud.json:Token` and the command exits 0

#### Scenario: Bad credentials surface upstream error

- GIVEN bad credentials are entered
- WHEN the upstream returns 401
- THEN the CLI prints "authentication failed" and exits non-zero
- AND no token is written
