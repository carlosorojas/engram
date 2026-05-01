#!/bin/sh
set -eu

# Engram Cloud server entrypoint.
#
# Environment variables (loaded from /vault/secrets/env if present):
#
# Auth mode (default: token):
#   ENGRAM_AUTH_MODE         "token" or "ldap" (mutually exclusive)
#
# Token mode (ENGRAM_AUTH_MODE=token, default):
#   ENGRAM_CLOUD_TOKEN              required — static bearer token
#   ENGRAM_CLOUD_ALLOWED_PROJECTS   required — comma-separated project allowlist (or "*")
#   ENGRAM_JWT_SECRET               required — non-default secret for dashboard sessions
#
# LDAP mode (ENGRAM_AUTH_MODE=ldap):
#   ENGRAM_AUTH_URL          required — full upstream login URL
#                            (e.g. https://idp.example.com/api/v1/ldap/auth/login)
#   ENGRAM_LDAP_GROUP_MAP    required — group→projects map
#                            format: "group1:projA,projB;group2:projC"
#                            "*" wildcard project grants all projects
#   ENGRAM_CLOUD_TOKEN       MUST be unset in ldap mode
#
# Common:
#   ENGRAM_CLOUD_HOST        bind host (default 127.0.0.1)
#   ENGRAM_PORT              listen port (default 8080)
#   ENGRAM_DATABASE_URL      Postgres DSN (or component vars)

if [ -f /vault/secrets/env ]; then
  set -a
  . /vault/secrets/env
  set +a
fi

exec engram "$@"
