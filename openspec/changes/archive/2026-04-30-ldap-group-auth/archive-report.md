# Archive Report: ldap-group-auth

**Archived**: 2026-04-30
**Verdict**: PASS (verify-report) + smoke test passed end-to-end
**Mode**: hybrid (engram + openspec)

## Engram Observation IDs (audit trail)
| Artifact | Topic Key | ID |
|----------|-----------|-----|
| Exploration | `sdd/ldap-group-auth/explore` | 1771 |
| Proposal | `sdd/ldap-group-auth/proposal` | 1773 |
| Spec | `sdd/ldap-group-auth/spec` | 1774 |
| Design | `sdd/ldap-group-auth/design` | 1775 |
| Tasks | `sdd/ldap-group-auth/tasks` | 1776 |
| Apply progress | `sdd/ldap-group-auth/apply-progress` | 1778 |
| Verify report | `sdd/ldap-group-auth/verify-report` | 1779 |
| Archive report | `sdd/ldap-group-auth/archive-report` | (this artifact) |

## Filesystem Actions

1. **Spec promoted** (NEW capability): `openspec/changes/ldap-group-auth/specs/ldap-group-authorization/spec.md` → `openspec/specs/ldap-group-authorization/spec.md`
2. **Change folder moved**: `openspec/changes/ldap-group-auth/` → `openspec/changes/archive/2026-04-30-ldap-group-auth/`

Archive contents (preserved verbatim for audit):
- `proposal.md`
- `exploration.md`
- `design.md`
- `tasks.md` (20/20 tasks complete)
- `specs/ldap-group-authorization/spec.md`
- `apply-progress.md` (5 batches)
- `verify-report.md` (PASS)
- `archive-report.md` (this file)

## Source of Truth Updated

`openspec/specs/ldap-group-authorization/spec.md` is now the canonical specification for LDAP group-based authorization in Engram Cloud. It contains 6 requirements with 17 scenarios.

## Implementation Summary

- **Lines of code**: ~963 LOC of new test code, ~600 LOC of new production code
- **Files created**: 8 new (4 production + 4 test)
- **Files modified**: 6 (config.go, auth.go, cloudserver.go, cmd/engram/cloud.go, entrypoint.sh, go.mod/sum)
- **Tests added**: 51 (all passing); cumulative repo suite green across 21 packages
- **Smoke test**: 8/8 scenarios passed against live Postgres + stub upstream
- **Backward compatibility**: token-mode behavior preserved bit-for-bit (existing tests untouched)

## Outstanding Suggestions (non-blocking, future work)

1. JWT signature verification (proposal decision 5 deferred this)
2. `go vet ./...` integration in future sdd-verify runs
3. Coverage tooling adoption
4. Remove legacy `authorizeProjectScope(w, project)` shim (no remaining call sites)

## SDD Cycle Complete

| Phase | Artifact | Status |
|-------|----------|--------|
| Explore | `exploration.md` | ✅ |
| Propose | `proposal.md` | ✅ |
| Spec | `specs/ldap-group-authorization/spec.md` | ✅ promoted |
| Design | `design.md` | ✅ |
| Tasks | `tasks.md` | ✅ 20/20 |
| Apply | `apply-progress.md` | ✅ 5 batches |
| Verify | `verify-report.md` | ✅ PASS |
| Archive | `archive-report.md` | ✅ this file |

The change is fully planned, implemented, verified end-to-end, and archived. Ready for the next change.
