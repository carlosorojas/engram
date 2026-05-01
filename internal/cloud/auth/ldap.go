package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// SECURITY: this package decodes upstream-issued JWTs WITHOUT verifying the
// signature, by design. JWTs only enter the system through the cloud server's
// own /auth/ldap/login proxy, which fetched them directly from the trusted
// upstream service over HTTPS. See openspec/changes/ldap-group-auth/proposal.md
// decision 5. Signature verification is listed as future hardening.

var (
	ErrLDAPMissingBearer      = errors.New("ldap auth: bearer token missing or wrong scheme")
	ErrLDAPInvalidJWT         = errors.New("ldap auth: malformed jwt")
	ErrLDAPNoAuthorizedGroups = errors.New("ldap auth: token has no groups mapped to any project")
)

// LDAPAuthorizer authenticates requests by decoding the bearer JWT issued by
// the upstream LDAP auth service and authorizes per-request access by mapping
// the JWT's groups claim through a boot-loaded group→projects table.
type LDAPAuthorizer struct {
	groupMap map[string][]string
	parser   *jwt.Parser
}

// NewLDAPAuthorizer returns an authorizer that resolves the given group map.
// The map is parsed once at boot via ParseGroupMap.
func NewLDAPAuthorizer(groupMap map[string][]string) *LDAPAuthorizer {
	return &LDAPAuthorizer{
		groupMap: groupMap,
		parser:   jwt.NewParser(),
	}
}

// Authorize satisfies the cloudserver.Authenticator interface for compatibility
// with code paths that only need an identity check. It runs the same logic as
// AuthorizeRequest but discards the mutated request — callers that need the
// per-request authorizer attached to context MUST type-assert and call
// AuthorizeRequest instead.
func (a *LDAPAuthorizer) Authorize(r *http.Request) error {
	_, err := a.AuthorizeRequest(r)
	return err
}

// AuthorizeRequest decodes the bearer JWT, resolves projects via the group
// map, attaches a per-request ProjectScopeAuthorizer to the request context,
// and returns the mutated request. Returns sentinel errors (ErrLDAP*) so the
// middleware can map them to specific HTTP status codes (401 vs 403).
func (a *LDAPAuthorizer) AuthorizeRequest(r *http.Request) (*http.Request, error) {
	token, err := bearerToken(r)
	if err != nil {
		return r, err
	}
	groups, err := decodeGroupsClaim(a.parser, token)
	if err != nil {
		return r, err
	}
	projects := ProjectsFor(groups, a.groupMap)
	if len(projects) == 0 {
		return r, ErrLDAPNoAuthorizedGroups
	}
	psa := NewProjectScopeAuthorizer(projects)
	ctx := WithRequestAuthorizer(r.Context(), psa)
	return r.WithContext(ctx), nil
}

func bearerToken(r *http.Request) (string, error) {
	header := strings.TrimSpace(r.Header.Get("Authorization"))
	if header == "" {
		return "", ErrLDAPMissingBearer
	}
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", ErrLDAPMissingBearer
	}
	token := strings.TrimSpace(parts[1])
	if token == "" {
		return "", ErrLDAPMissingBearer
	}
	return token, nil
}

func decodeGroupsClaim(parser *jwt.Parser, raw string) ([]string, error) {
	claims := jwt.MapClaims{}
	if _, _, err := parser.ParseUnverified(raw, &claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrLDAPInvalidJWT, err)
	}
	rawGroups, ok := claims["groups"]
	if !ok {
		return nil, ErrLDAPNoAuthorizedGroups
	}
	switch v := rawGroups.(type) {
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					out = append(out, s)
				}
			}
		}
		if len(out) == 0 {
			return nil, ErrLDAPNoAuthorizedGroups
		}
		return out, nil
	case []string:
		// jwt/v5 typically decodes JSON arrays as []interface{}, but accept
		// pre-typed []string for in-test convenience.
		out := make([]string, 0, len(v))
		for _, s := range v {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		if len(out) == 0 {
			return nil, ErrLDAPNoAuthorizedGroups
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: groups claim has unexpected type %T", ErrLDAPInvalidJWT, rawGroups)
	}
}
