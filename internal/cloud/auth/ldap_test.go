package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func mintTestJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte("test-key-not-verified-by-engram"))
	if err != nil {
		t.Fatalf("mint test jwt: %v", err)
	}
	return signed
}

func TestLDAPAuthorizerValidJWTAttachesAuthorizer(t *testing.T) {
	groupMap := map[string][]string{
		"ops":  {"proj-a", "proj-b"},
		"devs": {"proj-c"},
	}
	authz := NewLDAPAuthorizer(groupMap)
	token := mintTestJWT(t, jwt.MapClaims{
		"sub":    "alice",
		"groups": []string{"ops"},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	mutated, err := authz.AuthorizeRequest(req)
	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	psa, ok := RequestAuthorizerFromContext(mutated.Context())
	if !ok || psa == nil {
		t.Fatal("expected per-request authorizer attached to context")
	}
	if err := psa.AuthorizeProject("proj-a"); err != nil {
		t.Fatalf("expected proj-a allowed, got %v", err)
	}
	if err := psa.AuthorizeProject("proj-b"); err != nil {
		t.Fatalf("expected proj-b allowed, got %v", err)
	}
	if err := psa.AuthorizeProject("proj-c"); err == nil {
		t.Fatal("expected proj-c denied (user not in devs)")
	}
}

func TestLDAPAuthorizerMultiGroupUnion(t *testing.T) {
	groupMap := map[string][]string{
		"ops":  {"proj-a", "proj-b"},
		"devs": {"proj-b", "proj-c"},
	}
	authz := NewLDAPAuthorizer(groupMap)
	token := mintTestJWT(t, jwt.MapClaims{
		"groups": []string{"ops", "devs"},
	})
	req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	mutated, err := authz.AuthorizeRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	psa, _ := RequestAuthorizerFromContext(mutated.Context())
	for _, p := range []string{"proj-a", "proj-b", "proj-c"} {
		if err := psa.AuthorizeProject(p); err != nil {
			t.Fatalf("expected %s allowed (union), got %v", p, err)
		}
	}
	if err := psa.AuthorizeProject("proj-d"); err == nil {
		t.Fatal("expected proj-d denied (not in any mapped group)")
	}
}

func TestLDAPAuthorizerWildcardClaim(t *testing.T) {
	groupMap := map[string][]string{"admins": {WildcardProject}}
	authz := NewLDAPAuthorizer(groupMap)
	token := mintTestJWT(t, jwt.MapClaims{"groups": []string{"admins"}})
	req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	mutated, err := authz.AuthorizeRequest(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	psa, _ := RequestAuthorizerFromContext(mutated.Context())
	if err := psa.AuthorizeProject("any-random-project"); err != nil {
		t.Fatalf("expected wildcard to authorize anything, got %v", err)
	}
}

func TestLDAPAuthorizerMissingBearerHeader(t *testing.T) {
	authz := NewLDAPAuthorizer(map[string][]string{"ops": {"proj-a"}})
	req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)

	_, err := authz.AuthorizeRequest(req)
	if err == nil {
		t.Fatal("expected error for missing Authorization header")
	}
	if !errors.Is(err, ErrLDAPMissingBearer) {
		t.Fatalf("expected ErrLDAPMissingBearer, got %v", err)
	}
}

func TestLDAPAuthorizerMalformedJWT(t *testing.T) {
	authz := NewLDAPAuthorizer(map[string][]string{"ops": {"proj-a"}})
	req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")

	_, err := authz.AuthorizeRequest(req)
	if err == nil {
		t.Fatal("expected error for malformed JWT")
	}
	if !errors.Is(err, ErrLDAPInvalidJWT) {
		t.Fatalf("expected ErrLDAPInvalidJWT, got %v", err)
	}
}

func TestLDAPAuthorizerEmptyGroupsClaim(t *testing.T) {
	authz := NewLDAPAuthorizer(map[string][]string{"ops": {"proj-a"}})
	token := mintTestJWT(t, jwt.MapClaims{"groups": []string{}})
	req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err := authz.AuthorizeRequest(req)
	if err == nil {
		t.Fatal("expected 403-class error for empty groups claim")
	}
	if !errors.Is(err, ErrLDAPNoAuthorizedGroups) {
		t.Fatalf("expected ErrLDAPNoAuthorizedGroups, got %v", err)
	}
}

func TestLDAPAuthorizerMissingGroupsClaim(t *testing.T) {
	authz := NewLDAPAuthorizer(map[string][]string{"ops": {"proj-a"}})
	token := mintTestJWT(t, jwt.MapClaims{"sub": "alice"})
	req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err := authz.AuthorizeRequest(req)
	if !errors.Is(err, ErrLDAPNoAuthorizedGroups) {
		t.Fatalf("expected ErrLDAPNoAuthorizedGroups, got %v", err)
	}
}

func TestLDAPAuthorizerUserInUnmappedGroupOnly(t *testing.T) {
	authz := NewLDAPAuthorizer(map[string][]string{"ops": {"proj-a"}})
	token := mintTestJWT(t, jwt.MapClaims{"groups": []string{"unmapped-group"}})
	req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	_, err := authz.AuthorizeRequest(req)
	if !errors.Is(err, ErrLDAPNoAuthorizedGroups) {
		t.Fatalf("expected ErrLDAPNoAuthorizedGroups (no projects resolved), got %v", err)
	}
}

func TestLDAPAuthorizerNonBearerScheme(t *testing.T) {
	authz := NewLDAPAuthorizer(map[string][]string{"ops": {"proj-a"}})
	token := mintTestJWT(t, jwt.MapClaims{"groups": []string{"ops"}})
	req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	req.Header.Set("Authorization", "Basic "+token)

	_, err := authz.AuthorizeRequest(req)
	if !errors.Is(err, ErrLDAPMissingBearer) {
		t.Fatalf("expected ErrLDAPMissingBearer for non-Bearer scheme, got %v", err)
	}
}

func TestLDAPAuthorizerSatisfiesAuthenticator(t *testing.T) {
	// Compile-time + runtime check: LDAPAuthorizer implements Authenticator.Authorize.
	var _ interface{ Authorize(*http.Request) error } = (*LDAPAuthorizer)(nil)

	authz := NewLDAPAuthorizer(map[string][]string{"ops": {"proj-a"}})
	token := mintTestJWT(t, jwt.MapClaims{"groups": []string{"ops"}})
	req := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if err := authz.Authorize(req); err != nil {
		t.Fatalf("Authorize should succeed for valid token, got %v", err)
	}
	req2 := httptest.NewRequest(http.MethodGet, "/api/anything", nil)
	if err := authz.Authorize(req2); err == nil || !strings.Contains(err.Error(), "bearer") {
		t.Fatalf("Authorize should reject missing bearer, got %v", err)
	}
}
