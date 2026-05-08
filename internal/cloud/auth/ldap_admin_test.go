package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// mintAdminTestJWT creates a signed JWT with the given claims for use in
// IsAdminJWT tests. Uses an HS256 key; IsAdminJWT decodes unverified so the
// specific key doesn't matter.
func mintAdminTestJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte("test-admin-jwt-key"))
	if err != nil {
		t.Fatalf("mint jwt: %v", err)
	}
	return signed
}

func TestIsAdminJWT_EmptyAdminGroups(t *testing.T) {
	raw := mintAdminTestJWT(t, jwt.MapClaims{
		"groups": []interface{}{"ops-admins"},
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
	})
	if IsAdminJWT(raw, nil) {
		t.Fatal("expected false when adminGroups is nil")
	}
	if IsAdminJWT(raw, []string{}) {
		t.Fatal("expected false when adminGroups is empty")
	}
}

func TestIsAdminJWT_AdminInGroups(t *testing.T) {
	raw := mintAdminTestJWT(t, jwt.MapClaims{
		"groups": []interface{}{"ops-admins", "devs"},
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
	})
	if !IsAdminJWT(raw, []string{"ops-admins"}) {
		t.Fatal("expected true when JWT groups contains admin group")
	}
}

func TestIsAdminJWT_NoOverlap(t *testing.T) {
	raw := mintAdminTestJWT(t, jwt.MapClaims{
		"groups": []interface{}{"devs", "qa"},
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
	})
	if IsAdminJWT(raw, []string{"ops-admins", "cloud-ops"}) {
		t.Fatal("expected false when no overlap between JWT groups and adminGroups")
	}
}

func TestIsAdminJWT_MalformedJWT(t *testing.T) {
	if IsAdminJWT("not.a.real.jwt", []string{"ops-admins"}) {
		t.Fatal("expected false for malformed JWT")
	}
}

func TestIsAdminJWT_GroupsClaimMissing(t *testing.T) {
	raw := mintAdminTestJWT(t, jwt.MapClaims{
		"sub": "alice",
		"exp": float64(time.Now().Add(time.Hour).Unix()),
	})
	if IsAdminJWT(raw, []string{"ops-admins"}) {
		t.Fatal("expected false when groups claim is missing")
	}
}

func TestIsAdminJWT_MultipleAdminGroupsAny(t *testing.T) {
	raw := mintAdminTestJWT(t, jwt.MapClaims{
		"groups": []interface{}{"cloud-ops"},
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
	})
	if !IsAdminJWT(raw, []string{"ops-admins", "cloud-ops"}) {
		t.Fatal("expected true when any adminGroup matches")
	}
}

func TestIsAdminJWT_CaseSensitive(t *testing.T) {
	raw := mintAdminTestJWT(t, jwt.MapClaims{
		"groups": []interface{}{"Admins"},
		"exp":    float64(time.Now().Add(time.Hour).Unix()),
	})
	// "admins" != "Admins" — must be case-sensitive
	if IsAdminJWT(raw, []string{"admins"}) {
		t.Fatal("expected false: group matching is case-sensitive")
	}
	if !IsAdminJWT(raw, []string{"Admins"}) {
		t.Fatal("expected true: exact case match should succeed")
	}
}
