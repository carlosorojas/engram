package main

import (
	"strings"
	"testing"
)

// clearAuthEnv resets every env var that validateCloudServeAuthConfig reads,
// so each subtest starts from a clean slate.
func clearAuthEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"ENGRAM_AUTH_MODE",
		"ENGRAM_AUTH_URL",
		"ENGRAM_AUTH_API_KEY",
		"ENGRAM_LDAP_GROUP_MAP",
		"ENGRAM_CLOUD_TOKEN",
		"ENGRAM_CLOUD_ADMIN",
		"ENGRAM_CLOUD_INSECURE_NO_AUTH",
		"ENGRAM_CLOUD_ALLOWED_PROJECTS",
		"ENGRAM_JWT_SECRET",
	} {
		t.Setenv(k, "")
	}
}

func TestValidateCloudServeAuthConfigLDAPRequiresAuthURL(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ENGRAM_AUTH_MODE", "ldap")
	t.Setenv("ENGRAM_LDAP_GROUP_MAP", "ops:proj-a")
	t.Setenv("ENGRAM_AUTH_API_KEY", "k")

	err := validateCloudServeAuthConfig()
	if err == nil {
		t.Fatal("expected error: missing ENGRAM_AUTH_URL in ldap mode")
	}
	if !strings.Contains(err.Error(), "ENGRAM_AUTH_URL") {
		t.Fatalf("expected error to name ENGRAM_AUTH_URL, got %q", err.Error())
	}
}

func TestValidateCloudServeAuthConfigLDAPRequiresAPIKey(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ENGRAM_AUTH_MODE", "ldap")
	t.Setenv("ENGRAM_AUTH_URL", "https://idp.example.com/api/v1/ldap/auth/login")
	t.Setenv("ENGRAM_LDAP_GROUP_MAP", "ops:proj-a")

	err := validateCloudServeAuthConfig()
	if err == nil {
		t.Fatal("expected error: missing ENGRAM_AUTH_API_KEY in ldap mode")
	}
	if !strings.Contains(err.Error(), "ENGRAM_AUTH_API_KEY") {
		t.Fatalf("expected error to name ENGRAM_AUTH_API_KEY, got %q", err.Error())
	}
}

func TestValidateCloudServeAuthConfigLDAPRequiresGroupMap(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ENGRAM_AUTH_MODE", "ldap")
	t.Setenv("ENGRAM_AUTH_URL", "https://idp.example.com/api/v1/ldap/auth/login")
	t.Setenv("ENGRAM_AUTH_API_KEY", "k")

	err := validateCloudServeAuthConfig()
	if err == nil {
		t.Fatal("expected error: missing ENGRAM_LDAP_GROUP_MAP in ldap mode")
	}
	if !strings.Contains(err.Error(), "ENGRAM_LDAP_GROUP_MAP") {
		t.Fatalf("expected error to name ENGRAM_LDAP_GROUP_MAP, got %q", err.Error())
	}
}

func TestValidateCloudServeAuthConfigLDAPRejectsCloudToken(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ENGRAM_AUTH_MODE", "ldap")
	t.Setenv("ENGRAM_AUTH_URL", "https://idp.example.com/api/v1/ldap/auth/login")
	t.Setenv("ENGRAM_AUTH_API_KEY", "k")
	t.Setenv("ENGRAM_LDAP_GROUP_MAP", "ops:proj-a")
	t.Setenv("ENGRAM_CLOUD_TOKEN", "static-token-should-not-be-set")

	err := validateCloudServeAuthConfig()
	if err == nil {
		t.Fatal("expected error: ENGRAM_CLOUD_TOKEN must be unset in ldap mode")
	}
	if !strings.Contains(err.Error(), "ENGRAM_CLOUD_TOKEN") || !strings.Contains(err.Error(), "ldap") {
		t.Fatalf("expected error to flag conflicting CLOUD_TOKEN in ldap mode, got %q", err.Error())
	}
}

func TestValidateCloudServeAuthConfigLDAPRejectsGroupMapParseError(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ENGRAM_AUTH_MODE", "ldap")
	t.Setenv("ENGRAM_AUTH_URL", "https://idp.example.com/api/v1/ldap/auth/login")
	t.Setenv("ENGRAM_AUTH_API_KEY", "k")
	t.Setenv("ENGRAM_LDAP_GROUP_MAP", "ops:proj-a;ops:proj-b") // duplicate

	err := validateCloudServeAuthConfig()
	if err == nil {
		t.Fatal("expected error: malformed group map should fail validation")
	}
	if !strings.Contains(err.Error(), "duplicate group") {
		t.Fatalf("expected duplicate-group error, got %q", err.Error())
	}
}

func TestValidateCloudServeAuthConfigLDAPSuccess(t *testing.T) {
	clearAuthEnv(t)
	t.Setenv("ENGRAM_AUTH_MODE", "ldap")
	t.Setenv("ENGRAM_AUTH_URL", "https://idp.example.com/api/v1/ldap/auth/login")
	t.Setenv("ENGRAM_AUTH_API_KEY", "k")
	t.Setenv("ENGRAM_LDAP_GROUP_MAP", "ops:proj-a,proj-b;devs:proj-c")

	if err := validateCloudServeAuthConfig(); err != nil {
		t.Fatalf("expected nil error for valid ldap config, got %v", err)
	}
}

func TestValidateCloudServeAuthConfigTokenModeStillRequiresToken(t *testing.T) {
	// Regression: token mode (default) behavior unchanged when LDAP env unset.
	clearAuthEnv(t)
	t.Setenv("ENGRAM_AUTH_MODE", "token")

	err := validateCloudServeAuthConfig()
	if err == nil {
		t.Fatal("expected error: token mode without ENGRAM_CLOUD_TOKEN must fail")
	}
	if !strings.Contains(err.Error(), "ENGRAM_CLOUD_TOKEN") {
		t.Fatalf("expected error to mention ENGRAM_CLOUD_TOKEN, got %q", err.Error())
	}
}
