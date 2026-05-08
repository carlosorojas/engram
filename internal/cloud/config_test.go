package cloud

import (
	"strings"
	"testing"
)

func TestConfigFromEnvCloudHost(t *testing.T) {
	t.Run("default bind host stays loopback", func(t *testing.T) {
		t.Setenv("ENGRAM_CLOUD_HOST", "")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.BindHost != "127.0.0.1" {
			t.Fatalf("expected default bind host 127.0.0.1, got %q", cfg.BindHost)
		}
	})

	t.Run("env overrides bind host", func(t *testing.T) {
		t.Setenv("ENGRAM_CLOUD_HOST", "0.0.0.0")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.BindHost != "0.0.0.0" {
			t.Fatalf("expected bind host override 0.0.0.0, got %q", cfg.BindHost)
		}
	})
}

func TestConfigFromEnvAllowedProjects(t *testing.T) {
	t.Setenv("ENGRAM_CLOUD_ALLOWED_PROJECTS", "proj-a, proj-b,proj-a")
	cfg, err := ConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.AllowedProjects) != 2 {
		t.Fatalf("expected deduplicated allowlist, got %v", cfg.AllowedProjects)
	}
	if cfg.AllowedProjects[0] != "proj-a" || cfg.AllowedProjects[1] != "proj-b" {
		t.Fatalf("unexpected allowlist order/values: %v", cfg.AllowedProjects)
	}
}

func TestConfigFromEnvDatabaseDSN(t *testing.T) {
	clearDatabaseEnv := func(t *testing.T) {
		t.Helper()
		for _, k := range []string{
			"ENGRAM_DATABASE_URL",
			"ENGRAM_DATABASE_USER",
			"ENGRAM_DATABASE_PASSWORD",
			"ENGRAM_DATABASE_HOST",
			"ENGRAM_DATABASE_PORT",
			"ENGRAM_DATABASE",
			"ENGRAM_DATABASE_SSLMODE",
		} {
			t.Setenv(k, "")
		}
	}

	t.Run("ENGRAM_DATABASE_URL takes precedence over components", func(t *testing.T) {
		clearDatabaseEnv(t)
		t.Setenv("ENGRAM_DATABASE_URL", "postgres://u:p@h:1/db?sslmode=require")
		t.Setenv("ENGRAM_DATABASE_USER", "other")
		t.Setenv("ENGRAM_DATABASE_PASSWORD", "other")
		t.Setenv("ENGRAM_DATABASE_HOST", "other")
		t.Setenv("ENGRAM_DATABASE_PORT", "5432")
		t.Setenv("ENGRAM_DATABASE", "other")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.DSN != "postgres://u:p@h:1/db?sslmode=require" {
			t.Fatalf("expected URL to win, got %q", cfg.DSN)
		}
	})

	t.Run("components build DSN with default sslmode=disable", func(t *testing.T) {
		clearDatabaseEnv(t)
		t.Setenv("ENGRAM_DATABASE_USER", "engram")
		t.Setenv("ENGRAM_DATABASE_PASSWORD", "secret")
		t.Setenv("ENGRAM_DATABASE_HOST", "db.internal")
		t.Setenv("ENGRAM_DATABASE_PORT", "5432")
		t.Setenv("ENGRAM_DATABASE", "engram_cloud")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "postgres://engram:secret@db.internal:5432/engram_cloud?sslmode=disable"
		if cfg.DSN != expected {
			t.Fatalf("expected %q, got %q", expected, cfg.DSN)
		}
	})

	t.Run("ENGRAM_DATABASE_SSLMODE overrides default", func(t *testing.T) {
		clearDatabaseEnv(t)
		t.Setenv("ENGRAM_DATABASE_USER", "u")
		t.Setenv("ENGRAM_DATABASE_PASSWORD", "p")
		t.Setenv("ENGRAM_DATABASE_HOST", "h")
		t.Setenv("ENGRAM_DATABASE_PORT", "5432")
		t.Setenv("ENGRAM_DATABASE", "d")
		t.Setenv("ENGRAM_DATABASE_SSLMODE", "require")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(cfg.DSN, "sslmode=require") {
			t.Fatalf("expected sslmode=require in DSN, got %q", cfg.DSN)
		}
	})

	t.Run("special characters in password are URL-encoded", func(t *testing.T) {
		clearDatabaseEnv(t)
		t.Setenv("ENGRAM_DATABASE_USER", "u")
		t.Setenv("ENGRAM_DATABASE_PASSWORD", "p@ss word/#")
		t.Setenv("ENGRAM_DATABASE_HOST", "h")
		t.Setenv("ENGRAM_DATABASE_PORT", "5432")
		t.Setenv("ENGRAM_DATABASE", "d")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(cfg.DSN, "p@ss word/#") {
			t.Fatalf("expected password to be URL-encoded, got raw in %q", cfg.DSN)
		}
	})

	t.Run("partial component set returns error listing missing vars", func(t *testing.T) {
		clearDatabaseEnv(t)
		t.Setenv("ENGRAM_DATABASE_USER", "u")
		t.Setenv("ENGRAM_DATABASE_HOST", "h")
		_, err := ConfigFromEnv()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		msg := err.Error()
		for _, want := range []string{"ENGRAM_DATABASE_PASSWORD", "ENGRAM_DATABASE_PORT", "ENGRAM_DATABASE"} {
			if !strings.Contains(msg, want) {
				t.Fatalf("expected error to mention %q, got %q", want, msg)
			}
		}
	})

	t.Run("invalid ENGRAM_DATABASE_PORT returns error", func(t *testing.T) {
		clearDatabaseEnv(t)
		t.Setenv("ENGRAM_DATABASE_USER", "u")
		t.Setenv("ENGRAM_DATABASE_PASSWORD", "p")
		t.Setenv("ENGRAM_DATABASE_HOST", "h")
		t.Setenv("ENGRAM_DATABASE_PORT", "abc")
		t.Setenv("ENGRAM_DATABASE", "d")
		_, err := ConfigFromEnv()
		if err == nil || !strings.Contains(err.Error(), "ENGRAM_DATABASE_PORT") {
			t.Fatalf("expected port validation error, got %v", err)
		}
	})

	t.Run("no database env falls back to default DSN", func(t *testing.T) {
		clearDatabaseEnv(t)
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.DSN != DefaultConfig().DSN {
			t.Fatalf("expected default DSN, got %q", cfg.DSN)
		}
	})
}

func TestConfigFromEnvAuthMode(t *testing.T) {
	t.Run("default auth mode is token", func(t *testing.T) {
		t.Setenv("ENGRAM_AUTH_MODE", "")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.AuthMode != "token" {
			t.Fatalf("expected default auth mode token, got %q", cfg.AuthMode)
		}
	})

	t.Run("ldap value is accepted", func(t *testing.T) {
		t.Setenv("ENGRAM_AUTH_MODE", "ldap")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.AuthMode != "ldap" {
			t.Fatalf("expected ldap, got %q", cfg.AuthMode)
		}
	})

	t.Run("invalid mode returns error listing accepted values", func(t *testing.T) {
		t.Setenv("ENGRAM_AUTH_MODE", "both")
		_, err := ConfigFromEnv()
		if err == nil {
			t.Fatal("expected error for invalid auth mode, got nil")
		}
		msg := err.Error()
		if !strings.Contains(msg, "token") || !strings.Contains(msg, "ldap") {
			t.Fatalf("expected error to list accepted values token/ldap, got %q", msg)
		}
	})

	t.Run("whitespace and case are normalized", func(t *testing.T) {
		t.Setenv("ENGRAM_AUTH_MODE", "  LDAP  ")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.AuthMode != "ldap" {
			t.Fatalf("expected normalized ldap, got %q", cfg.AuthMode)
		}
	})
}

func TestConfigFromEnvAuthURL(t *testing.T) {
	t.Run("auth url defaults empty", func(t *testing.T) {
		t.Setenv("ENGRAM_AUTH_URL", "")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.AuthURL != "" {
			t.Fatalf("expected empty default, got %q", cfg.AuthURL)
		}
	})

	t.Run("env populates auth url", func(t *testing.T) {
		t.Setenv("ENGRAM_AUTH_URL", "https://idp.example.com/api/v1/ldap/auth/login")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.AuthURL != "https://idp.example.com/api/v1/ldap/auth/login" {
			t.Fatalf("unexpected auth url: %q", cfg.AuthURL)
		}
	})
}

func TestConfigFromEnvLDAPGroupMap(t *testing.T) {
	t.Run("group map defaults empty", func(t *testing.T) {
		t.Setenv("ENGRAM_LDAP_GROUP_MAP", "")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.LDAPGroupMap != "" {
			t.Fatalf("expected empty default, got %q", cfg.LDAPGroupMap)
		}
	})

	t.Run("env populates group map raw string", func(t *testing.T) {
		raw := "ops:proj-a,proj-b;devs:proj-c"
		t.Setenv("ENGRAM_LDAP_GROUP_MAP", raw)
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.LDAPGroupMap != raw {
			t.Fatalf("expected raw passthrough, got %q", cfg.LDAPGroupMap)
		}
	})
}

func TestConfigFromEnvLDAPAdminGroups(t *testing.T) {
	t.Run("unset defaults to empty slice", func(t *testing.T) {
		t.Setenv("ENGRAM_LDAP_ADMIN_GROUPS", "")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.LDAPAdminGroups) != 0 {
			t.Fatalf("expected empty LDAPAdminGroups, got %v", cfg.LDAPAdminGroups)
		}
	})

	t.Run("single group parsed", func(t *testing.T) {
		t.Setenv("ENGRAM_LDAP_ADMIN_GROUPS", "admins")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.LDAPAdminGroups) != 1 || cfg.LDAPAdminGroups[0] != "admins" {
			t.Fatalf("expected [admins], got %v", cfg.LDAPAdminGroups)
		}
	})

	t.Run("comma-separated groups parsed and whitespace trimmed", func(t *testing.T) {
		t.Setenv("ENGRAM_LDAP_ADMIN_GROUPS", " ops-admins , cloud-ops , ")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.LDAPAdminGroups) != 2 {
			t.Fatalf("expected 2 groups, got %v", cfg.LDAPAdminGroups)
		}
		if cfg.LDAPAdminGroups[0] != "ops-admins" || cfg.LDAPAdminGroups[1] != "cloud-ops" {
			t.Fatalf("unexpected group values: %v", cfg.LDAPAdminGroups)
		}
	})

	t.Run("case is preserved (case-sensitive)", func(t *testing.T) {
		t.Setenv("ENGRAM_LDAP_ADMIN_GROUPS", "OPS-Admins,cloud-OPS")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.LDAPAdminGroups[0] != "OPS-Admins" || cfg.LDAPAdminGroups[1] != "cloud-OPS" {
			t.Fatalf("expected case-preserved groups, got %v", cfg.LDAPAdminGroups)
		}
	})

	t.Run("empty entries dropped", func(t *testing.T) {
		t.Setenv("ENGRAM_LDAP_ADMIN_GROUPS", ",admins,,")
		cfg, err := ConfigFromEnv()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(cfg.LDAPAdminGroups) != 1 || cfg.LDAPAdminGroups[0] != "admins" {
			t.Fatalf("expected [admins] after dropping empties, got %v", cfg.LDAPAdminGroups)
		}
	})
}

func TestIsDefaultJWTSecret(t *testing.T) {
	t.Run("default secret returns true", func(t *testing.T) {
		if !IsDefaultJWTSecret(DefaultJWTSecret) {
			t.Fatal("expected default jwt secret to be recognized")
		}
	})

	t.Run("custom secret returns false", func(t *testing.T) {
		if IsDefaultJWTSecret("custom-super-secret-value-1234567890") {
			t.Fatal("expected custom jwt secret to be treated as non-default")
		}
	})
}
