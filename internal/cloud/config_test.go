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
