package cloud

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

type Config struct {
	DSN             string
	JWTSecret       string
	CORSOrigins     []string
	MaxPool         int
	Port            int
	BindHost        string
	AdminToken      string
	AllowedProjects []string
	AuthMode        string
	AuthURL         string
	AuthAPIKey      string
	LDAPGroupMap    string
	LDAPAdminGroups []string
}

const DefaultJWTSecret = "engram-dev-jwt-secret-for-local-smoke-1234"

const (
	AuthModeToken = "token"
	AuthModeLDAP  = "ldap"
)

func DefaultConfig() Config {
	return Config{
		DSN:         "postgres://engram:engram_dev@localhost:5433/engram_cloud?sslmode=disable",
		JWTSecret:   DefaultJWTSecret,
		CORSOrigins: []string{"*"},
		MaxPool:     10,
		Port:        8080,
		BindHost:    "127.0.0.1",
		AuthMode:    AuthModeToken,
	}
}

func IsDefaultJWTSecret(secret string) bool {
	return strings.TrimSpace(secret) == DefaultJWTSecret
}

func ConfigFromEnv() (Config, error) {
	cfg := DefaultConfig()
	dsn, err := resolveDatabaseDSN()
	if err != nil {
		return cfg, err
	}
	if dsn != "" {
		cfg.DSN = dsn
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_JWT_SECRET")); v != "" {
		cfg.JWTSecret = v
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_CLOUD_ADMIN")); v != "" {
		cfg.AdminToken = v
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_PORT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.Port = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_CLOUD_HOST")); v != "" {
		cfg.BindHost = v
	}
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("ENGRAM_AUTH_MODE"))); v != "" {
		switch v {
		case AuthModeToken, AuthModeLDAP:
			cfg.AuthMode = v
		default:
			return cfg, fmt.Errorf("invalid ENGRAM_AUTH_MODE %q: accepted values are %q and %q", v, AuthModeToken, AuthModeLDAP)
		}
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_AUTH_URL")); v != "" {
		cfg.AuthURL = v
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_AUTH_API_KEY")); v != "" {
		cfg.AuthAPIKey = v
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_LDAP_GROUP_MAP")); v != "" {
		cfg.LDAPGroupMap = v
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_LDAP_ADMIN_GROUPS")); v != "" {
		parts := strings.Split(v, ",")
		groups := make([]string, 0, len(parts))
		for _, part := range parts {
			g := strings.TrimSpace(part)
			if g == "" {
				continue
			}
			groups = append(groups, g)
		}
		cfg.LDAPAdminGroups = groups
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_CLOUD_ALLOWED_PROJECTS")); v != "" {
		parts := strings.Split(v, ",")
		projects := make([]string, 0, len(parts))
		seen := make(map[string]struct{})
		for _, part := range parts {
			project := strings.TrimSpace(part)
			if project == "" {
				continue
			}
			if _, ok := seen[project]; ok {
				continue
			}
			seen[project] = struct{}{}
			projects = append(projects, project)
		}
		cfg.AllowedProjects = projects
	}
	return cfg, nil
}

// resolveDatabaseDSN returns the Postgres DSN derived from the environment.
// ENGRAM_DATABASE_URL takes precedence. If it is unset but any of the component
// variables (ENGRAM_DATABASE_USER/PASSWORD/HOST/PORT/ENGRAM_DATABASE) is set,
// all five are required; otherwise the caller keeps the default DSN.
func resolveDatabaseDSN() (string, error) {
	if v := strings.TrimSpace(os.Getenv("ENGRAM_DATABASE_URL")); v != "" {
		return v, nil
	}
	components := map[string]string{
		"ENGRAM_DATABASE_USER":     strings.TrimSpace(os.Getenv("ENGRAM_DATABASE_USER")),
		"ENGRAM_DATABASE_PASSWORD": strings.TrimSpace(os.Getenv("ENGRAM_DATABASE_PASSWORD")),
		"ENGRAM_DATABASE_HOST":     strings.TrimSpace(os.Getenv("ENGRAM_DATABASE_HOST")),
		"ENGRAM_DATABASE_PORT":     strings.TrimSpace(os.Getenv("ENGRAM_DATABASE_PORT")),
		"ENGRAM_DATABASE":          strings.TrimSpace(os.Getenv("ENGRAM_DATABASE")),
	}
	anySet := false
	for _, v := range components {
		if v != "" {
			anySet = true
			break
		}
	}
	if !anySet {
		return "", nil
	}
	var missing []string
	for k, v := range components {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return "", fmt.Errorf("incomplete database configuration: ENGRAM_DATABASE_URL is not set and the following component variables are missing: %s", strings.Join(missing, ", "))
	}
	port, err := strconv.Atoi(components["ENGRAM_DATABASE_PORT"])
	if err != nil || port <= 0 || port > 65535 {
		return "", fmt.Errorf("invalid ENGRAM_DATABASE_PORT: %q", components["ENGRAM_DATABASE_PORT"])
	}
	sslmode := strings.TrimSpace(os.Getenv("ENGRAM_DATABASE_SSLMODE"))
	if sslmode == "" {
		sslmode = "disable"
	}
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(components["ENGRAM_DATABASE_USER"], components["ENGRAM_DATABASE_PASSWORD"]),
		Host:   fmt.Sprintf("%s:%d", components["ENGRAM_DATABASE_HOST"], port),
		Path:   "/" + components["ENGRAM_DATABASE"],
	}
	q := u.Query()
	q.Set("sslmode", sslmode)
	u.RawQuery = q.Encode()
	return u.String(), nil
}
