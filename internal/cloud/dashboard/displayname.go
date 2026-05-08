package dashboard

import "strings"

// LDAPUserInfo carries display fields for the logged-in LDAP user.
// Populated by the MountConfig.LDAPLogin closure; the dashboard package
// does NOT import internal/cloud/auth to avoid a circular path.
type LDAPUserInfo struct {
	UID       string
	CN        string
	Mail      string
	GivenName string
	SN        string
}

// DisplayNameFromUserInfo resolves a human-readable display name from the
// LDAP user info. Priority: trimmed CN → trimmed UID → email local-part of
// trimmed Mail (split on @) → "OPERATOR".
// Pure function — no network calls, no JWT parsing at render time. REQ-19, REQ-21
func DisplayNameFromUserInfo(u LDAPUserInfo) string {
	if s := strings.TrimSpace(u.CN); s != "" {
		return s
	}
	if s := strings.TrimSpace(u.UID); s != "" {
		return s
	}
	if s := strings.TrimSpace(u.Mail); s != "" {
		if at := strings.Index(s, "@"); at > 0 {
			return s[:at]
		}
		return s
	}
	return "OPERATOR"
}
