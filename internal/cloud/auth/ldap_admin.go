package auth

import "github.com/golang-jwt/jwt/v5"

// IsAdminJWT reports whether any of the JWT's groups claim values are present
// in adminGroups. The JWT is decoded WITHOUT signature verification — it was
// already trusted when minted into the dashboard session cookie.
//
// Returns false (never panics) when:
//   - adminGroups is empty
//   - rawJWT is malformed or cannot be decoded
//   - the JWT has no groups claim
//   - no group in the JWT intersects adminGroups
func IsAdminJWT(rawJWT string, adminGroups []string) bool {
	if len(adminGroups) == 0 {
		return false
	}
	p := jwt.NewParser()
	groups, err := decodeGroupsClaim(p, rawJWT)
	if err != nil {
		return false
	}
	adminSet := make(map[string]struct{}, len(adminGroups))
	for _, g := range adminGroups {
		adminSet[g] = struct{}{}
	}
	for _, g := range groups {
		if _, ok := adminSet[g]; ok {
			return true
		}
	}
	return false
}
