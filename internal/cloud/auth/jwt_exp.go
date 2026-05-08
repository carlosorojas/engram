package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// ErrJWTMissingExp is returned when the JWT has no exp claim or exp is zero.
	ErrJWTMissingExp = errors.New("jwt: missing or zero exp claim")
	// ErrJWTExpired is returned when the JWT exp is past the leeway boundary.
	// The leeway is 30 seconds: tokens expired up to 30s ago are still accepted.
	ErrJWTExpired = errors.New("jwt: token is already expired")
)

// ExtractMaxAge decodes the JWT (unverified — same posture as LDAPAuthorizer)
// and returns the number of seconds until expiry, suitable for cookie MaxAge.
//
// Returns ErrJWTMissingExp if the exp claim is absent or zero.
// Returns ErrJWTExpired if exp + 30s < now (30s clock-skew leeway).
//
// When the token is within the leeway window but already past exp, the return
// value may be zero or small-negative; callers should clamp to 0 if needed.
func ExtractMaxAge(rawJWT string, now func() time.Time) (int, error) {
	var claims jwt.MapClaims
	_, _, err := jwt.NewParser().ParseUnverified(rawJWT, &claims)
	if err != nil {
		return 0, err
	}

	expVal, ok := claims["exp"]
	if !ok {
		return 0, ErrJWTMissingExp
	}

	// JWT library stores numeric claims as float64 when parsing into MapClaims.
	expFloat, ok := expVal.(float64)
	if !ok || expFloat == 0 {
		return 0, ErrJWTMissingExp
	}

	expTime := time.Unix(int64(expFloat), 0)

	// Reject if now - 30s > expTime, i.e. expired beyond the leeway window.
	if now().Add(-30 * time.Second).After(expTime) {
		return 0, ErrJWTExpired
	}

	maxAge := int(expTime.Sub(now()).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}
	return maxAge, nil
}
