package auth

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestExtractMaxAge_MissingExp: JWT with no exp field → ErrJWTMissingExp, result 0. REQ-6
func TestExtractMaxAge_MissingExp(t *testing.T) {
	raw := mintTestJWT(t, jwt.MapClaims{"sub": "user1"})
	now := func() time.Time { return time.Now() }

	got, err := ExtractMaxAge(raw, now)
	if !errors.Is(err, ErrJWTMissingExp) {
		t.Errorf("want ErrJWTMissingExp, got %v", err)
	}
	if got != 0 {
		t.Errorf("want result 0, got %d", got)
	}
}

// TestExtractMaxAge_ZeroExp: JWT with exp=0 → ErrJWTMissingExp, result 0. REQ-6
func TestExtractMaxAge_ZeroExp(t *testing.T) {
	raw := mintTestJWT(t, jwt.MapClaims{"sub": "user1", "exp": float64(0)})
	now := func() time.Time { return time.Now() }

	got, err := ExtractMaxAge(raw, now)
	if !errors.Is(err, ErrJWTMissingExp) {
		t.Errorf("want ErrJWTMissingExp for exp=0, got %v", err)
	}
	if got != 0 {
		t.Errorf("want result 0, got %d", got)
	}
}

// TestExtractMaxAge_ExpiredWithoutLeeway: exp = now - 31s → ErrJWTExpired. REQ-7
func TestExtractMaxAge_ExpiredWithoutLeeway(t *testing.T) {
	fixedNow := time.Unix(1_000_000, 0)
	exp := fixedNow.Add(-31 * time.Second).Unix()
	raw := mintTestJWT(t, jwt.MapClaims{"sub": "u", "exp": float64(exp)})
	now := func() time.Time { return fixedNow }

	_, err := ExtractMaxAge(raw, now)
	if !errors.Is(err, ErrJWTExpired) {
		t.Errorf("want ErrJWTExpired for exp 31s in the past, got %v", err)
	}
}

// TestExtractMaxAge_WithinLeeway: exp = now - 29s → allowed (30s leeway). REQ-7
func TestExtractMaxAge_WithinLeeway(t *testing.T) {
	fixedNow := time.Unix(1_000_000, 0)
	exp := fixedNow.Add(-29 * time.Second).Unix()
	raw := mintTestJWT(t, jwt.MapClaims{"sub": "u", "exp": float64(exp)})
	now := func() time.Time { return fixedNow }

	got, err := ExtractMaxAge(raw, now)
	if err != nil {
		t.Errorf("want nil error within 30s leeway, got %v", err)
	}
	if got < 0 {
		t.Errorf("want non-negative result, got %d", got)
	}
}

// TestExtractMaxAge_ValidFuture: exp = now + 3600s → result ≈ 3600, err nil. REQ-8
func TestExtractMaxAge_ValidFuture(t *testing.T) {
	fixedNow := time.Unix(1_000_000, 0)
	exp := fixedNow.Add(3600 * time.Second).Unix()
	raw := mintTestJWT(t, jwt.MapClaims{"sub": "u", "exp": float64(exp)})
	now := func() time.Time { return fixedNow }

	got, err := ExtractMaxAge(raw, now)
	if err != nil {
		t.Errorf("want nil error, got %v", err)
	}
	// Allow ±2s tolerance for integer truncation
	if got < 3598 || got > 3602 {
		t.Errorf("want result ≈3600 (±2), got %d", got)
	}
}
