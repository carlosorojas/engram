package auth

import "testing"

// TestUserInfo_ZeroValue verifies the UserInfo struct exists with the expected
// exported field names and that a zero-value instance has all-empty strings.
// REQ-5, REQ-19
func TestUserInfo_ZeroValue(t *testing.T) {
	var u UserInfo
	if u.UID != "" {
		t.Errorf("UID: want empty string, got %q", u.UID)
	}
	if u.CN != "" {
		t.Errorf("CN: want empty string, got %q", u.CN)
	}
	if u.Mail != "" {
		t.Errorf("Mail: want empty string, got %q", u.Mail)
	}
	if u.GivenName != "" {
		t.Errorf("GivenName: want empty string, got %q", u.GivenName)
	}
	if u.SN != "" {
		t.Errorf("SN: want empty string, got %q", u.SN)
	}
}
