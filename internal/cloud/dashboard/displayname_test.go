package dashboard

import "testing"

// TestDisplayNameFromUserInfo_CN: CN non-empty → returns CN. REQ-19
func TestDisplayNameFromUserInfo_CN(t *testing.T) {
	u := LDAPUserInfo{CN: "Carlos Rojas", UID: "carlososiel", Mail: "crojas@grainchain.io"}
	got := DisplayNameFromUserInfo(u)
	if got != "Carlos Rojas" {
		t.Errorf("want %q, got %q", "Carlos Rojas", got)
	}
}

// TestDisplayNameFromUserInfo_UID: CN empty, UID non-empty → returns UID. REQ-19
func TestDisplayNameFromUserInfo_UID(t *testing.T) {
	u := LDAPUserInfo{CN: "", UID: "carlososiel", Mail: "crojas@grainchain.io"}
	got := DisplayNameFromUserInfo(u)
	if got != "carlososiel" {
		t.Errorf("want %q, got %q", "carlososiel", got)
	}
}

// TestDisplayNameFromUserInfo_MailLocalPart: CN and UID empty, Mail has @ → returns local part. REQ-19
func TestDisplayNameFromUserInfo_MailLocalPart(t *testing.T) {
	u := LDAPUserInfo{CN: "", UID: "", Mail: "crojas@grainchain.io"}
	got := DisplayNameFromUserInfo(u)
	if got != "crojas" {
		t.Errorf("want %q, got %q", "crojas", got)
	}
}

// TestDisplayNameFromUserInfo_Fallback: all fields empty → returns "OPERATOR". REQ-19
func TestDisplayNameFromUserInfo_Fallback(t *testing.T) {
	u := LDAPUserInfo{}
	got := DisplayNameFromUserInfo(u)
	if got != "OPERATOR" {
		t.Errorf("want %q, got %q", "OPERATOR", got)
	}
}

// TestDisplayNameFromUserInfo_MailNoAt: Mail present but no @ → returns Mail as-is. Edge case 1.13
func TestDisplayNameFromUserInfo_MailNoAt(t *testing.T) {
	u := LDAPUserInfo{CN: "", UID: "", Mail: "noatsign"}
	got := DisplayNameFromUserInfo(u)
	if got != "noatsign" {
		t.Errorf("want %q, got %q", "noatsign", got)
	}
}
