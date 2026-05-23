package subconv

import "testing"

func TestStableHashIgnoresFragment(t *testing.T) {
	a := "vless://uuid@example.com:443?security=reality&pbk=abc#old-name"
	b := "vless://uuid@example.com:443?security=reality&pbk=abc#new-name"
	if StableHash(a) != StableHash(b) {
		t.Fatalf("StableHash should ignore URL fragment/display name")
	}
}

func TestStableHashKeepsConnectionParams(t *testing.T) {
	a := "vless://uuid@example.com:443?security=reality&pbk=abc#name"
	b := "vless://uuid@example.com:443?security=reality&pbk=def#name"
	if StableHash(a) == StableHash(b) {
		t.Fatalf("StableHash should include connection parameters")
	}
}
