package derphole

import "testing"

func TestVerificationStringIsStable(t *testing.T) {
	got := VerificationString("token-value")
	want := VerificationString("token-value")
	if got != want {
		t.Fatalf("VerificationString() = %q, want stable output %q", got, want)
	}
}
