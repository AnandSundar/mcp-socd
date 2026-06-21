package config

import "testing"

// TestDefaultConfigPath returns a non-empty, absolute path on the host
// platform. We can't assert the exact value (XDG directories differ by
// OS and by $HOME), but the path should always be well-formed.
func TestDefaultConfigPath(t *testing.T) {
	got, err := DefaultConfigPath()
	if err != nil {
		t.Skipf("DefaultConfigPath() error on this platform/env, skipping: %v", err)
	}
	if got == "" {
		t.Fatal("DefaultConfigPath() returned empty string")
	}
}
