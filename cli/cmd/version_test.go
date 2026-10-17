package cmd

import (
	"bytes"
	"testing"
)

func TestVersionOutput(t *testing.T) {
	orig := version
	version = "0.1.0"
	defer func() { version = orig }()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := buf.String(); got != "kubedash 0.1.0\n" {
		t.Errorf("version output = %q, want %q", got, "kubedash 0.1.0\n")
	}
}

// TestVersionPrintsLdflagsValue triangulates with a different version value:
// the print path must reflect whatever version the linker stamped in, not a
// hardcoded string.
func TestVersionPrintsLdflagsValue(t *testing.T) {
	orig := version
	version = "9.9.9-test"
	defer func() { version = orig }()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if got := buf.String(); got != "kubedash 9.9.9-test\n" {
		t.Errorf("version output = %q, want %q", got, "kubedash 9.9.9-test\n")
	}
}
