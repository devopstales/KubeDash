package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// TestGetTokenNotImplemented: get-token must print the pointer to the
// in-flight kubectl-oidc-plugin blueprint on stderr and return
// errNotImplemented (which cmd.Execute maps to exit 2 in main).
func TestGetTokenNotImplemented(t *testing.T) {
	out := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	rootCmd.SetOut(out)
	rootCmd.SetErr(errBuf)
	rootCmd.SetArgs([]string{"get-token"})
	err := rootCmd.Execute()
	if !errors.Is(err, errNotImplemented) {
		t.Fatalf("get-token error = %v, want sentinel errNotImplemented", err)
	}
	if !strings.Contains(errBuf.String(), "not yet implemented") {
		t.Errorf("get-token stderr = %q, want the not-implemented pointer", errBuf.String())
	}
}

// TestCleanSetupNotImplemented triangulates the not-implemented shape on
// two different inputs (clean, setup): same sentinel, own stderr pointer.
func TestCleanSetupNotImplemented(t *testing.T) {
	for _, arg := range []string{"clean", "setup"} {
		t.Run(arg, func(t *testing.T) {
			errBuf := &bytes.Buffer{}
			rootCmd.SetOut(&bytes.Buffer{})
			rootCmd.SetErr(errBuf)
			rootCmd.SetArgs([]string{arg})
			err := rootCmd.Execute()
			if !errors.Is(err, errNotImplemented) {
				t.Fatalf("%s error = %v, want sentinel errNotImplemented", arg, err)
			}
			if !strings.Contains(errBuf.String(), arg+": not yet implemented") {
				t.Errorf("%s stderr = %q, want the %s pointer", arg, errBuf.String(), arg)
			}
		})
	}
}
