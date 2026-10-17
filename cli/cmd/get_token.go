package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// getTokenCmd is the seam where the in-flight kubectl-oidc-plugin change
// plugs its pkg/oidc ExecCredential flow. Until then it prints the pointer
// and fails with the errNotImplemented sentinel (main exits 2).
var getTokenCmd = &cobra.Command{
	Use:   "get-token",
	Short: "Print an ExecCredential (not yet implemented — see the kubectl-oidc-plugin blueprint)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		fmt.Fprintln(cmd.ErrOrStderr(), "get-token: not yet implemented (see .skillgrid/specs/2026-10-17-kubectl-oidc-plugin/blueprint.md)")
		return errNotImplemented
	},
}
