package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// cleanCmd is the not-yet-implemented stub (main exits 2).
var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Clean up cached credentials (not yet implemented — see the kubectl-oidc-plugin blueprint)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		fmt.Fprintln(cmd.ErrOrStderr(), "clean: not yet implemented (see .skillgrid/specs/2026-10-17-kubectl-oidc-plugin/blueprint.md)")
		return errNotImplemented
	},
}
