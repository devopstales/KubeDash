package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is overridden at build time via -ldflags "-X cmd.version=<v>".
var version = "0.1.0"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the plugin version",
	Run: func(cmd *cobra.Command, _ []string) {
		fmt.Fprintf(cmd.OutOrStdout(), "kubedash %s\n", version)
	},
}
