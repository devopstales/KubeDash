// Package cmd wires the kubedash cobra command tree.
package cmd

import (
	"errors"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:          "kubedash",
	Short:        "KubeDash kubectl credential plugin (spine: version only in base structure)",
	SilenceUsage: true,
	// Stubs (get-token/clean/setup) print their own pointer on stderr;
	// suppress cobra's "Error:" duplicate for the not-implemented case.
	SilenceErrors: true,
}

// errNotImplemented is returned by stub subcommands. main maps it to exit 2
// so kubectl's credential plugin protocol sees a deterministic failure.
var errNotImplemented = errors.New("not implemented")

// Execute runs the command tree. A stub subcommand's errNotImplemented maps
// to exit 2 (kubectl's exec credential plugin convention); any other error
// maps to exit 1.
func Execute() {
	err := rootCmd.Execute()
	if err == nil {
		return
	}
	if errors.Is(err, errNotImplemented) {
		os.Exit(2)
	}
	os.Exit(1)
}

func init() {
	rootCmd.AddCommand(versionCmd, getTokenCmd, cleanCmd, setupCmd)
}
