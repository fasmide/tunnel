package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// These values are populated by release builds using linker flags.
var (
	Tag            = "dev"
	SourceRevision = "unknown"
	BuildDate      = "unknown"
)

// AddVersion installs a metadata-only command that never starts the application.
func AddVersion(root *cobra.Command) {
	root.AddCommand(&cobra.Command{
		Use: "version", Short: "Print build version information", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\ntag: %s\nsrcrev: %s\ncompile date: %s\n", root.Name(), Tag, SourceRevision, BuildDate)
			return err
		},
	})
}
