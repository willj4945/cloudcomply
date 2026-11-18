// Package cmd wires the Cobra command tree. It contains no business logic —
// commands delegate to internal/tui, internal/nist, and internal/report.
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/willj4945/cloudcomply/internal/tui"
)

// demoMode is a persistent flag shared by the TUI and `report nist` — see
// cmd/fetch.go. Default is live AWS calls; --demo opts into the old
// fake-data-only behavior.
var demoMode bool

var rootCmd = &cobra.Command{
	Use:   "cloudcomply",
	Short: "Assess AWS Organizations against NIST SP 800-53 / RMF controls",
	RunE: func(cmd *cobra.Command, args []string) error {
		return tui.Run(newFetcher(demoMode))
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&demoMode, "demo", false, "use built-in demo data instead of live AWS Security Hub calls")
}

// Execute runs the CLI. version/commit/date come from ldflags set at build
// time (see .goreleaser.yml); main.go passes them through unchanged.
func Execute(version, commit, date string) error {
	rootCmd.Version = fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	return rootCmd.Execute()
}
