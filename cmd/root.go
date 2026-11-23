// Package cmd wires the Cobra command tree. It contains no business logic —
// commands delegate to internal/tui, internal/nist, and internal/report.
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/willj4945/cloudcomply/internal/awsclient"
	"github.com/willj4945/cloudcomply/internal/tui"
)

// Persistent flags shared by the TUI and `report nist`; see cmd/fetch.go.
var (
	demoMode       bool
	nativeChecks   bool
	assumeRoleName string
	regionsFlag    string
)

// liveFetchOptions validates the shared flags once, before any AWS call, so
// a typo in --regions fails fast instead of mid-scan.
func liveFetchOptions() (fetchOptions, error) {
	regions, err := awsclient.ParseRegions(regionsFlag)
	if err != nil {
		return fetchOptions{}, fmt.Errorf("--regions: %w", err)
	}
	return fetchOptions{
		demo:         demoMode,
		nativeChecks: nativeChecks,
		scan:         awsclient.ScanOptions{RoleName: assumeRoleName, Regions: regions},
	}, nil
}

var rootCmd = &cobra.Command{
	Use:   "cloudcomply",
	Short: "Assess AWS Organizations against NIST SP 800-53 / RMF controls",
	RunE: func(cmd *cobra.Command, args []string) error {
		opts, err := liveFetchOptions()
		if err != nil {
			return err
		}
		return tui.Run(newFetcher(opts))
	},
}

func init() {
	f := rootCmd.PersistentFlags()
	f.BoolVar(&demoMode, "demo", false, "use built-in demo data instead of live AWS Security Hub calls")
	f.BoolVar(&nativeChecks, "native-checks", false, "also run cloudcomply's own AI workload checks in every account and region (needs the assessor role; see deploy/README.md)")
	f.StringVar(&assumeRoleName, "assume-role-name", awsclient.DefaultAssessorRoleName, "role native checks assume in each member account")
	f.StringVar(&regionsFlag, "regions", "", "comma-separated regions for native checks (default: each account's enabled regions)")
}

// Execute runs the CLI. version/commit/date come from ldflags set at build
// time (see .goreleaser.yml); main.go passes them through unchanged.
func Execute(version, commit, date string) error {
	rootCmd.Version = fmt.Sprintf("%s (commit %s, built %s)", version, commit, date)
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true
	return rootCmd.Execute()
}
