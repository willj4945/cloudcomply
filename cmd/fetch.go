package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/willj4945/cloudcomply/internal/awsclient"
	"github.com/willj4945/cloudcomply/internal/nist"
	"github.com/willj4945/cloudcomply/internal/tui"
)

// fetchTimeout bounds the live Security Hub + Organizations fetch. Native
// checks are bounded per call instead (see awsclient.ScanOptions), because a
// scan across a large organization legitimately takes longer than any one
// fixed budget.
const fetchTimeout = 30 * time.Second

// fetchOptions are the flag values that shape a live fetch.
type fetchOptions struct {
	demo         bool
	nativeChecks bool
	scan         awsclient.ScanOptions
}

// newFetcher centralizes the demo-vs-live decision so root.go (TUI) and
// report.go (headless) don't each duplicate it.
func newFetcher(opts fetchOptions) tui.FindingsFetcher {
	if opts.demo {
		return func(ctx context.Context) ([]nist.Finding, nist.OrgSummary, error) {
			return nist.DemoFindings(), nist.OrgSummary{Name: "Acme Federal Org", AccountCount: 47, IsOrgMode: true}, nil
		}
	}
	return func(ctx context.Context) ([]nist.Finding, nist.OrgSummary, error) {
		shCtx, cancel := context.WithTimeout(ctx, fetchTimeout)
		defer cancel()
		client, err := awsclient.New(shCtx)
		if err != nil {
			return nil, nist.OrgSummary{}, fmt.Errorf("connecting to AWS: %w (try --demo)", err)
		}
		if _, err = client.WhoAmI(shCtx); err != nil {
			return nil, nist.OrgSummary{}, fmt.Errorf("no valid AWS credentials found: %w (try --demo)", err)
		}
		results, err := client.GetNISTResults(shCtx)
		if err != nil {
			return nil, nist.OrgSummary{}, fmt.Errorf("fetching Security Hub findings: %w", err)
		}
		org, err := client.GetOrgSummary(shCtx)
		if err != nil {
			return nil, nist.OrgSummary{}, fmt.Errorf("fetching organization summary: %w", err)
		}
		if opts.nativeChecks {
			native, err := client.Scan(ctx, awsclient.NativeCollectors(), opts.scan)
			if err != nil {
				return nil, nist.OrgSummary{}, fmt.Errorf("running native checks: %w", err)
			}
			results = append(results, native...)
		}
		return nist.RollUp(results), org, nil
	}
}
