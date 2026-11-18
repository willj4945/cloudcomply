package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/willj4945/cloudcomply/internal/awsclient"
	"github.com/willj4945/cloudcomply/internal/nist"
	"github.com/willj4945/cloudcomply/internal/tui"
)

// fetchTimeout bounds how long headless `report nist` waits on a live AWS
// call (the TUI has its own copy of this constant in internal/tui, since
// its async fetch is triggered independently via Bubble Tea's Init()).
const fetchTimeout = 30 * time.Second

// newFetcher centralizes the demo-vs-live decision so root.go (TUI) and
// report.go (headless) don't each duplicate it.
func newFetcher(demo bool) tui.FindingsFetcher {
	if demo {
		return func(ctx context.Context) ([]nist.Finding, nist.OrgSummary, error) {
			return nist.DemoFindings(), nist.OrgSummary{Name: "Acme Federal Org", AccountCount: 47, IsOrgMode: true}, nil
		}
	}
	return func(ctx context.Context) ([]nist.Finding, nist.OrgSummary, error) {
		client, err := awsclient.New(ctx)
		if err != nil {
			return nil, nist.OrgSummary{}, fmt.Errorf("connecting to AWS: %w (try --demo)", err)
		}
		if _, err = client.WhoAmI(ctx); err != nil {
			return nil, nist.OrgSummary{}, fmt.Errorf("no valid AWS credentials found: %w (try --demo)", err)
		}
		findings, err := client.GetNISTFindings(ctx)
		if err != nil {
			return nil, nist.OrgSummary{}, fmt.Errorf("fetching Security Hub findings: %w", err)
		}
		org, err := client.GetOrgSummary(ctx)
		if err != nil {
			return nil, nist.OrgSummary{}, fmt.Errorf("fetching organization summary: %w", err)
		}
		return findings, org, nil
	}
}
