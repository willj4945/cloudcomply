package awsclient

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"github.com/willj4945/cloudcomply/internal/nist"
)

// nistStandardFilter is the resource portion of the NIST SP 800-53 Rev 5
// standard's subscription ARN in Security Hub (full ARN would be
// "arn:aws:securityhub:<region>::standards/nist-800-53/v/5.0.0"). Update
// this if AWS revises the standard version.
const nistStandardFilter = "standards/nist-800-53/v/5.0.0"

// nistControlPrefix is how Security Hub tags a finding's
// Compliance.RelatedRequirements entry when it maps to a NIST 800-53 Rev 5
// control, e.g. "NIST.800-53.r5 AC-4".
const nistControlPrefix = "NIST.800-53.r5 "

var statusMap = map[types.ComplianceStatus]nist.FindingStatus{
	types.ComplianceStatusPassed:  nist.StatusPassed,
	types.ComplianceStatusFailed:  nist.StatusFailed,
	types.ComplianceStatusWarning: nist.StatusFailed,
	// NOT_AVAILABLE and any future values are intentionally absent — callers
	// treat a missing map entry as "can't be scored, skip this finding".
}

var severityMap = map[types.SeverityLabel]nist.Severity{
	types.SeverityLabelCritical: nist.SeverityCritical,
	types.SeverityLabelHigh:     nist.SeverityHigh,
	types.SeverityLabelMedium:   nist.SeverityMedium,
	types.SeverityLabelLow:      nist.SeverityLow,
	// INFORMATIONAL and anything unrecognized fall back to SeverityLow.
}

var severityRank = map[nist.Severity]int{
	nist.SeverityCritical: 3,
	nist.SeverityHigh:     2,
	nist.SeverityMedium:   1,
	nist.SeverityLow:      0,
}

// controlAggregate collects every raw ASFF finding for one NIST control ID
// into a single row, since a control can be checked by many Security Hub
// security controls across many resources/accounts.
type controlAggregate struct {
	controlID string
	family    string
	title     string
	severity  nist.Severity
	failed    bool
	accounts  map[string]bool
}

// GetNISTFindings fetches every active Security Hub finding associated with
// the NIST SP 800-53 standard and aggregates them into one nist.Finding per
// control ID.
func (c *Client) GetNISTFindings(ctx context.Context) ([]nist.Finding, error) {
	filters := &types.AwsSecurityFindingFilters{
		ComplianceAssociatedStandardsId: []types.StringFilter{{
			Value:      aws.String(nistStandardFilter),
			Comparison: types.StringFilterComparisonEquals,
		}},
		RecordState: []types.StringFilter{{
			Value:      aws.String(string(types.RecordStateActive)),
			Comparison: types.StringFilterComparisonEquals,
		}},
	}

	agg := map[string]*controlAggregate{}
	p := securityhub.NewGetFindingsPaginator(c.sh, &securityhub.GetFindingsInput{Filters: filters})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("get findings: %w", err)
		}
		for _, f := range page.Findings {
			mergeFinding(agg, f)
		}
	}
	return finalizeFindings(agg), nil
}

func mergeFinding(agg map[string]*controlAggregate, f types.AwsSecurityFinding) {
	controlID, family, ok := parseNISTControlID(f.Compliance)
	if !ok {
		return
	}
	status, scorable := statusMap[f.Compliance.Status]
	if !scorable {
		return
	}

	a, exists := agg[controlID]
	if !exists {
		a = &controlAggregate{
			controlID: controlID,
			family:    family,
			// Best-effort: Security Hub's per-security-control title, not an
			// official NIST 800-53 control title (no such lookup exists via
			// this API). TODO(nistmap): replace with a real control-title
			// lookup alongside the DoD SRG impact-level crosswalk.
			title:    sanitizeText(aws.ToString(f.Title)),
			severity: mapSeverity(f.Severity),
			accounts: map[string]bool{},
		}
		agg[controlID] = a
	}
	if status == nist.StatusFailed {
		a.failed = true
		a.accounts[aws.ToString(f.AwsAccountId)] = true
		if sev := mapSeverity(f.Severity); severityRank[sev] > severityRank[a.severity] {
			a.severity = sev
		}
	}
}

func finalizeFindings(agg map[string]*controlAggregate) []nist.Finding {
	out := make([]nist.Finding, 0, len(agg))
	for _, a := range agg {
		status := nist.StatusPassed
		rmfStep := "Monitor"
		if a.failed {
			status = nist.StatusFailed
			rmfStep = "Assess"
		}
		out = append(out, nist.Finding{
			ControlID:        a.controlID,
			Title:            a.title,
			Family:           a.family,
			Status:           status,
			Severity:         a.severity,
			AccountsAffected: len(a.accounts),
			RMFStep:          rmfStep,
			// TODO(nistmap): placeholder until the NIST 800-53 -> DoD SRG
			// Impact Level crosswalk is built from the SRG data already
			// gathered; AWS has no concept of DoD SRG impact levels.
			MinImpactLevel: nist.IL2,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ControlID < out[j].ControlID })
	return out
}

// parseNISTControlID extracts a NIST 800-53 control ID (e.g. "AC-4") and its
// family prefix (e.g. "AC") from a finding's Compliance.RelatedRequirements.
func parseNISTControlID(c *types.Compliance) (controlID, family string, ok bool) {
	if c == nil {
		return "", "", false
	}
	for _, req := range c.RelatedRequirements {
		if !strings.HasPrefix(req, nistControlPrefix) {
			continue
		}
		controlID = strings.TrimSpace(sanitizeText(strings.TrimPrefix(req, nistControlPrefix)))
		if idx := strings.Index(controlID, "-"); idx > 0 {
			family = controlID[:idx]
		}
		return controlID, family, controlID != "" && family != ""
	}
	return "", "", false
}

func mapSeverity(s *types.Severity) nist.Severity {
	if s == nil {
		return nist.SeverityLow
	}
	if sev, ok := severityMap[s.Label]; ok {
		return sev
	}
	return nist.SeverityLow
}

// sanitizeText drops control characters from text that reaches the terminal.
// Finding titles can be written by any product integrated with Security Hub
// (BatchImportFindings), so an embedded ANSI/OSC escape sequence would
// otherwise be interpreted by the user's terminal in table and TUI output.
func sanitizeText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
