package awsclient

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"cloudcomply/internal/nist"
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

// GetNISTFindings fetches every active Security Hub finding associated with
// the NIST SP 800-53 standard and rolls them up into one nist.Finding per
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

	var results []nist.CheckResult
	p := securityhub.NewGetFindingsPaginator(c.sh, &securityhub.GetFindingsInput{Filters: filters})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("get findings: %w", err)
		}
		for _, f := range page.Findings {
			if r, ok := toCheckResult(f); ok {
				results = append(results, r)
			}
		}
	}
	return nist.RollUp(results), nil
}

// toCheckResult adapts one ASFF finding into the shared result model.
// It deliberately preserves pre-CheckResult behavior so live output doesn't
// shift under users: only the first NIST requirement is used even when a
// finding lists several, and NOT_AVAILABLE findings are dropped rather than
// reported as ERROR. Changing either is a scoring change to make on purpose.
func toCheckResult(f types.AwsSecurityFinding) (nist.CheckResult, bool) {
	controlID, ok := parseNISTControlID(f.Compliance)
	if !ok {
		return nist.CheckResult{}, false
	}
	status, scorable := statusMap[f.Compliance.Status]
	if !scorable {
		return nist.CheckResult{}, false
	}
	return nist.CheckResult{
		CheckID: aws.ToString(f.Compliance.SecurityControlId),
		// Best-effort: Security Hub's per-security-control title, not an
		// official NIST 800-53 control title (no such lookup exists via
		// this API). TODO(nistmap): replace with a real control-title
		// lookup alongside the DoD SRG impact-level crosswalk.
		Title:    aws.ToString(f.Title),
		Controls: []string{controlID},
		Status:   status,
		Severity: mapSeverity(f.Severity),
		Account:  aws.ToString(f.AwsAccountId),
		Region:   aws.ToString(f.Region),
		// MinImpactLevel left empty: AWS has no concept of DoD SRG impact
		// levels, so RollUp applies its IL2 placeholder. TODO(nistmap).
	}, true
}

// parseNISTControlID extracts the first NIST 800-53 control ID (e.g. "AC-4")
// from a finding's Compliance.RelatedRequirements.
func parseNISTControlID(c *types.Compliance) (controlID string, ok bool) {
	if c == nil {
		return "", false
	}
	for _, req := range c.RelatedRequirements {
		if !strings.HasPrefix(req, nistControlPrefix) {
			continue
		}
		controlID = strings.TrimSpace(strings.TrimPrefix(req, nistControlPrefix))
		return controlID, strings.Index(controlID, "-") > 0
	}
	return "", false
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
