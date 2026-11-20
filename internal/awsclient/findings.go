package awsclient

import (
	"context"
	"fmt"
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
	types.ComplianceStatusPassed: nist.StatusPassed,
	types.ComplianceStatusFailed: nist.StatusFailed,
	// Every WARNING reason in the Security Hub CSPM User Guide's reason-code
	// table is a cross-account / cross-Region "can't check from here" case
	// (e.g. SNS_TOPIC_CROSS_ACCOUNT), not a detected misconfiguration.
	types.ComplianceStatusWarning: nist.StatusError,
	// NOT_AVAILABLE is classified by reason code in mapStatus; any future
	// values are intentionally absent and the finding is skipped.
}

// notAvailableReasons classifies NOT_AVAILABLE findings by
// Compliance.StatusReasons[].ReasonCode. Security Hub uses NOT_AVAILABLE for
// both "couldn't evaluate" and "nothing to evaluate", and the reason code is
// the only way to tell them apart. Source: the reason-code table in
// "Compliance details for control findings", Security Hub CSPM User Guide
// (controls-findings-create-update.html), retrieved 2026-11-16. Codes not
// listed here, and findings with no reason, are skipped rather than guessed
// at.
var notAvailableReasons = map[string]nist.FindingStatus{
	"CONFIG_ACCESS_DENIED":         nist.StatusError,
	"CONFIG_RULE_EVALUATION_ERROR": nist.StatusError,
	// The rule is still being created: the control genuinely hasn't been
	// evaluated yet, so it can't be claimed as passing.
	"CONFIG_RULE_NOT_FOUND":         nist.StatusError,
	"INTERNAL_SERVICE_ERROR":        nist.StatusError,
	"THROTTLING_ERROR":              nist.StatusError,
	"CONFIG_RETURNS_NOT_APPLICABLE": nist.StatusNotApplicable,
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

// toCheckResult adapts one ASFF finding into the shared result model. The
// finding counts toward every NIST control it lists, matching how Security
// Hub's own NIST standard attributes it.
func toCheckResult(f types.AwsSecurityFinding) (nist.CheckResult, bool) {
	controls := parseNISTControlIDs(f.Compliance)
	if len(controls) == 0 {
		return nist.CheckResult{}, false
	}
	status, scorable := mapStatus(f.Compliance)
	if !scorable {
		return nist.CheckResult{}, false
	}
	return nist.CheckResult{
		CheckID: sanitizeText(aws.ToString(f.Compliance.SecurityControlId)),
		// Best-effort: Security Hub's per-security-control title, not an
		// official NIST 800-53 control title (no such lookup exists via
		// this API). TODO(nistmap): replace with a real control-title
		// lookup alongside the DoD SRG impact-level crosswalk.
		Title:    sanitizeText(aws.ToString(f.Title)),
		Controls: controls,
		Status:   status,
		Severity: mapSeverity(f.Severity),
		Account:  aws.ToString(f.AwsAccountId),
		Region:   aws.ToString(f.Region),
		Detail:   sanitizeText(statusReasonDetail(f.Compliance)),
		// MinImpactLevel left empty: AWS has no concept of DoD SRG impact
		// levels, so RollUp applies its IL2 placeholder. TODO(nistmap).
	}, true
}

// mapStatus is only called after parseNISTControlIDs found a control, so c
// is non-nil.
func mapStatus(c *types.Compliance) (nist.FindingStatus, bool) {
	if s, ok := statusMap[c.Status]; ok {
		return s, true
	}
	if c.Status != types.ComplianceStatusNotAvailable {
		return "", false
	}
	var status nist.FindingStatus
	for _, r := range c.StatusReasons {
		s := notAvailableReasons[aws.ToString(r.ReasonCode)]
		if s == nist.StatusError {
			return nist.StatusError, true
		}
		if s == nist.StatusNotApplicable {
			status = s
		}
	}
	return status, status != ""
}

// statusReasonDetail renders Compliance.StatusReasons as
// "CODE: description; CODE: description" so an ERROR result says why.
func statusReasonDetail(c *types.Compliance) string {
	var parts []string
	for _, r := range c.StatusReasons {
		code := aws.ToString(r.ReasonCode)
		if desc := aws.ToString(r.Description); desc != "" {
			code += ": " + desc
		}
		parts = append(parts, code)
	}
	return strings.Join(parts, "; ")
}

// parseNISTControlIDs extracts every NIST 800-53 control ID (e.g. "AC-4")
// from a finding's Compliance.RelatedRequirements, in order, without
// duplicates. Malformed entries are skipped.
func parseNISTControlIDs(c *types.Compliance) []string {
	if c == nil {
		return nil
	}
	var ids []string
	seen := map[string]bool{}
	for _, req := range c.RelatedRequirements {
		if !strings.HasPrefix(req, nistControlPrefix) {
			continue
		}
		id := strings.TrimSpace(sanitizeText(strings.TrimPrefix(req, nistControlPrefix)))
		if strings.Index(id, "-") <= 0 || seen[id] {
			continue
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids
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
// Finding fields can be written by any product integrated with Security Hub
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
