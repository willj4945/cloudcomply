// Package nist holds the domain types and scoring logic for NIST SP 800-53 /
// DoD Cloud Computing SRG compliance findings, independent of how those
// findings are sourced (demo data today, live Security Hub later) or
// rendered (TUI, headless report).
package nist

type Severity string
type FindingStatus string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"

	StatusFailed FindingStatus = "FAILED"
	StatusPassed FindingStatus = "PASSED"
	// StatusNotApplicable marks a check whose subject doesn't exist in scope
	// (e.g. no Bedrock usage in an account). Excluded from score denominators.
	StatusNotApplicable FindingStatus = "NOT_APPLICABLE"
	// StatusError marks a check that couldn't be evaluated (access denied,
	// API failure). It is never counted as a pass: a tool that reports
	// compliance because it couldn't see anything is worse than no tool.
	StatusError FindingStatus = "ERROR"
)

// ImpactLevel is a DoD Cloud Computing SRG Impact Level (IL2/IL4/IL5/IL6).
// Levels are cumulative: a control required starting at IL2 is also in scope
// at IL4/IL5/IL6, matching how the SRG's baselines stack in practice.
type ImpactLevel string

const (
	IL2 ImpactLevel = "IL2"
	IL4 ImpactLevel = "IL4"
	IL5 ImpactLevel = "IL5"
	IL6 ImpactLevel = "IL6"
)

var impactLevelOrder = []ImpactLevel{IL2, IL4, IL5, IL6}

func impactLevelIndex(l ImpactLevel) int {
	for i, il := range impactLevelOrder {
		if il == l {
			return i
		}
	}
	return -1
}

// Valid reports whether l is one of the defined impact levels.
func (l ImpactLevel) Valid() bool {
	return impactLevelIndex(l) >= 0
}

// ImpactLevelAtOrBelow reports whether a control whose minimum required
// level is min is also in scope for a Mission Owner targeting target.
func ImpactLevelAtOrBelow(min, target ImpactLevel) bool {
	return impactLevelIndex(min) <= impactLevelIndex(target)
}

// Finding mirrors the shape of a real Security Hub NIST 800-53 finding.
// Switching from fake data to live AWS calls later means replacing
// DemoFindings() without touching anything else. JSON tags are deliberately
// snake_case (not a mirror of Security Hub's PascalCase API) and, once the
// `report nist --format json` path ships, are a stable contract — don't
// rename fields without a version bump.
type Finding struct {
	ControlID        string        `json:"control_id"`
	Title            string        `json:"title"`
	Family           string        `json:"family"` // e.g. "AC", "AU", "CM"
	Status           FindingStatus `json:"status"`
	Severity         Severity      `json:"severity"`
	AccountsAffected int           `json:"accounts_affected"`
	RMFStep          string        `json:"rmf_step"`         // e.g. "Assess", "Monitor", "Implement"
	MinImpactLevel   ImpactLevel   `json:"min_impact_level"` // lowest DoD CC SRG Impact Level at which this control is required for a Mission Owner
}

// OrgSummary is a lightweight snapshot of the AWS Organization being assessed,
// sourced from either demo data or a live Organizations API call.
type OrgSummary struct {
	Name         string `json:"name"`
	AccountCount int    `json:"account_count"`
	// IsOrgMode is false when the credentials in use aren't part of an AWS
	// Organization at all (AWSOrganizationsNotInUseException) — cloudcomply
	// falls back to scoring the single account rather than failing outright,
	// since org-wide access is often gated behind separate approval.
	IsOrgMode bool `json:"is_org_mode"`
}

// CheckResult is one evaluation of one check against one resource (or
// account/region scope). It is the unit both Security Hub findings and
// native checks are normalized into; RollUp aggregates results into the
// per-control Finding rows that the TUI and `report nist` display.
type CheckResult struct {
	CheckID  string        `json:"check_id"`
	Title    string        `json:"title"`
	Controls []string      `json:"controls"` // NIST 800-53 Rev 5 IDs, e.g. "AU-12"
	Status   FindingStatus `json:"status"`
	Severity Severity      `json:"severity"`
	Account  string        `json:"account"`
	Region   string        `json:"region,omitempty"`
	Resource string        `json:"resource,omitempty"`
	// Detail explains a FAILED/ERROR result; for ERROR it names the denied
	// action or failing API call.
	Detail string `json:"detail,omitempty"`
	// MinImpactLevel is empty when unknown; RollUp then falls back to IL2,
	// matching the Security Hub path's long-standing placeholder.
	MinImpactLevel ImpactLevel `json:"min_impact_level,omitempty"`
}
