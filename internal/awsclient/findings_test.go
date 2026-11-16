package awsclient

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"cloudcomply/internal/nist"
)

func finding(account, title string, relatedReqs []string, status types.ComplianceStatus, sev types.SeverityLabel) types.AwsSecurityFinding {
	return types.AwsSecurityFinding{
		AwsAccountId: aws.String(account),
		Title:        aws.String(title),
		Compliance: &types.Compliance{
			RelatedRequirements: relatedReqs,
			Status:              status,
		},
		Severity: &types.Severity{Label: sev},
	}
}

func TestParseNISTControlIDs(t *testing.T) {
	tests := []struct {
		name string
		reqs []string
		want []string
	}{
		{"single", []string{"NIST.800-53.r5 AC-4", "PCI.DSS.321 1.2"}, []string{"AC-4"}},
		{"every NIST requirement, in order", []string{"NIST.800-53.r5 AC-4", "PCI.DSS.321 1.2", "NIST.800-53.r5 SC-7"}, []string{"AC-4", "SC-7"}},
		{"duplicates collapsed", []string{"NIST.800-53.r5 AC-4", "NIST.800-53.r5 AC-4"}, []string{"AC-4"}},
		{"malformed skipped, valid kept", []string{"NIST.800-53.r5 bogus", "NIST.800-53.r5 AU-12"}, []string{"AU-12"}},
		{"no match", []string{"PCI.DSS.321 1.2"}, nil},
		{"nil requirements", nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseNISTControlIDs(&types.Compliance{RelatedRequirements: tt.reqs})
			if len(got) != len(tt.want) {
				t.Fatalf("parseNISTControlIDs(%v) = %v, want %v", tt.reqs, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseNISTControlIDs(%v) = %v, want %v", tt.reqs, got, tt.want)
				}
			}
		})
	}
	if got := parseNISTControlIDs(nil); got != nil {
		t.Errorf("parseNISTControlIDs(nil) = %v, want nil", got)
	}
}

func notAvailable(account string, controls []string, reasonCodes ...string) types.AwsSecurityFinding {
	f := finding(account, "Unevaluated", controls, types.ComplianceStatusNotAvailable, types.SeverityLabelMedium)
	for _, code := range reasonCodes {
		f.Compliance.StatusReasons = append(f.Compliance.StatusReasons, types.StatusReason{ReasonCode: aws.String(code)})
	}
	return f
}

func TestMapStatus_NotAvailableByReasonCode(t *testing.T) {
	tests := []struct {
		name   string
		codes  []string
		want   nist.FindingStatus
		wantOK bool
	}{
		{"config access denied", []string{"CONFIG_ACCESS_DENIED"}, nist.StatusError, true},
		{"rule evaluation error", []string{"CONFIG_RULE_EVALUATION_ERROR"}, nist.StatusError, true},
		{"rule still being created", []string{"CONFIG_RULE_NOT_FOUND"}, nist.StatusError, true},
		{"internal service error", []string{"INTERNAL_SERVICE_ERROR"}, nist.StatusError, true},
		{"throttling", []string{"THROTTLING_ERROR"}, nist.StatusError, true},
		{"config says not applicable", []string{"CONFIG_RETURNS_NOT_APPLICABLE"}, nist.StatusNotApplicable, true},
		{"error outranks not applicable", []string{"CONFIG_RETURNS_NOT_APPLICABLE", "THROTTLING_ERROR"}, nist.StatusError, true},
		{"unrecognized code skipped", []string{"SOMETHING_NEW"}, "", false},
		{"no reason skipped", nil, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := mapStatus(notAvailable("1", []string{"NIST.800-53.r5 AC-6"}, tt.codes...).Compliance)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("mapStatus(NOT_AVAILABLE %v) = %q, %v; want %q, %v", tt.codes, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestToCheckResult_DetailCarriesReason(t *testing.T) {
	f := notAvailable("1", []string{"NIST.800-53.r5 AC-6"})
	f.Compliance.StatusReasons = []types.StatusReason{{
		ReasonCode:  aws.String("CONFIG_RULE_EVALUATION_ERROR"),
		Description: aws.String("missing permission s3:GetBucketPolicy"),
	}}
	r, ok := toCheckResult(f)
	if !ok || r.Status != nist.StatusError {
		t.Fatalf("toCheckResult = %+v, %v; want ERROR", r, ok)
	}
	if want := "CONFIG_RULE_EVALUATION_ERROR: missing permission s3:GetBucketPolicy"; r.Detail != want {
		t.Errorf("Detail = %q, want %q", r.Detail, want)
	}
}

// rollUp runs ASFF findings through the adapter and the shared rollup, the
// same path GetNISTFindings takes after paging.
func rollUp(findings ...types.AwsSecurityFinding) []nist.Finding {
	var results []nist.CheckResult
	for _, f := range findings {
		if r, ok := toCheckResult(f); ok {
			results = append(results, r)
		}
	}
	return nist.RollUp(results)
}

func TestToCheckResult(t *testing.T) {
	f := finding("111111111111", "Logging", []string{"NIST.800-53.r5 AU-12"}, types.ComplianceStatusWarning, types.SeverityLabelInformational)
	f.Compliance.SecurityControlId = aws.String("CloudTrail.1")
	f.Region = aws.String("us-gov-west-1")

	r, ok := toCheckResult(f)
	if !ok {
		t.Fatal("toCheckResult returned ok=false for a scorable NIST finding")
	}
	if r.CheckID != "CloudTrail.1" || r.Account != "111111111111" || r.Region != "us-gov-west-1" {
		t.Errorf("identity fields = %q/%q/%q", r.CheckID, r.Account, r.Region)
	}
	if r.Status != nist.StatusFailed {
		t.Errorf("WARNING mapped to %v, want FAILED", r.Status)
	}
	if r.Severity != nist.SeverityLow {
		t.Errorf("INFORMATIONAL mapped to %v, want LOW", r.Severity)
	}
	if len(r.Controls) != 1 || r.Controls[0] != "AU-12" {
		t.Errorf("Controls = %v, want [AU-12]", r.Controls)
	}
	if r.Detail != "" {
		t.Errorf("Detail = %q, want empty (no status reasons)", r.Detail)
	}
}

func TestRollUp_AllPassed(t *testing.T) {
	got := rollUp(
		finding("111111111111", "Account Management", []string{"NIST.800-53.r5 AC-2"}, types.ComplianceStatusPassed, types.SeverityLabelLow),
		finding("222222222222", "Account Management", []string{"NIST.800-53.r5 AC-2"}, types.ComplianceStatusPassed, types.SeverityLabelLow),
	)
	if len(got) != 1 {
		t.Fatalf("expected 1 aggregated finding, got %d", len(got))
	}
	f := got[0]
	if f.Status != nist.StatusPassed {
		t.Errorf("Status = %v, want PASSED", f.Status)
	}
	if f.AccountsAffected != 0 {
		t.Errorf("AccountsAffected = %d, want 0 (no failures)", f.AccountsAffected)
	}
	if f.RMFStep != "Monitor" {
		t.Errorf("RMFStep = %q, want Monitor", f.RMFStep)
	}
}

func TestRollUp_SomeFailedAcrossAccounts(t *testing.T) {
	got := rollUp(
		finding("111111111111", "Account Management", []string{"NIST.800-53.r5 AC-2"}, types.ComplianceStatusFailed, types.SeverityLabelHigh),
		finding("222222222222", "Account Management", []string{"NIST.800-53.r5 AC-2"}, types.ComplianceStatusFailed, types.SeverityLabelCritical),
		finding("333333333333", "Account Management", []string{"NIST.800-53.r5 AC-2"}, types.ComplianceStatusPassed, types.SeverityLabelLow),
		// Duplicate account+control failure shouldn't double-count.
		finding("111111111111", "Account Management", []string{"NIST.800-53.r5 AC-2"}, types.ComplianceStatusFailed, types.SeverityLabelHigh),
	)
	if len(got) != 1 {
		t.Fatalf("expected 1 aggregated finding, got %d", len(got))
	}
	f := got[0]
	if f.Status != nist.StatusFailed {
		t.Errorf("Status = %v, want FAILED", f.Status)
	}
	if f.AccountsAffected != 2 {
		t.Errorf("AccountsAffected = %d, want 2 distinct failing accounts", f.AccountsAffected)
	}
	if f.Severity != nist.SeverityCritical {
		t.Errorf("Severity = %v, want CRITICAL (highest among failures)", f.Severity)
	}
	if f.RMFStep != "Assess" {
		t.Errorf("RMFStep = %q, want Assess", f.RMFStep)
	}
	if f.MinImpactLevel != nist.IL2 {
		t.Errorf("MinImpactLevel = %v, want IL2 placeholder", f.MinImpactLevel)
	}
}

func TestToCheckResult_SkipsUnscorableAndNonNIST(t *testing.T) {
	got := rollUp(
		// Not a NIST 800-53 finding at all.
		finding("111111111111", "Other", []string{"PCI.DSS.321 1.2"}, types.ComplianceStatusFailed, types.SeverityLabelHigh),
		// NOT_AVAILABLE with no reason code — can't be classified, so skipped.
		finding("111111111111", "Other", []string{"NIST.800-53.r5 SC-7"}, types.ComplianceStatusNotAvailable, types.SeverityLabelHigh),
	)
	if len(got) != 0 {
		t.Errorf("expected no aggregated controls, got %d", len(got))
	}
}

func TestRollUp_SortedByControlID(t *testing.T) {
	got := rollUp(
		finding("1", "t", []string{"NIST.800-53.r5 SI-2"}, types.ComplianceStatusPassed, types.SeverityLabelLow),
		finding("1", "t", []string{"NIST.800-53.r5 AC-2"}, types.ComplianceStatusPassed, types.SeverityLabelLow),
		finding("1", "t", []string{"NIST.800-53.r5 CM-6"}, types.ComplianceStatusPassed, types.SeverityLabelLow),
	)
	want := []string{"AC-2", "CM-6", "SI-2"}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].ControlID != id {
			t.Errorf("got[%d].ControlID = %q, want %q", i, got[i].ControlID, id)
		}
	}
}

// The worked example from the scoring-change discussion: F's failure used to
// be credited only to SC-7, hiding that AC-4 fails too.
func TestRollUp_FindingCountsTowardEveryListedControl(t *testing.T) {
	got := rollUp(
		finding("1", "P", []string{"NIST.800-53.r5 AC-3", "NIST.800-53.r5 AC-6"}, types.ComplianceStatusPassed, types.SeverityLabelLow),
		finding("1", "F", []string{"NIST.800-53.r5 SC-7", "NIST.800-53.r5 AC-4"}, types.ComplianceStatusFailed, types.SeverityLabelHigh),
		finding("1", "Q", []string{"NIST.800-53.r5 AC-4"}, types.ComplianceStatusPassed, types.SeverityLabelLow),
	)
	want := map[string]nist.FindingStatus{
		"AC-3": nist.StatusPassed,
		"AC-4": nist.StatusFailed,
		"AC-6": nist.StatusPassed,
		"SC-7": nist.StatusFailed,
	}
	if len(got) != len(want) {
		t.Fatalf("got %d controls, want %d: %+v", len(got), len(want), got)
	}
	for _, f := range got {
		if f.Status != want[f.ControlID] {
			t.Errorf("%s = %v, want %v", f.ControlID, f.Status, want[f.ControlID])
		}
	}
	if score := nist.ComplianceScore(got); score != 50 {
		t.Errorf("score = %d, want 50", score)
	}
}

// A not-applicable NOT_AVAILABLE must not knock a well-covered control off
// PASSED; a genuine evaluation failure must stop it claiming a pass.
func TestRollUp_NotAvailableClassification(t *testing.T) {
	passes := make([]types.AwsSecurityFinding, 40)
	for i := range passes {
		passes[i] = finding("1", "Least Privilege", []string{"NIST.800-53.r5 AC-6"}, types.ComplianceStatusPassed, types.SeverityLabelLow)
	}

	got := rollUp(append(passes, notAvailable("1", []string{"NIST.800-53.r5 AC-6"}, "CONFIG_RETURNS_NOT_APPLICABLE"))...)
	if got[0].Status != nist.StatusPassed {
		t.Errorf("with not-applicable reason: AC-6 = %v, want PASSED", got[0].Status)
	}

	got = rollUp(append(passes, notAvailable("1", []string{"NIST.800-53.r5 AC-6"}, "CONFIG_ACCESS_DENIED"))...)
	if got[0].Status != nist.StatusError {
		t.Errorf("with access-denied reason: AC-6 = %v, want ERROR", got[0].Status)
	}
	if got[0].AccountsAffected != 0 {
		t.Errorf("AccountsAffected = %d, want 0 (an error isn't a failure)", got[0].AccountsAffected)
	}
}
