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

func TestParseNISTControlID(t *testing.T) {
	tests := []struct {
		name   string
		reqs   []string
		wantID string
		wantOK bool
	}{
		{"matches", []string{"NIST.800-53.r5 AC-4", "PCI.DSS.321 1.2"}, "AC-4", true},
		{"first NIST requirement wins", []string{"NIST.800-53.r5 AC-4", "NIST.800-53.r5 SC-7"}, "AC-4", true},
		{"no match", []string{"PCI.DSS.321 1.2"}, "", false},
		{"no family prefix", []string{"NIST.800-53.r5 bogus"}, "bogus", false},
		{"nil requirements", nil, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &types.Compliance{RelatedRequirements: tt.reqs}
			id, ok := parseNISTControlID(c)
			if id != tt.wantID || ok != tt.wantOK {
				t.Errorf("parseNISTControlID(%v) = %q, %v; want %q, %v",
					tt.reqs, id, ok, tt.wantID, tt.wantOK)
			}
		})
	}
	if _, ok := parseNISTControlID(nil); ok {
		t.Error("parseNISTControlID(nil) should return ok=false")
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
		// NIST finding but NOT_AVAILABLE — can't be scored.
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
