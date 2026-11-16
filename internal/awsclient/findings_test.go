package awsclient

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"

	"github.com/willj4945/cloudcomply/internal/nist"
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
		name    string
		reqs    []string
		wantID  string
		wantFam string
		wantOK  bool
	}{
		{"matches", []string{"NIST.800-53.r5 AC-4", "PCI.DSS.321 1.2"}, "AC-4", "AC", true},
		{"no match", []string{"PCI.DSS.321 1.2"}, "", "", false},
		{"nil requirements", nil, "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &types.Compliance{RelatedRequirements: tt.reqs}
			id, fam, ok := parseNISTControlID(c)
			if id != tt.wantID || fam != tt.wantFam || ok != tt.wantOK {
				t.Errorf("parseNISTControlID(%v) = %q, %q, %v; want %q, %q, %v",
					tt.reqs, id, fam, ok, tt.wantID, tt.wantFam, tt.wantOK)
			}
		})
	}
	if _, _, ok := parseNISTControlID(nil); ok {
		t.Error("parseNISTControlID(nil) should return ok=false")
	}
}

func TestMergeAndFinalize_AllPassed(t *testing.T) {
	agg := map[string]*controlAggregate{}
	mergeFinding(agg, finding("111111111111", "Account Management", []string{"NIST.800-53.r5 AC-2"}, types.ComplianceStatusPassed, types.SeverityLabelLow))
	mergeFinding(agg, finding("222222222222", "Account Management", []string{"NIST.800-53.r5 AC-2"}, types.ComplianceStatusPassed, types.SeverityLabelLow))

	got := finalizeFindings(agg)
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

func TestMergeAndFinalize_SomeFailedAcrossAccounts(t *testing.T) {
	agg := map[string]*controlAggregate{}
	mergeFinding(agg, finding("111111111111", "Account Management", []string{"NIST.800-53.r5 AC-2"}, types.ComplianceStatusFailed, types.SeverityLabelHigh))
	mergeFinding(agg, finding("222222222222", "Account Management", []string{"NIST.800-53.r5 AC-2"}, types.ComplianceStatusFailed, types.SeverityLabelCritical))
	mergeFinding(agg, finding("333333333333", "Account Management", []string{"NIST.800-53.r5 AC-2"}, types.ComplianceStatusPassed, types.SeverityLabelLow))
	// Duplicate account+control failure shouldn't double-count.
	mergeFinding(agg, finding("111111111111", "Account Management", []string{"NIST.800-53.r5 AC-2"}, types.ComplianceStatusFailed, types.SeverityLabelHigh))

	got := finalizeFindings(agg)
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

func TestMergeFinding_SkipsUnscorableAndNonNIST(t *testing.T) {
	agg := map[string]*controlAggregate{}
	// Not a NIST 800-53 finding at all.
	mergeFinding(agg, finding("111111111111", "Other", []string{"PCI.DSS.321 1.2"}, types.ComplianceStatusFailed, types.SeverityLabelHigh))
	// NIST finding but NOT_AVAILABLE — can't be scored.
	mergeFinding(agg, finding("111111111111", "Other", []string{"NIST.800-53.r5 SC-7"}, types.ComplianceStatusNotAvailable, types.SeverityLabelHigh))

	if len(agg) != 0 {
		t.Errorf("expected no aggregated controls, got %d", len(agg))
	}
}

func TestFinalizeFindings_SortedByControlID(t *testing.T) {
	agg := map[string]*controlAggregate{}
	mergeFinding(agg, finding("1", "t", []string{"NIST.800-53.r5 SI-2"}, types.ComplianceStatusPassed, types.SeverityLabelLow))
	mergeFinding(agg, finding("1", "t", []string{"NIST.800-53.r5 AC-2"}, types.ComplianceStatusPassed, types.SeverityLabelLow))
	mergeFinding(agg, finding("1", "t", []string{"NIST.800-53.r5 CM-6"}, types.ComplianceStatusPassed, types.SeverityLabelLow))

	got := finalizeFindings(agg)
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

func TestMergeFinding_StripsControlCharsFromTitle(t *testing.T) {
	agg := map[string]*controlAggregate{}
	evil := "Bad\x1b]52;c;ZXZpbA==\x07Title\x1b[2J\n"
	mergeFinding(agg, finding("111111111111", evil, []string{"NIST.800-53.r5 AC-2"}, types.ComplianceStatusFailed, types.SeverityLabelHigh))

	got := finalizeFindings(agg)
	if len(got) != 1 {
		t.Fatalf("expected 1 aggregated finding, got %d", len(got))
	}
	if want := "Bad]52;c;ZXZpbA==Title[2J"; got[0].Title != want {
		t.Errorf("Title = %q, want %q", got[0].Title, want)
	}
}
