package nist

import "testing"

func result(check string, controls []string, status FindingStatus, account string) CheckResult {
	return CheckResult{
		CheckID:  check,
		Title:    check + " title",
		Controls: controls,
		Status:   status,
		Severity: SeverityMedium,
		Account:  account,
	}
}

func byControl(findings []Finding) map[string]Finding {
	m := map[string]Finding{}
	for _, f := range findings {
		m[f.ControlID] = f
	}
	return m
}

func TestRollUp_StatusPrecedence(t *testing.T) {
	tests := []struct {
		name     string
		statuses []FindingStatus
		want     FindingStatus
		wantStep string
	}{
		{"all passed", []FindingStatus{StatusPassed, StatusPassed}, StatusPassed, "Monitor"},
		{"one failure fails the control", []FindingStatus{StatusPassed, StatusError, StatusFailed, StatusNotApplicable}, StatusFailed, "Assess"},
		{"error blocks a pass", []FindingStatus{StatusPassed, StatusError}, StatusError, "Assess"},
		{"N/A doesn't dilute a pass", []FindingStatus{StatusNotApplicable, StatusPassed}, StatusPassed, "Monitor"},
		{"all N/A", []FindingStatus{StatusNotApplicable, StatusNotApplicable}, StatusNotApplicable, "Monitor"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var results []CheckResult
			for _, s := range tt.statuses {
				results = append(results, result("X.1", []string{"AU-12"}, s, "111111111111"))
			}
			got := RollUp(results)
			if len(got) != 1 {
				t.Fatalf("got %d findings, want 1", len(got))
			}
			if got[0].Status != tt.want || got[0].RMFStep != tt.wantStep {
				t.Errorf("Status/RMFStep = %v/%q, want %v/%q", got[0].Status, got[0].RMFStep, tt.want, tt.wantStep)
			}
		})
	}
}

func TestRollUp_ResultCountsTowardEveryMappedControl(t *testing.T) {
	got := byControl(RollUp([]CheckResult{
		result("AI-AU-12-01", []string{"AU-12", "AU-2"}, StatusFailed, "111111111111"),
		result("AI-AU-12-01", []string{"AU-12", "AU-2"}, StatusFailed, "222222222222"),
	}))
	for _, id := range []string{"AU-12", "AU-2"} {
		f, ok := got[id]
		if !ok {
			t.Fatalf("missing rollup row for %s", id)
		}
		if f.Status != StatusFailed || f.AccountsAffected != 2 || f.Family != "AU" {
			t.Errorf("%s = %+v, want FAILED, 2 accounts, family AU", id, f)
		}
	}
}

func TestRollUp_OnlyFailuresCountAccountsAndEscalateSeverity(t *testing.T) {
	errored := result("X.1", []string{"SC-7"}, StatusError, "111111111111")
	errored.Severity = SeverityCritical
	failed := result("X.1", []string{"SC-7"}, StatusFailed, "222222222222")
	failed.Severity = SeverityHigh

	got := RollUp([]CheckResult{errored, failed})
	f := got[0]
	if f.AccountsAffected != 1 {
		t.Errorf("AccountsAffected = %d, want 1 (errors aren't failures)", f.AccountsAffected)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("Severity = %v, want CRITICAL (first-seen severity, escalated only by failures)", f.Severity)
	}
}

func TestRollUp_MinImpactLevel(t *testing.T) {
	il5 := result("A", []string{"AC-6"}, StatusPassed, "1")
	il5.MinImpactLevel = IL5
	il4 := result("B", []string{"AC-6"}, StatusPassed, "1")
	il4.MinImpactLevel = IL4
	unknown := result("C", []string{"CM-5"}, StatusPassed, "1")

	got := byControl(RollUp([]CheckResult{il5, il4, unknown}))
	if got["AC-6"].MinImpactLevel != IL4 {
		t.Errorf("AC-6 MinImpactLevel = %v, want IL4 (lowest of contributing checks)", got["AC-6"].MinImpactLevel)
	}
	if got["CM-5"].MinImpactLevel != IL2 {
		t.Errorf("CM-5 MinImpactLevel = %v, want IL2 fallback", got["CM-5"].MinImpactLevel)
	}
}

func TestRollUp_SkipsUnknownStatusAndSorts(t *testing.T) {
	got := RollUp([]CheckResult{
		result("A", []string{"SI-2"}, StatusPassed, "1"),
		result("B", []string{"AC-2"}, StatusPassed, "1"),
		result("C", []string{"CM-6"}, FindingStatus("BOGUS"), "1"),
	})
	want := []string{"AC-2", "SI-2"}
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d", len(got), len(want))
	}
	for i, id := range want {
		if got[i].ControlID != id {
			t.Errorf("got[%d] = %q, want %q", i, got[i].ControlID, id)
		}
	}
}
