package nist

import "testing"

func findings(statuses ...FindingStatus) []Finding {
	out := make([]Finding, len(statuses))
	for i, s := range statuses {
		out[i] = Finding{ControlID: "AC-2", Status: s, MinImpactLevel: IL2}
	}
	return out
}

func TestComplianceScore(t *testing.T) {
	tests := []struct {
		name string
		in   []Finding
		want int
	}{
		{"empty scores zero, not 100", nil, 0},
		{"pass/fail only", findings(StatusPassed, StatusFailed, StatusPassed, StatusFailed), 50},
		{"N/A excluded from denominator", findings(StatusPassed, StatusNotApplicable, StatusNotApplicable), 100},
		{"errors stay in denominator", findings(StatusPassed, StatusError), 50},
		{"only N/A scores zero", findings(StatusNotApplicable), 0},
		{"only errors scores zero", findings(StatusError, StatusError), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ComplianceScore(tt.in); got != tt.want {
				t.Errorf("ComplianceScore = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSummarize(t *testing.T) {
	got := Summarize(findings(StatusPassed, StatusPassed, StatusFailed, StatusNotApplicable, StatusError, StatusError))
	want := Tally{Passed: 2, Failed: 1, NotApplicable: 1, Errors: 2}
	if got != want {
		t.Errorf("Summarize = %+v, want %+v", got, want)
	}
}

// Demo data is the score users see first; scoring changes must not move it.
func TestComplianceScore_DemoUnchanged(t *testing.T) {
	if got := ComplianceScore(DemoFindings()); got != 40 {
		t.Errorf("demo score = %d, want 40", got)
	}
	if got := ComplianceScoreForImpactLevel(DemoFindings(), IL5); got != 42 {
		t.Errorf("demo IL5 score = %d, want 42", got)
	}
}

func TestComplianceScoreForImpactLevel(t *testing.T) {
	in := []Finding{
		{Status: StatusPassed, MinImpactLevel: IL2},
		{Status: StatusFailed, MinImpactLevel: IL5},
	}
	if got := ComplianceScoreForImpactLevel(in, IL4); got != 100 {
		t.Errorf("IL4 score = %d, want 100 (IL5 control out of scope)", got)
	}
	if got := ComplianceScoreForImpactLevel(in, IL5); got != 50 {
		t.Errorf("IL5 score = %d, want 50", got)
	}
}
