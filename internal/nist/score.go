package nist

// Tally counts findings by status.
type Tally struct {
	Passed        int
	Failed        int
	NotApplicable int
	Errors        int
}

// Summarize tallies findings by status. Callers filter first (by family,
// impact level, …) so the same rollup serves every view.
func Summarize(findings []Finding) Tally {
	var t Tally
	for _, f := range findings {
		switch f.Status {
		case StatusPassed:
			t.Passed++
		case StatusFailed:
			t.Failed++
		case StatusNotApplicable:
			t.NotApplicable++
		case StatusError:
			t.Errors++
		}
	}
	return t
}

// Score returns the percentage of scorable findings that passed.
// NOT_APPLICABLE is excluded from the denominator; ERROR stays in it, so
// findings that couldn't be evaluated pull the score down rather than
// silently disappearing.
func (t Tally) Score() int {
	denom := t.Passed + t.Failed + t.Errors
	if denom == 0 {
		return 0
	}
	return (t.Passed * 100) / denom
}

// ComplianceScore returns the percentage of scorable findings with status
// PASSED (see Tally.Score).
func ComplianceScore(findings []Finding) int {
	return Summarize(findings).Score()
}

// ComplianceScoreForImpactLevel scores only the findings in scope for a
// Mission Owner targeting the given DoD CC SRG Impact Level.
func ComplianceScoreForImpactLevel(findings []Finding, target ImpactLevel) int {
	var inScope []Finding
	for _, f := range findings {
		if ImpactLevelAtOrBelow(f.MinImpactLevel, target) {
			inScope = append(inScope, f)
		}
	}
	return ComplianceScore(inScope)
}
