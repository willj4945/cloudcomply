package nist

import (
	"sort"
	"strings"
)

var severityRank = map[Severity]int{
	SeverityCritical: 3,
	SeverityHigh:     2,
	SeverityMedium:   1,
	SeverityLow:      0,
}

// statusRank orders how a control's status is decided from its results: one
// failure fails the control; with no failures, any error means the control
// can't be claimed as passing; it is NOT_APPLICABLE only if every result is.
var statusRank = map[FindingStatus]int{
	StatusFailed:        3,
	StatusError:         2,
	StatusPassed:        1,
	StatusNotApplicable: 0,
}

type controlAggregate struct {
	controlID string
	title     string
	severity  Severity
	status    FindingStatus
	accounts  map[string]bool
	minIL     ImpactLevel
}

// RollUp aggregates check results into one Finding per NIST control. A
// result mapped to several controls counts toward each of them.
func RollUp(results []CheckResult) []Finding {
	agg := map[string]*controlAggregate{}
	for _, r := range results {
		if _, known := statusRank[r.Status]; !known {
			continue
		}
		for _, controlID := range r.Controls {
			merge(agg, controlID, r)
		}
	}

	out := make([]Finding, 0, len(agg))
	for _, a := range agg {
		family, _, _ := strings.Cut(a.controlID, "-")
		rmfStep := "Monitor"
		if a.status == StatusFailed || a.status == StatusError {
			rmfStep = "Assess"
		}
		minIL := a.minIL
		if minIL == "" {
			minIL = IL2
		}
		out = append(out, Finding{
			ControlID:        a.controlID,
			Title:            a.title,
			Family:           family,
			Status:           a.status,
			Severity:         a.severity,
			AccountsAffected: len(a.accounts),
			RMFStep:          rmfStep,
			MinImpactLevel:   minIL,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ControlID < out[j].ControlID })
	return out
}

func merge(agg map[string]*controlAggregate, controlID string, r CheckResult) {
	a, exists := agg[controlID]
	if !exists {
		a = &controlAggregate{
			controlID: controlID,
			title:     r.Title,
			severity:  r.Severity,
			status:    r.Status,
			accounts:  map[string]bool{},
			minIL:     r.MinImpactLevel,
		}
		agg[controlID] = a
	}
	if statusRank[r.Status] > statusRank[a.status] {
		a.status = r.Status
	}
	if r.MinImpactLevel != "" && (a.minIL == "" || impactLevelIndex(r.MinImpactLevel) < impactLevelIndex(a.minIL)) {
		a.minIL = r.MinImpactLevel
	}
	if r.Status == StatusFailed {
		a.accounts[r.Account] = true
		if severityRank[r.Severity] > severityRank[a.severity] {
			a.severity = r.Severity
		}
	}
}
