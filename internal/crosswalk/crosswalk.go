// Package crosswalk maps cloudcomply's native check IDs to every framework a
// finding is reported against: NIST SP 800-53 Rev 5, DoD Cloud Computing SRG
// impact levels, NIST AI RMF 1.0, and the OWASP Top 10 for LLM Applications.
//
// Mappings are data, not logic, and carry their provenance: either a cited
// published crosswalk or an explicit cloudcomply interpretation. Being
// explicit about which is which is part of the tool's credibility with
// assessors. This package has no AWS dependency.
package crosswalk

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/willj4945/cloudcomply/internal/nist"
)

// Source records where a mapping comes from.
type Source string

const (
	// SourcePublished means the mapping is taken from a published crosswalk;
	// Mapping.Citation must name it.
	SourcePublished Source = "published"
	// SourceInterpretation means no official mapping exists and this is
	// cloudcomply's own judgment.
	SourceInterpretation Source = "cloudcomply-interpretation"
)

// Mapping is the full framework crosswalk for one check.
type Mapping struct {
	NIST80053      []string         // e.g. "AU-12", "SC-7(3)"
	MinImpactLevel nist.ImpactLevel // lowest DoD CC SRG IL requiring the check
	AIRMF          []string         // e.g. "MEASURE 2.7", "MANAGE 4.1"
	OWASPLLM       []string         // e.g. "LLM01"
	Source         Source
	Citation       string // required when Source is SourcePublished
}

// mappings is keyed by check ID (e.g. "AI-AU-12-01"). Entries are added
// alongside the checks that use them, starting in Phase 2 of
// docs/ai-controls/plan.md.
var mappings = map[string]Mapping{}

// Lookup returns the mapping for a check ID.
func Lookup(checkID string) (Mapping, bool) {
	m, ok := mappings[checkID]
	return m, ok
}

var (
	nistControlRe = regexp.MustCompile(`^[A-Z]{2}-\d{1,2}(\(\d{1,2}\))?$`)
	aiRMFRe       = regexp.MustCompile(`^(GOVERN|MAP|MEASURE|MANAGE) \d+(\.\d+)?$`)
	owaspLLMRe    = regexp.MustCompile(`^LLM(0[1-9]|10)$`)
)

// Validate checks a mapping's identifiers and provenance.
func (m Mapping) Validate() error {
	var errs []error
	if len(m.NIST80053) == 0 {
		errs = append(errs, errors.New("no NIST 800-53 controls"))
	}
	for _, c := range m.NIST80053 {
		if !nistControlRe.MatchString(c) {
			errs = append(errs, fmt.Errorf("invalid NIST 800-53 control %q", c))
		}
	}
	if !m.MinImpactLevel.Valid() {
		errs = append(errs, fmt.Errorf("invalid impact level %q", m.MinImpactLevel))
	}
	for _, c := range m.AIRMF {
		if !aiRMFRe.MatchString(c) {
			errs = append(errs, fmt.Errorf("invalid AI RMF category %q (want e.g. \"MEASURE 2.7\")", c))
		}
	}
	for _, r := range m.OWASPLLM {
		if !owaspLLMRe.MatchString(r) {
			errs = append(errs, fmt.Errorf("invalid OWASP LLM risk %q (want LLM01-LLM10)", r))
		}
	}
	switch m.Source {
	case SourcePublished:
		if m.Citation == "" {
			errs = append(errs, errors.New("published mapping has no citation"))
		}
	case SourceInterpretation:
	default:
		errs = append(errs, fmt.Errorf("unknown source %q", m.Source))
	}
	return errors.Join(errs...)
}
