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
	Title          string           // short check title, shown as the result title
	NIST80053      []string         // e.g. "AU-12", "SC-7(3)"
	MinImpactLevel nist.ImpactLevel // lowest DoD CC SRG IL requiring the check
	AIRMF          []string         // e.g. "MEASURE 2.7", "MANAGE 4.1"
	OWASPLLM       []string         // e.g. "LLM01"
	Source         Source
	Citation       string // required when Source is SourcePublished
}

// mappings is keyed by check ID (e.g. "AI-AU-12-01"). Entries are added
// alongside the checks that use them (docs/ai-controls/plan.md).
//
// AI RMF and OWASP mappings below are cloudcomply's interpretation: no
// published crosswalk maps Bedrock invocation logging to either framework.
// AI RMF IDs are NIST AI 100-1 subcategories; OWASP IDs are the 2025 Top 10
// for LLM Applications.
var mappings = map[string]Mapping{
	// Invocation logging is the detection prerequisite for LLM incident
	// response: a prompt injection or runaway usage that was never logged
	// can't be investigated.
	"AI-AU-12-01": {
		Title:          "Bedrock model invocation logging enabled",
		NIST80053:      []string{"AU-12", "AU-2"},
		MinImpactLevel: nist.IL2,
		AIRMF:          []string{"MEASURE 2.4", "MANAGE 4.1"},
		OWASPLLM:       []string{"LLM01", "LLM10"},
		Source:         SourceInterpretation,
	},
	// Without text delivery the logs record that a call happened but not the
	// prompt or response, which is what an investigation needs.
	"AI-AU-12-02": {
		Title:          "Bedrock invocation logs capture prompt and response text",
		NIST80053:      []string{"AU-12", "AU-3"},
		MinImpactLevel: nist.IL2,
		AIRMF:          []string{"MEASURE 2.4"},
		OWASPLLM:       []string{"LLM01", "LLM02"},
		Source:         SourceInterpretation,
	},
}

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
	if m.Title == "" {
		errs = append(errs, errors.New("no title"))
	}
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
