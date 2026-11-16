package crosswalk

import (
	"strings"
	"testing"

	"cloudcomply/internal/nist"
)

func TestAllMappingsValid(t *testing.T) {
	for id, m := range mappings {
		if err := m.Validate(); err != nil {
			t.Errorf("mapping %s: %v", id, err)
		}
	}
}

func valid() Mapping {
	return Mapping{
		NIST80053:      []string{"AU-12", "SC-7(3)"},
		MinImpactLevel: nist.IL4,
		AIRMF:          []string{"MEASURE 2.7", "MANAGE 4"},
		OWASPLLM:       []string{"LLM01", "LLM10"},
		Source:         SourceInterpretation,
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Mapping)
		wantErr string
	}{
		{"valid", func(*Mapping) {}, ""},
		{"published with citation", func(m *Mapping) { m.Source, m.Citation = SourcePublished, "NIST AI 100-1 crosswalk" }, ""},
		{"no controls", func(m *Mapping) { m.NIST80053 = nil }, "no NIST 800-53 controls"},
		{"bad control", func(m *Mapping) { m.NIST80053 = []string{"AU12"} }, `invalid NIST 800-53 control "AU12"`},
		{"bad impact level", func(m *Mapping) { m.MinImpactLevel = "IL3" }, `invalid impact level "IL3"`},
		{"missing impact level", func(m *Mapping) { m.MinImpactLevel = "" }, "invalid impact level"},
		{"vague AI RMF category", func(m *Mapping) { m.AIRMF = []string{"MEASURE 2.x"} }, `invalid AI RMF category "MEASURE 2.x"`},
		{"bad OWASP risk", func(m *Mapping) { m.OWASPLLM = []string{"LLM11"} }, `invalid OWASP LLM risk "LLM11"`},
		{"published without citation", func(m *Mapping) { m.Source = SourcePublished }, "no citation"},
		{"missing source", func(m *Mapping) { m.Source = "" }, "unknown source"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := valid()
			tt.mutate(&m)
			err := m.Validate()
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("unexpected error: %v", err)
			case tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)):
				t.Errorf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLookup(t *testing.T) {
	mappings["TEST-1"] = valid()
	defer delete(mappings, "TEST-1")

	if m, ok := Lookup("TEST-1"); !ok || m.MinImpactLevel != nist.IL4 {
		t.Errorf("Lookup(TEST-1) = %+v, %v", m, ok)
	}
	if _, ok := Lookup("missing"); ok {
		t.Error("Lookup(missing) returned ok=true")
	}
}
