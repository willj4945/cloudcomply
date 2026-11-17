package tui

import (
	"testing"

	"github.com/willj4945/cloudcomply/internal/nist"
)

func TestFilterFindings(t *testing.T) {
	in := []nist.Finding{
		{ControlID: "AC-2", Family: "AC", MinImpactLevel: nist.IL2},
		{ControlID: "AC-6", Family: "AC", MinImpactLevel: nist.IL5},
		{ControlID: "AU-12", Family: "AU", MinImpactLevel: nist.IL2},
	}
	tests := []struct {
		name, family, il string
		want             []string
	}{
		{"no filter", "ALL", "ALL", []string{"AC-2", "AC-6", "AU-12"}},
		{"family", "AC", "ALL", []string{"AC-2", "AC-6"}},
		{"impact level", "ALL", "IL4", []string{"AC-2", "AU-12"}},
		{"both", "AC", "IL4", []string{"AC-2"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterFindings(in, tt.family, tt.il)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d findings, want %d", len(got), len(tt.want))
			}
			for i, id := range tt.want {
				if got[i].ControlID != id {
					t.Errorf("got[%d] = %q, want %q", i, got[i].ControlID, id)
				}
			}
		})
	}
}

func TestBuildTable_RowsMatchFilterAndShortenNA(t *testing.T) {
	in := []nist.Finding{
		{ControlID: "AU-12", Family: "AU", Status: nist.StatusNotApplicable, MinImpactLevel: nist.IL2},
		{ControlID: "SC-7", Family: "SC", Status: nist.StatusError, MinImpactLevel: nist.IL2},
	}
	rows := buildTable(in, "ALL", "ALL").Rows()
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0][2] != "N/A" || rows[1][2] != "ERROR" {
		t.Errorf("status cells = %q, %q; want N/A, ERROR", rows[0][2], rows[1][2])
	}
	if got := len(buildTable(in, "SC", "ALL").Rows()); got != 1 {
		t.Errorf("SC filter rows = %d, want 1", got)
	}
}
