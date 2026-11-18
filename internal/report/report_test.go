package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/willj4945/cloudcomply/internal/nist"
)

func TestRenderNIST_JSONFieldContract(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderNIST(&buf, nist.DemoFindings()[:1], "json"); err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	want := []string{"control_id", "title", "family", "status", "severity", "accounts_affected", "rmf_step", "min_impact_level"}
	if len(rows) != 1 || len(rows[0]) != len(want) {
		t.Fatalf("got %v, want one row with exactly %d fields", rows, len(want))
	}
	for _, k := range want {
		if _, ok := rows[0][k]; !ok {
			t.Errorf("missing JSON field %q", k)
		}
	}
}

func TestRenderNIST_TableHeader(t *testing.T) {
	var buf bytes.Buffer
	if err := RenderNIST(&buf, nil, ""); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(buf.String(), "CONTROL") {
		t.Errorf("table output should start with header, got %q", buf.String())
	}
}

func TestValidateFormat(t *testing.T) {
	for _, f := range []string{"", "table", "json"} {
		if err := ValidateFormat(f); err != nil {
			t.Errorf("ValidateFormat(%q) = %v, want nil", f, err)
		}
	}
	if err := ValidateFormat("xml"); err == nil {
		t.Error("ValidateFormat(\"xml\") = nil, want error")
	}
}
