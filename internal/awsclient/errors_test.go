package awsclient

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/aws/smithy-go"

	"github.com/willj4945/cloudcomply/internal/crosswalk"
	"github.com/willj4945/cloudcomply/internal/nist"
)

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		want       nist.FindingStatus
		wantDetail string
	}{
		{"access denied names the action", apiError("Bedrock", "GetModelInvocationLoggingConfiguration", "AccessDeniedException"),
			nist.StatusError, "access denied: Bedrock:GetModelInvocationLoggingConfiguration (AccessDeniedException)"},
		{"EC2-style unauthorized", apiError("EC2", "DescribeVpcEndpoints", "UnauthorizedOperation"),
			nist.StatusError, "access denied: EC2:DescribeVpcEndpoints"},
		{"service absent from region", &smithy.OperationError{ServiceID: "Bedrock", OperationName: "ListGuardrails",
			Err: &net.DNSError{Err: "no such host", Name: "bedrock.ap-east-2.amazonaws.com", IsNotFound: true}},
			nist.StatusNotApplicable, "Bedrock:ListGuardrails: service not available"},
		{"transient DNS failure is not N/A", &smithy.OperationError{ServiceID: "Bedrock", OperationName: "ListGuardrails",
			Err: &net.DNSError{Err: "timeout", IsTimeout: true}},
			nist.StatusError, "Bedrock:ListGuardrails failed"},
		{"other API error", apiError("SageMaker", "ListEndpoints", "ThrottlingException"),
			nist.StatusError, "SageMaker:ListEndpoints failed"},
		{"timeout", context.DeadlineExceeded, nist.StatusError, "AWS call failed: context deadline exceeded"},
		{"unwrapped", errors.New("boom"), nist.StatusError, "AWS call failed: boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, detail := ClassifyError(tt.err)
			if got != tt.want || !strings.Contains(detail, tt.wantDetail) {
				t.Errorf("ClassifyError = %v, %q; want %v, containing %q", got, detail, tt.want, tt.wantDetail)
			}
		})
	}
}

func TestResultsForError_FillsFromCrosswalk(t *testing.T) {
	withMappings(t, "AI-T-01", "AI-T-02")
	tgt := Target{Account: "222222222222", Region: "us-gov-west-1"}

	got := ResultsForError([]string{"AI-T-01", "AI-T-02"}, tgt, apiError("Bedrock", "X", "AccessDeniedException"))
	if len(got) != 2 {
		t.Fatalf("got %d results, want 2", len(got))
	}
	for _, r := range got {
		if r.Status != nist.StatusError || r.Account != tgt.Account || r.Region != tgt.Region || r.Title != r.CheckID {
			t.Errorf("result = %+v", r)
		}
		if len(r.Controls) != 1 || r.Controls[0] != "AU-12" || r.MinImpactLevel != nist.IL4 {
			t.Errorf("crosswalk fields = %v / %v, want [AU-12] / IL4", r.Controls, r.MinImpactLevel)
		}
	}
	// Must roll up into a visible control row, not vanish.
	if rows := nist.RollUp(got); len(rows) != 1 || rows[0].Status != nist.StatusError {
		t.Errorf("RollUp = %+v, want one ERROR row", rows)
	}
}

// withMappings points lookupMapping at fake crosswalk entries for the test.
func withMappings(t *testing.T, ids ...string) {
	t.Helper()
	known := map[string]bool{}
	for _, id := range ids {
		known[id] = true
	}
	orig := lookupMapping
	lookupMapping = func(id string) (crosswalk.Mapping, bool) {
		if !known[id] {
			return crosswalk.Mapping{}, false
		}
		return crosswalk.Mapping{NIST80053: []string{"AU-12"}, MinImpactLevel: nist.IL4, Source: crosswalk.SourceInterpretation}, true
	}
	t.Cleanup(func() { lookupMapping = orig })
}
