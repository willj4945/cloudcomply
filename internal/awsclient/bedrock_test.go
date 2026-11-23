package awsclient

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/smithy-go"

	"github.com/willj4945/cloudcomply/internal/crosswalk"
	"github.com/willj4945/cloudcomply/internal/nist"
)

type fakeBedrock struct {
	logging      string // fixture path
	loggingErr   error
	models       string
	modelsErr    error
	availability map[string]string // model ID -> fixture
	modelCalls   int
}

func (f *fakeBedrock) GetModelInvocationLoggingConfiguration(context.Context, *bedrock.GetModelInvocationLoggingConfigurationInput, ...func(*bedrock.Options)) (*bedrock.GetModelInvocationLoggingConfigurationOutput, error) {
	if f.loggingErr != nil {
		return nil, f.loggingErr
	}
	var out bedrock.GetModelInvocationLoggingConfigurationOutput
	loadFixture(f.logging, &out)
	return &out, nil
}

func (f *fakeBedrock) ListFoundationModels(context.Context, *bedrock.ListFoundationModelsInput, ...func(*bedrock.Options)) (*bedrock.ListFoundationModelsOutput, error) {
	f.modelCalls++
	if f.modelsErr != nil {
		return nil, f.modelsErr
	}
	var out bedrock.ListFoundationModelsOutput
	loadFixture(f.models, &out)
	return &out, nil
}

func (f *fakeBedrock) GetFoundationModelAvailability(_ context.Context, in *bedrock.GetFoundationModelAvailabilityInput, _ ...func(*bedrock.Options)) (*bedrock.GetFoundationModelAvailabilityOutput, error) {
	var out bedrock.GetFoundationModelAvailabilityOutput
	loadFixture(f.availability[aws.ToString(in.ModelId)], &out)
	return &out, nil
}

type fakeMetrics struct {
	fixture string
	err     error
	in      *cloudwatch.GetMetricDataInput
}

func (f *fakeMetrics) GetMetricData(_ context.Context, in *cloudwatch.GetMetricDataInput, _ ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error) {
	f.in = in
	if f.err != nil {
		return nil, f.err
	}
	var out cloudwatch.GetMetricDataOutput
	loadFixture(f.fixture, &out)
	return &out, nil
}

var fixedNow = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

func collectBedrock(t *testing.T, br *fakeBedrock, m *fakeMetrics, region string) map[string]nist.CheckResult {
	t.Helper()
	c := bedrockLoggingCollector{
		bedrock: func(aws.Config) bedrockAPI { return br },
		metrics: func(aws.Config) metricsAPI { return m },
		now:     func() time.Time { return fixedNow },
	}
	tgt := Target{Account: "222222222222", Region: region}
	got := map[string]nist.CheckResult{}
	for _, r := range c.Collect(context.Background(), tgt) {
		if r.Account != tgt.Account || r.Region != tgt.Region {
			t.Errorf("result scope = %s/%s, want %s/%s", r.Account, r.Region, tgt.Account, tgt.Region)
		}
		got[r.CheckID] = r
	}
	if len(got) != 2 {
		t.Fatalf("got %d results, want one each for %s and %s", len(got), checkBedrockLogging, checkBedrockTextLogging)
	}
	return got
}

type want struct {
	status nist.FindingStatus
	sev    nist.Severity // "" = don't check
	detail string        // substring; "" = don't check
}

func check(t *testing.T, r nist.CheckResult, w want) {
	t.Helper()
	if r.Status != w.status || (w.sev != "" && r.Severity != w.sev) || !strings.Contains(r.Detail, w.detail) {
		t.Errorf("%s = %s/%s %q; want %s/%s containing %q", r.CheckID, r.Status, r.Severity, r.Detail, w.status, w.sev, w.detail)
	}
}

func TestBedrockLogging_Configured(t *testing.T) {
	got := collectBedrock(t, &fakeBedrock{logging: "bedrock/GetModelInvocationLoggingConfiguration-cloudwatch-text.json"}, &fakeMetrics{}, "us-east-1")
	check(t, got[checkBedrockLogging], want{nist.StatusPassed, "", "CloudWatch Logs"})
	check(t, got[checkBedrockTextLogging], want{nist.StatusPassed, "", ""})
}

func TestBedrockLogging_TextDeliveryOff(t *testing.T) {
	got := collectBedrock(t, &fakeBedrock{logging: "bedrock/GetModelInvocationLoggingConfiguration-s3-no-text.json"}, &fakeMetrics{}, "us-east-1")
	check(t, got[checkBedrockLogging], want{nist.StatusPassed, "", "S3"})
	check(t, got[checkBedrockTextLogging], want{nist.StatusFailed, nist.SeverityMedium, "text data delivery is off"})
}

func TestBedrockLogging_UnconfiguredFailsWhetherOrNotUsed(t *testing.T) {
	tests := []struct {
		name    string
		logging string
		metrics *fakeMetrics
		want    want
	}{
		{"used via bedrock-runtime", "unset", &fakeMetrics{fixture: "cloudwatch/GetMetricData-runtime-used.json"},
			want{nist.StatusFailed, nist.SeverityHigh, "42 model invocations in the last 90 days went unlogged"}},
		{"used via bedrock-mantle only", "unset", &fakeMetrics{fixture: "cloudwatch/GetMetricData-mantle-only.json"},
			want{nist.StatusFailed, nist.SeverityHigh, "5 model invocations"}},
		{"unused but usable (D4)", "unset", &fakeMetrics{fixture: "cloudwatch/GetMetricData-unused.json"},
			want{nist.StatusFailed, nist.SeverityMedium, "no invocations in the last 90 days"}},
		{"config with no destination counts as unset", "no-destination", &fakeMetrics{fixture: "cloudwatch/GetMetricData-unused.json"},
			want{nist.StatusFailed, nist.SeverityMedium, "not configured"}},
		{"usage unknown stays FAILED at HIGH", "unset", &fakeMetrics{err: apiError("CloudWatch", "GetMetricData", "AccessDenied")},
			want{nist.StatusFailed, nist.SeverityHigh, "could not be determined (access denied: CloudWatch:GetMetricData"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			br := &fakeBedrock{logging: "bedrock/GetModelInvocationLoggingConfiguration-" + tt.logging + ".json"}
			got := collectBedrock(t, br, tt.metrics, "us-east-1")
			check(t, got[checkBedrockLogging], tt.want)
			check(t, got[checkBedrockTextLogging], want{tt.want.status, tt.want.sev, ""})
			if br.modelCalls != 0 {
				t.Errorf("model access checked in a commercial region; it's only meaningful in GovCloud")
			}
		})
	}
}

func TestBedrockLogging_UsageQueryCoversBothEndpointsOver90Days(t *testing.T) {
	m := &fakeMetrics{fixture: "cloudwatch/GetMetricData-unused.json"}
	collectBedrock(t, &fakeBedrock{logging: "bedrock/GetModelInvocationLoggingConfiguration-unset.json"}, m, "us-east-1")
	if m.in == nil {
		t.Fatal("GetMetricData not called")
	}
	if got := fixedNow.Sub(aws.ToTime(m.in.StartTime)); got != 90*24*time.Hour {
		t.Errorf("lookback = %v, want 90 days", got)
	}
	seen := map[string]bool{}
	for _, q := range m.in.MetricDataQueries {
		metric := q.MetricStat.Metric
		seen[aws.ToString(metric.Namespace)+"/"+aws.ToString(metric.MetricName)] = true
		if len(metric.Dimensions) != 0 {
			t.Errorf("%s queried with dimensions; AWS counts all requests only without them", aws.ToString(metric.MetricName))
		}
	}
	if !seen["AWS/Bedrock/Invocations"] || !seen["AWS/BedrockMantle/Inferences"] {
		t.Errorf("queried %v, want both AWS/Bedrock/Invocations and AWS/BedrockMantle/Inferences", seen)
	}
}

func TestBedrockLogging_NotApplicable(t *testing.T) {
	scp := apiErrorMessage("Bedrock", "GetModelInvocationLoggingConfiguration", "AccessDeniedException",
		"User: arn:aws:sts::222222222222:assumed-role/cloudcomply-assessor/cloudcomply is not authorized to perform: bedrock:GetModelInvocationLoggingConfiguration with an explicit deny in a service control policy")
	noEndpoint := &smithy.OperationError{ServiceID: "Bedrock", OperationName: "GetModelInvocationLoggingConfiguration",
		Err: &net.DNSError{Err: "no such host", Name: "bedrock.ap-east-2.amazonaws.com", IsNotFound: true}}

	tests := []struct {
		name   string
		br     *fakeBedrock
		region string
		detail string
	}{
		{"Bedrock disabled by SCP", &fakeBedrock{loggingErr: scp}, "us-east-1", "denied by a service control policy"},
		{"Bedrock not offered in region", &fakeBedrock{loggingErr: noEndpoint}, "ap-east-2", "not available in this region"},
		{"GovCloud with no model access enabled", &fakeBedrock{
			logging:      "bedrock/GetModelInvocationLoggingConfiguration-unset.json",
			models:       "bedrock/ListFoundationModels-govcloud.json",
			availability: map[string]string{"amazon.titan-text-express-v1": "bedrock/GetFoundationModelAvailability-not-entitled.json", "anthropic.claude-3-haiku-20240307-v1:0": "bedrock/GetFoundationModelAvailability-not-entitled.json"},
		}, "us-gov-west-1", "no foundation model access is enabled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := collectBedrock(t, tt.br, &fakeMetrics{}, tt.region)
			check(t, got[checkBedrockLogging], want{nist.StatusNotApplicable, "", tt.detail})
			check(t, got[checkBedrockTextLogging], want{nist.StatusNotApplicable, "", tt.detail})
		})
	}
}

func TestBedrockLogging_GovCloudWithModelAccessFails(t *testing.T) {
	br := &fakeBedrock{
		logging:      "bedrock/GetModelInvocationLoggingConfiguration-unset.json",
		models:       "bedrock/ListFoundationModels-govcloud.json",
		availability: map[string]string{"amazon.titan-text-express-v1": "bedrock/GetFoundationModelAvailability-not-entitled.json", "anthropic.claude-3-haiku-20240307-v1:0": "bedrock/GetFoundationModelAvailability-entitled.json"},
	}
	got := collectBedrock(t, br, &fakeMetrics{fixture: "cloudwatch/GetMetricData-unused.json"}, "us-gov-west-1")
	check(t, got[checkBedrockLogging], want{nist.StatusFailed, nist.SeverityMedium, "not configured"})
}

func TestBedrockLogging_Errors(t *testing.T) {
	plainDenied := apiErrorMessage("Bedrock", "GetModelInvocationLoggingConfiguration", "AccessDeniedException",
		"User: arn:aws:sts::222222222222:assumed-role/cloudcomply-assessor/cloudcomply is not authorized to perform: bedrock:GetModelInvocationLoggingConfiguration because no identity-based policy allows the bedrock:GetModelInvocationLoggingConfiguration action")
	tests := []struct {
		name   string
		br     *fakeBedrock
		region string
		detail string
	}{
		{"assessor role missing the permission", &fakeBedrock{loggingErr: plainDenied}, "us-east-1",
			"access denied: Bedrock:GetModelInvocationLoggingConfiguration"},
		{"GovCloud model access can't be read", &fakeBedrock{
			logging:   "bedrock/GetModelInvocationLoggingConfiguration-unset.json",
			modelsErr: apiError("Bedrock", "ListFoundationModels", "AccessDeniedException"),
		}, "us-gov-west-1", "access denied: Bedrock:ListFoundationModels"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := collectBedrock(t, tt.br, &fakeMetrics{}, tt.region)
			check(t, got[checkBedrockLogging], want{nist.StatusError, "", tt.detail})
			check(t, got[checkBedrockTextLogging], want{nist.StatusError, "", tt.detail})
		})
	}
}

func TestBedrockLogging_RollsUpUnderMappedControls(t *testing.T) {
	got := collectBedrock(t, &fakeBedrock{logging: "bedrock/GetModelInvocationLoggingConfiguration-s3-no-text.json"}, &fakeMetrics{}, "us-east-1")
	if r := got[checkBedrockLogging]; r.Title != "Bedrock model invocation logging enabled" || strings.Join(r.Controls, ",") != "AU-12,AU-2" {
		t.Errorf("AI-AU-12-01 title/controls = %q / %v", r.Title, r.Controls)
	}
	rows := map[string]nist.FindingStatus{}
	for _, f := range nist.RollUp([]nist.CheckResult{got[checkBedrockLogging], got[checkBedrockTextLogging]}) {
		rows[f.ControlID] = f.Status
	}
	// AU-12 fails because text delivery is off; AU-2 only carries the
	// logging-enabled check, which passes; AU-3 carries the text check.
	if rows["AU-12"] != nist.StatusFailed || rows["AU-2"] != nist.StatusPassed || rows["AU-3"] != nist.StatusFailed {
		t.Errorf("rolled-up rows = %v", rows)
	}
}

func TestNativeCollectors_AllChecksMappedAndValid(t *testing.T) {
	// scan() refuses checks with no crosswalk entry; prove the real table
	// covers every native check so --native-checks can't fail at start-up.
	for _, col := range NativeCollectors() {
		for _, id := range col.CheckIDs() {
			m, ok := crosswalk.Lookup(id)
			if !ok {
				t.Errorf("%s has no crosswalk mapping", id)
				continue
			}
			if err := m.Validate(); err != nil {
				t.Errorf("%s mapping invalid: %v", id, err)
			}
		}
	}
}
