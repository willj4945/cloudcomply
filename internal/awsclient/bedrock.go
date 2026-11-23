package awsclient

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrock"
	bedrocktypes "github.com/aws/aws-sdk-go-v2/service/bedrock/types"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	cwtypes "github.com/aws/aws-sdk-go-v2/service/cloudwatch/types"

	"github.com/willj4945/cloudcomply/internal/nist"
)

const (
	checkBedrockLogging     = "AI-AU-12-01"
	checkBedrockTextLogging = "AI-AU-12-02"
	usageLookback           = 90 * 24 * time.Hour
)

type bedrockAPI interface {
	GetModelInvocationLoggingConfiguration(context.Context, *bedrock.GetModelInvocationLoggingConfigurationInput, ...func(*bedrock.Options)) (*bedrock.GetModelInvocationLoggingConfigurationOutput, error)
	ListFoundationModels(context.Context, *bedrock.ListFoundationModelsInput, ...func(*bedrock.Options)) (*bedrock.ListFoundationModelsOutput, error)
	GetFoundationModelAvailability(context.Context, *bedrock.GetFoundationModelAvailabilityInput, ...func(*bedrock.Options)) (*bedrock.GetFoundationModelAvailabilityOutput, error)
}

type metricsAPI interface {
	GetMetricData(context.Context, *cloudwatch.GetMetricDataInput, ...func(*cloudwatch.Options)) (*cloudwatch.GetMetricDataOutput, error)
}

// bedrockLoggingCollector implements AI-AU-12-01 (invocation logging has a
// destination) and AI-AU-12-02 (text prompts/responses are delivered).
//
// Per decision D4 in docs/ai-controls/plan.md, a region where Bedrock is
// usable but has no invocation logging FAILS whether or not it has been used:
// a service that isn't disabled can be used without authorization, unlogged.
// Usage only sets severity. It is NOT_APPLICABLE only where Bedrock is
// demonstrably unavailable: Bedrock calls denied by an SCP, no Bedrock
// endpoint in the region, or (GovCloud) no foundation model access enabled.
type bedrockLoggingCollector struct {
	bedrock func(aws.Config) bedrockAPI
	metrics func(aws.Config) metricsAPI
	now     func() time.Time
}

func newBedrockLoggingCollector() bedrockLoggingCollector {
	return bedrockLoggingCollector{
		bedrock: func(cfg aws.Config) bedrockAPI { return bedrock.NewFromConfig(cfg) },
		metrics: func(cfg aws.Config) metricsAPI { return cloudwatch.NewFromConfig(cfg) },
		now:     time.Now,
	}
}

func (bedrockLoggingCollector) CheckIDs() []string {
	return []string{checkBedrockLogging, checkBedrockTextLogging}
}

func (c bedrockLoggingCollector) Collect(ctx context.Context, t Target) []nist.CheckResult {
	ids := c.CheckIDs()
	br := c.bedrock(t.Config)

	out, err := br.GetModelInvocationLoggingConfiguration(ctx, &bedrock.GetModelInvocationLoggingConfigurationInput{})
	if err != nil {
		if deniedBySCP(err) {
			return ResultsForStatus(ids, t, nist.StatusNotApplicable,
				"Bedrock is disabled in this account: its API calls are denied by a service control policy")
		}
		return ResultsForError(ids, t, err)
	}

	if cfg := out.LoggingConfig; hasLogDestination(cfg) {
		text := newResult(checkBedrockTextLogging, t, nist.StatusPassed, nist.SeverityMedium, "")
		if !aws.ToBool(cfg.TextDataDeliveryEnabled) {
			text.Status = nist.StatusFailed
			text.Detail = "invocation logging is on but text data delivery is off: prompts and responses are not recorded"
		}
		return []nist.CheckResult{
			newResult(checkBedrockLogging, t, nist.StatusPassed, nist.SeverityHigh, "invocation logs delivered to "+logDestinations(cfg)),
			text,
		}
	}

	if isGovCloud(t.Region) {
		enabled, err := anyModelAccessEnabled(ctx, br)
		if err != nil {
			return ResultsForError(ids, t, err)
		}
		if !enabled {
			return ResultsForStatus(ids, t, nist.StatusNotApplicable,
				"no foundation model access is enabled in this GovCloud region, so Bedrock can't be invoked")
		}
	}

	sev, detail := c.usageSeverity(ctx, t)
	return []nist.CheckResult{
		newResult(checkBedrockLogging, t, nist.StatusFailed, sev, "Bedrock is usable here but model invocation logging is not configured; "+detail),
		newResult(checkBedrockTextLogging, t, nist.StatusFailed, sev, "no invocation logging, so prompts and responses are not recorded; "+detail),
	}
}

// usageSeverity separates active, unlogged use (HIGH) from a usable but idle
// service (MEDIUM). Both fail; this only tells an assessor which to fix first.
// If usage can't be determined the result stays FAILED at HIGH, since the
// missing logging is already established.
func (c bedrockLoggingCollector) usageSeverity(ctx context.Context, t Target) (nist.Severity, string) {
	n, err := bedrockInvocations(ctx, c.metrics(t.Config), c.now())
	switch {
	case err != nil:
		_, why := ClassifyError(err)
		return nist.SeverityHigh, "usage in the last 90 days could not be determined (" + why + ")"
	case n > 0:
		return nist.SeverityHigh, fmt.Sprintf("%.0f model invocations in the last 90 days went unlogged", n)
	default:
		return nist.SeverityMedium, "no invocations in the last 90 days, but nothing prevents unlogged use"
	}
}

func hasLogDestination(cfg *bedrocktypes.LoggingConfig) bool {
	if cfg == nil {
		return false
	}
	cw := cfg.CloudWatchConfig != nil && aws.ToString(cfg.CloudWatchConfig.LogGroupName) != ""
	s3 := cfg.S3Config != nil && aws.ToString(cfg.S3Config.BucketName) != ""
	return cw || s3
}

func logDestinations(cfg *bedrocktypes.LoggingConfig) string {
	var d []string
	if cfg.CloudWatchConfig != nil && aws.ToString(cfg.CloudWatchConfig.LogGroupName) != "" {
		d = append(d, "CloudWatch Logs")
	}
	if cfg.S3Config != nil && aws.ToString(cfg.S3Config.BucketName) != "" {
		d = append(d, "S3")
	}
	return strings.Join(d, " and ")
}

func isGovCloud(region string) bool {
	return strings.HasPrefix(region, "us-gov-")
}

// anyModelAccessEnabled reports whether any foundation model is entitled for
// the account. Only meaningful in GovCloud, where model access is granted
// manually; in commercial regions access is enabled on first use, so an
// unentitled model there is still usable. Entitlement, not
// authorizationStatus, is used because authorization describes the caller,
// and the read-only assessor role is never authorized to invoke.
func anyModelAccessEnabled(ctx context.Context, api bedrockAPI) (bool, error) {
	models, err := api.ListFoundationModels(ctx, &bedrock.ListFoundationModelsInput{})
	if err != nil {
		return false, err
	}
	for _, m := range models.ModelSummaries {
		av, err := api.GetFoundationModelAvailability(ctx, &bedrock.GetFoundationModelAvailabilityInput{ModelId: m.ModelId})
		if err != nil {
			return false, err
		}
		if av.EntitlementAvailability == bedrocktypes.EntitlementAvailabilityAvailable {
			return true, nil
		}
	}
	return false, nil
}

// bedrockInvocations sums inference requests over the lookback window across
// both inference endpoints, which publish to different namespaces:
// bedrock-runtime (InvokeModel/Converse) as AWS/Bedrock Invocations, and
// bedrock-mantle (OpenAI/Anthropic-compatible APIs) as AWS/BedrockMantle
// Inferences. Reading only one would call a mantle-only account idle.
// Metrics are queried without dimensions, which AWS documents as the way to
// count all requests.
func bedrockInvocations(ctx context.Context, api metricsAPI, now time.Time) (float64, error) {
	query := func(id, namespace, metric string) cwtypes.MetricDataQuery {
		return cwtypes.MetricDataQuery{
			Id: aws.String(id),
			MetricStat: &cwtypes.MetricStat{
				Metric: &cwtypes.Metric{Namespace: aws.String(namespace), MetricName: aws.String(metric)},
				Period: aws.Int32(86400),
				Stat:   aws.String("Sum"),
			},
		}
	}
	in := &cloudwatch.GetMetricDataInput{
		StartTime: aws.Time(now.Add(-usageLookback)),
		EndTime:   aws.Time(now),
		MetricDataQueries: []cwtypes.MetricDataQuery{
			query("runtime", "AWS/Bedrock", "Invocations"),
			query("mantle", "AWS/BedrockMantle", "Inferences"),
		},
	}
	var total float64
	p := cloudwatch.NewGetMetricDataPaginator(api, in)
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return 0, err
		}
		for _, r := range page.MetricDataResults {
			for _, v := range r.Values {
				total += v
			}
		}
	}
	return total, nil
}

// NativeCollectors returns every native check collector, in report order.
func NativeCollectors() []Collector {
	return []Collector{newBedrockLoggingCollector()}
}
