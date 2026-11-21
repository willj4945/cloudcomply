package awsclient

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/account"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/smithy-go"

	"github.com/willj4945/cloudcomply/internal/nist"
)

const homeARN = "arn:aws-us-gov:sts::111111111111:assumed-role/SecurityAudit/operator"

type fakeCollector struct {
	ids     []string
	collect func(ctx context.Context, t Target) []nist.CheckResult
}

func (f fakeCollector) CheckIDs() []string { return f.ids }
func (f fakeCollector) Collect(ctx context.Context, t Target) []nist.CheckResult {
	return f.collect(ctx, t)
}

// passing reports one PASSED result per check for every target it sees.
func passing(ids ...string) fakeCollector {
	return fakeCollector{ids: ids, collect: func(_ context.Context, t Target) []nist.CheckResult {
		return ResultsForStatus(ids, t, nist.StatusPassed, "")
	}}
}

type fakeAWS struct {
	mu          sync.Mutex
	accounts    []string
	accountsErr error
	assumeErr   map[string]error // by account ID
	regionsErr  map[string]error // by account ID
	assumed     []string
	regionCalls int
}

func (f *fakeAWS) deps() scanDeps {
	return scanDeps{
		base:      aws.Config{Region: "us-gov-west-1"},
		callerARN: func(context.Context) (string, error) { return homeARN, nil },
		listAccounts: func(context.Context) ([]string, error) {
			return f.accounts, f.accountsErr
		},
		assume: func(_ context.Context, roleARN string) (aws.Config, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.assumed = append(f.assumed, roleARN)
			acct := strings.Split(roleARN, ":")[4]
			if err := f.assumeErr[acct]; err != nil {
				return aws.Config{}, err
			}
			return aws.Config{AppID: acct}, nil
		},
		listRegions: func(_ context.Context, cfg aws.Config) ([]string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.regionCalls++
			acct := cfg.AppID
			if acct == "" {
				acct = "111111111111"
			}
			if err := f.regionsErr[acct]; err != nil {
				return nil, err
			}
			return []string{"us-gov-east-1", "us-gov-west-1"}, nil
		},
	}
}

func targetsSeen(results []nist.CheckResult) []string {
	var out []string
	for _, r := range results {
		out = append(out, r.Account+"/"+r.Region+"/"+string(r.Status))
	}
	return out
}

func TestScan_FansOutAcrossAccountsAndRegions(t *testing.T) {
	withMappings(t, "AI-T-01")
	f := &fakeAWS{accounts: []string{"111111111111", "222222222222"}}

	got, err := scan(context.Background(), f.deps(), []Collector{passing("AI-T-01")}, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"111111111111/us-gov-east-1/PASSED", "111111111111/us-gov-west-1/PASSED",
		"222222222222/us-gov-east-1/PASSED", "222222222222/us-gov-west-1/PASSED",
	}
	if fmt.Sprint(targetsSeen(got)) != fmt.Sprint(want) {
		t.Errorf("results = %v, want %v", targetsSeen(got), want)
	}
	// Caller's own account uses its own credentials; others assume the role,
	// in the caller's partition.
	if len(f.assumed) != 1 || f.assumed[0] != "arn:aws-us-gov:iam::222222222222:role/cloudcomply-assessor" {
		t.Errorf("assumed = %v", f.assumed)
	}
	for _, r := range got {
		if r.Account == "222222222222" && r.Region == "" {
			t.Errorf("target region not set: %+v", r)
		}
	}
}

func TestScan_TargetConfigCarriesAccountCredentialsAndRegion(t *testing.T) {
	withMappings(t, "AI-T-01")
	f := &fakeAWS{accounts: []string{"111111111111", "222222222222"}}
	var mu sync.Mutex
	seen := map[string]string{}
	col := fakeCollector{ids: []string{"AI-T-01"}, collect: func(_ context.Context, tg Target) []nist.CheckResult {
		mu.Lock()
		seen[tg.Account+"/"+tg.Region] = tg.Config.AppID + "@" + tg.Config.Region
		mu.Unlock()
		return nil
	}}
	if _, err := scan(context.Background(), f.deps(), []Collector{col}, ScanOptions{Regions: []string{"us-gov-west-1"}}); err != nil {
		t.Fatal(err)
	}
	if seen["222222222222/us-gov-west-1"] != "222222222222@us-gov-west-1" {
		t.Errorf("member target config = %q, want assumed creds in target region", seen["222222222222/us-gov-west-1"])
	}
	if seen["111111111111/us-gov-west-1"] != "@us-gov-west-1" {
		t.Errorf("home target config = %q, want base creds in target region", seen["111111111111/us-gov-west-1"])
	}
}

func TestScan_UnreachableAccountIsErrorNotAbort(t *testing.T) {
	withMappings(t, "AI-T-01", "AI-T-02")
	f := &fakeAWS{
		accounts:  []string{"111111111111", "222222222222", "333333333333"},
		assumeErr: map[string]error{"333333333333": apiError("STS", "AssumeRole", "AccessDenied")},
	}

	got, err := scan(context.Background(), f.deps(), []Collector{passing("AI-T-01", "AI-T-02")}, ScanOptions{RoleName: "custom-auditor"})
	if err != nil {
		t.Fatalf("scan aborted: %v", err)
	}
	var errs, passes int
	for _, r := range got {
		switch {
		case r.Account == "333333333333":
			errs++
			if r.Status != nist.StatusError || !strings.Contains(r.Detail, "arn:aws-us-gov:iam::333333333333:role/custom-auditor") {
				t.Errorf("unreachable account result = %+v", r)
			}
		case r.Status == nist.StatusPassed:
			passes++
		}
	}
	if errs != 2 {
		t.Errorf("got %d ERROR results for the unreachable account, want 2 (one per check)", errs)
	}
	if passes != 8 {
		t.Errorf("got %d PASSED results from reachable accounts, want 8 (2 accounts × 2 regions × 2 checks)", passes)
	}
}

func TestScan_RegionDiscoveryFailureIsErrorWithHint(t *testing.T) {
	withMappings(t, "AI-T-01")
	f := &fakeAWS{
		accounts:   []string{"111111111111", "222222222222"},
		regionsErr: map[string]error{"222222222222": apiError("Account", "ListRegions", "AccessDeniedException")},
	}
	got, err := scan(context.Background(), f.deps(), []Collector{passing("AI-T-01")}, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range got {
		if r.Account == "222222222222" && (r.Status != nist.StatusError || !strings.Contains(r.Detail, "--regions")) {
			t.Errorf("region discovery failure = %+v, want ERROR mentioning --regions", r)
		}
	}
}

func TestScan_RegionsOverrideSkipsDiscovery(t *testing.T) {
	withMappings(t, "AI-T-01")
	f := &fakeAWS{accounts: []string{"111111111111", "222222222222"}}
	got, err := scan(context.Background(), f.deps(), []Collector{passing("AI-T-01")}, ScanOptions{Regions: []string{"us-gov-west-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if f.regionCalls != 0 {
		t.Errorf("listRegions called %d times, want 0 with --regions", f.regionCalls)
	}
	if len(got) != 2 {
		t.Errorf("got %d results, want 2 (2 accounts × 1 region)", len(got))
	}
}

func TestScan_SingleAccountMode(t *testing.T) {
	withMappings(t, "AI-T-01")
	f := &fakeAWS{} // listAccounts returns nil: not in an organization
	got, err := scan(context.Background(), f.deps(), []Collector{passing("AI-T-01")}, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.assumed) != 0 {
		t.Errorf("assumed %v in single-account mode, want none", f.assumed)
	}
	if len(got) != 2 || got[0].Account != "111111111111" {
		t.Errorf("results = %v", targetsSeen(got))
	}
}

func TestScan_GlobalFailuresReturnError(t *testing.T) {
	withMappings(t, "AI-T-01")

	f := &fakeAWS{accountsErr: apiError("Organizations", "ListAccounts", "AccessDeniedException")}
	if _, err := scan(context.Background(), f.deps(), []Collector{passing("AI-T-01")}, ScanOptions{}); err == nil || !strings.Contains(err.Error(), "list accounts") {
		t.Errorf("ListAccounts denied: err = %v", err)
	}

	d := (&fakeAWS{}).deps()
	d.callerARN = func(context.Context) (string, error) { return "", errors.New("no credentials") }
	if _, err := scan(context.Background(), d, nil, ScanOptions{}); err == nil || !strings.Contains(err.Error(), "caller identity") {
		t.Errorf("no identity: err = %v", err)
	}

	if _, err := scan(context.Background(), (&fakeAWS{}).deps(), []Collector{passing("UNMAPPED-1")}, ScanOptions{}); err == nil || !strings.Contains(err.Error(), "no crosswalk mapping") {
		t.Errorf("unmapped check: err = %v", err)
	}
}

func TestScan_BoundsConcurrency(t *testing.T) {
	withMappings(t, "AI-T-01")
	accts := make([]string, 10)
	for i := range accts {
		accts[i] = fmt.Sprintf("%012d", 200000000000+i)
	}
	f := &fakeAWS{accounts: accts}
	var inFlight, peak int32
	col := fakeCollector{ids: []string{"AI-T-01"}, collect: func(context.Context, Target) []nist.CheckResult {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		return nil
	}}
	if _, err := scan(context.Background(), f.deps(), []Collector{col}, ScanOptions{Concurrency: 3}); err != nil {
		t.Fatal(err)
	}
	if peak > 3 {
		t.Errorf("peak concurrency = %d, want ≤ 3", peak)
	}
}

func TestScan_EachCollectCallIsTimeBounded(t *testing.T) {
	withMappings(t, "AI-T-01")
	f := &fakeAWS{}
	col := fakeCollector{ids: []string{"AI-T-01"}, collect: func(ctx context.Context, tg Target) []nist.CheckResult {
		<-ctx.Done()
		return ResultsForError([]string{"AI-T-01"}, tg, ctx.Err())
	}}
	start := time.Now()
	got, err := scan(context.Background(), f.deps(), []Collector{col}, ScanOptions{CallTimeout: 20 * time.Millisecond, Regions: []string{"us-gov-west-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("scan took %v; per-call timeout not applied", time.Since(start))
	}
	if len(got) != 1 || got[0].Status != nist.StatusError || !strings.Contains(got[0].Detail, "deadline exceeded") {
		t.Errorf("results = %+v, want one ERROR for the timed-out call", got)
	}
}

func TestParseRegions(t *testing.T) {
	tests := []struct {
		in      string
		want    []string
		wantErr bool
	}{
		{"", nil, false},
		{"us-east-1", []string{"us-east-1"}, false},
		{"us-east-1, us-gov-west-1,us-east-1", []string{"us-east-1", "us-gov-west-1"}, false},
		{"us-east-1,,", []string{"us-east-1"}, false},
		{"US-EAST-1", nil, true},
		{"us-east-1,narnia", nil, true},
	}
	for _, tt := range tests {
		got, err := ParseRegions(tt.in)
		if (err != nil) != tt.wantErr || fmt.Sprint(got) != fmt.Sprint(tt.want) {
			t.Errorf("ParseRegions(%q) = %v, %v; want %v, err=%v", tt.in, got, err, tt.want, tt.wantErr)
		}
	}
}

func TestParseCallerARN(t *testing.T) {
	p, a, err := parseCallerARN(homeARN)
	if err != nil || p != "aws-us-gov" || a != "111111111111" {
		t.Errorf("parseCallerARN = %q, %q, %v", p, a, err)
	}
	if _, _, err := parseCallerARN("not-an-arn"); err == nil {
		t.Error("parseCallerARN(not-an-arn) succeeded")
	}
}

type fakeListAccounts struct{ pages []string }

func (f *fakeListAccounts) ListAccounts(_ context.Context, in *organizations.ListAccountsInput, _ ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error) {
	page := 0
	if in.NextToken != nil {
		page = 1
	}
	var out organizations.ListAccountsOutput
	loadFixture(f.pages[page], &out)
	return &out, nil
}

func TestListActiveAccounts_FromFixtures(t *testing.T) {
	api := &fakeListAccounts{pages: []string{"organizations/ListAccounts-page1.json", "organizations/ListAccounts-page2.json"}}
	got, err := listActiveAccounts(context.Background(), api)
	if err != nil {
		t.Fatal(err)
	}
	// Suspended and pending accounts skipped; legacy Status-only record kept.
	want := []string{"111111111111", "222222222222", "444444444444"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("listActiveAccounts = %v, want %v", got, want)
	}
}

type notInOrg struct{}

func (notInOrg) ListAccounts(context.Context, *organizations.ListAccountsInput, ...func(*organizations.Options)) (*organizations.ListAccountsOutput, error) {
	return nil, &smithy.OperationError{ServiceID: "Organizations", OperationName: "ListAccounts", Err: &orgtypes.AWSOrganizationsNotInUseException{}}
}

func TestListActiveAccounts_NotInOrganization(t *testing.T) {
	got, err := listActiveAccounts(context.Background(), notInOrg{})
	if err != nil || got != nil {
		t.Errorf("listActiveAccounts = %v, %v; want nil, nil (single-account mode)", got, err)
	}
}

type fakeListRegions struct{ fixture string }

func (f fakeListRegions) ListRegions(_ context.Context, in *account.ListRegionsInput, _ ...func(*account.Options)) (*account.ListRegionsOutput, error) {
	if len(in.RegionOptStatusContains) != 2 {
		return nil, fmt.Errorf("want ENABLED + ENABLED_BY_DEFAULT filter, got %v", in.RegionOptStatusContains)
	}
	var out account.ListRegionsOutput
	loadFixture(f.fixture, &out)
	return &out, nil
}

func TestListEnabledRegions_FromFixture(t *testing.T) {
	got, err := listEnabledRegions(context.Background(), fakeListRegions{"account/ListRegions.json"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "[me-central-1 us-east-1 us-west-2]"; fmt.Sprint(got) != want {
		t.Errorf("listEnabledRegions = %v, want %v (sorted)", got, want)
	}
}
