package awsclient

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"cloudcomply/internal/nist"
)

const (
	// DefaultAssessorRoleName is the read-only role deployed to member
	// accounts by deploy/cloudformation/assessor-role.yaml.
	DefaultAssessorRoleName = "cloudcomply-assessor"
	defaultConcurrency      = 8
	defaultCallTimeout      = 60 * time.Second
	roleSessionName         = "cloudcomply"
)

// Target is one account/region pair a Collector runs against. Config
// carries credentials for Account and has Region set.
type Target struct {
	Account string
	Region  string
	Config  aws.Config
}

// Collector evaluates a fixed set of native checks against one target.
// Collect reports per-check failures (access denied, service absent from
// the region) as ERROR / NOT_APPLICABLE results — see ResultsForError —
// rather than returning an error, so one bad call never sinks the scan.
type Collector interface {
	// CheckIDs lists the crosswalk IDs this collector reports. Scan uses it
	// to emit ERROR results when a whole account can't be reached.
	CheckIDs() []string
	Collect(ctx context.Context, t Target) []nist.CheckResult
}

// ScanOptions controls account/region fan-out. Zero values select defaults.
type ScanOptions struct {
	RoleName    string        // role assumed in non-caller accounts
	Regions     []string      // empty: discover enabled regions per account
	Concurrency int           // max concurrent account/target operations
	CallTimeout time.Duration // bound on each assume-role, region lookup and Collect
}

func (o ScanOptions) withDefaults() ScanOptions {
	if o.RoleName == "" {
		o.RoleName = DefaultAssessorRoleName
	}
	if o.Concurrency <= 0 {
		o.Concurrency = defaultConcurrency
	}
	if o.CallTimeout <= 0 {
		o.CallTimeout = defaultCallTimeout
	}
	return o
}

// ParseRegions parses a --regions value: one region or a comma-separated
// list. Empty input means "discover", returned as nil.
func ParseRegions(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, r := range strings.Split(s, ",") {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		if !regionRe.MatchString(r) {
			return nil, fmt.Errorf("invalid region %q", r)
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out, nil
}

// scanDeps isolates every AWS call Scan makes so the fan-out logic can be
// tested without AWS.
type scanDeps struct {
	callerARN    func(ctx context.Context) (string, error)
	listAccounts func(ctx context.Context) ([]string, error)
	assume       func(ctx context.Context, roleARN string) (aws.Config, error)
	listRegions  func(ctx context.Context, cfg aws.Config) ([]string, error)
	base         aws.Config
}

func (c *Client) deps() scanDeps {
	return scanDeps{
		base: c.cfg,
		callerARN: func(ctx context.Context) (string, error) {
			out, err := c.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
			if err != nil {
				return "", err
			}
			return aws.ToString(out.Arn), nil
		},
		listAccounts: func(ctx context.Context) ([]string, error) {
			return listActiveAccounts(ctx, c.org)
		},
		assume: func(ctx context.Context, roleARN string) (aws.Config, error) {
			cfg := c.cfg.Copy()
			cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(c.sts, roleARN, func(o *stscreds.AssumeRoleOptions) {
				o.RoleSessionName = roleSessionName
			}))
			// Retrieve now so an unassumable role fails here, attributed to
			// its account, instead of inside every collector call.
			if _, err := cfg.Credentials.Retrieve(ctx); err != nil {
				return aws.Config{}, err
			}
			return cfg, nil
		},
		listRegions: func(ctx context.Context, cfg aws.Config) ([]string, error) {
			return listEnabledRegions(ctx, account.NewFromConfig(cfg))
		},
	}
}

// Scan runs every collector against every reachable account × region.
// Only failures that make the whole scan meaningless (no caller identity,
// can't list the organization's accounts, a check with no crosswalk entry)
// return an error; per-account and per-target failures become ERROR
// results so the rest of the scan still reports.
func (c *Client) Scan(ctx context.Context, collectors []Collector, opts ScanOptions) ([]nist.CheckResult, error) {
	return scan(ctx, c.deps(), collectors, opts)
}

func scan(ctx context.Context, d scanDeps, collectors []Collector, opts ScanOptions) ([]nist.CheckResult, error) {
	opts = opts.withDefaults()
	for _, col := range collectors {
		for _, id := range col.CheckIDs() {
			if _, ok := lookupMapping(id); !ok {
				return nil, fmt.Errorf("check %s has no crosswalk mapping", id)
			}
		}
	}

	callerARN, err := d.callerARN(ctx)
	if err != nil {
		return nil, fmt.Errorf("get caller identity: %w", err)
	}
	partition, home, err := parseCallerARN(callerARN)
	if err != nil {
		return nil, err
	}
	accounts, err := d.listAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	if len(accounts) == 0 {
		accounts = []string{home}
	}

	var (
		mu      sync.Mutex
		results []nist.CheckResult
		targets []Target
	)
	emit := func(rs ...nist.CheckResult) {
		mu.Lock()
		results = append(results, rs...)
		mu.Unlock()
	}

	forEach(len(accounts), opts.Concurrency, func(i int) {
		acct := accounts[i]
		ts, err := resolveAccount(ctx, d, opts, partition, home, acct)
		if err != nil {
			for _, col := range collectors {
				emit(ResultsForStatus(col.CheckIDs(), Target{Account: acct}, nist.StatusError, err.Error())...)
			}
			return
		}
		mu.Lock()
		targets = append(targets, ts...)
		mu.Unlock()
	})

	type job struct {
		col Collector
		t   Target
	}
	var jobs []job
	for _, t := range targets {
		for _, col := range collectors {
			jobs = append(jobs, job{col, t})
		}
	}
	forEach(len(jobs), opts.Concurrency, func(i int) {
		callCtx, cancel := context.WithTimeout(ctx, opts.CallTimeout)
		defer cancel()
		emit(jobs[i].col.Collect(callCtx, jobs[i].t)...)
	})

	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if a.Account != b.Account {
			return a.Account < b.Account
		}
		if a.Region != b.Region {
			return a.Region < b.Region
		}
		return a.CheckID < b.CheckID
	})
	return results, nil
}

// resolveAccount returns one Target per region for an account, assuming the
// assessor role unless acct is the caller's own account.
func resolveAccount(ctx context.Context, d scanDeps, opts ScanOptions, partition, home, acct string) ([]Target, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.CallTimeout)
	defer cancel()

	cfg := d.base
	if acct != home {
		roleARN := fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, acct, opts.RoleName)
		var err error
		if cfg, err = d.assume(ctx, roleARN); err != nil {
			return nil, fmt.Errorf("assume %s: %w", roleARN, err)
		}
	}

	regions := opts.Regions
	if len(regions) == 0 {
		var err error
		if regions, err = d.listRegions(ctx, cfg); err != nil {
			return nil, fmt.Errorf("discover enabled regions (set --regions to skip discovery): %w", err)
		}
	}

	targets := make([]Target, 0, len(regions))
	for _, r := range regions {
		rc := cfg.Copy()
		rc.Region = r
		targets = append(targets, Target{Account: acct, Region: r, Config: rc})
	}
	return targets, nil
}

// forEach runs fn(0..n-1) with at most limit calls in flight.
func forEach(n, limit int, fn func(i int)) {
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer func() { <-sem; wg.Done() }()
			fn(i)
		}(i)
	}
	wg.Wait()
}

// parseCallerARN returns the partition (aws, aws-us-gov, …) and account ID
// from an STS caller ARN. The partition matters: GovCloud role ARNs use
// arn:aws-us-gov, and the IL4/IL5 audience lives there.
func parseCallerARN(arn string) (partition, accountID string, err error) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" || parts[1] == "" || parts[4] == "" {
		return "", "", fmt.Errorf("unexpected caller ARN %q", arn)
	}
	return parts[1], parts[4], nil
}

// listActiveAccounts returns the IDs of ACTIVE accounts in the
// organization, or nil when the caller isn't in one (single-account mode).
func listActiveAccounts(ctx context.Context, api organizations.ListAccountsAPIClient) ([]string, error) {
	var ids []string
	p := organizations.NewListAccountsPaginator(api, &organizations.ListAccountsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			var notInOrg *orgtypes.AWSOrganizationsNotInUseException
			if errors.As(err, &notInOrg) {
				return nil, nil
			}
			return nil, err
		}
		for _, a := range page.Accounts {
			if accountActive(a) {
				ids = append(ids, aws.ToString(a.Id))
			}
		}
	}
	return ids, nil
}

// accountActive prefers State, falling back to the deprecated Status field
// for responses that predate State.
func accountActive(a orgtypes.Account) bool {
	if a.State != "" {
		return a.State == orgtypes.AccountStateActive
	}
	return a.Status == orgtypes.AccountStatusActive
}

func listEnabledRegions(ctx context.Context, api account.ListRegionsAPIClient) ([]string, error) {
	var regions []string
	p := account.NewListRegionsPaginator(api, &account.ListRegionsInput{
		RegionOptStatusContains: []accounttypes.RegionOptStatus{
			accounttypes.RegionOptStatusEnabled,
			accounttypes.RegionOptStatusEnabledByDefault,
		},
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range page.Regions {
			regions = append(regions, aws.ToString(r.RegionName))
		}
	}
	sort.Strings(regions)
	return regions, nil
}
