# cloudcomply — Phase 0 Reconnaissance Report

Codebase read at `main` @ `f85f1ea` (after PRs #13/#14). ~1,250 lines of Go across
`cmd/`, `internal/{awsclient,nist,report,tui}`. `go test ./...` passes. No code was
written for this report.

> This is a point-in-time snapshot. The living plan is [plan.md](plan.md); the open
> questions at the end of this report are tracked there as decisions D1–D6.

## TL;DR

**cloudcomply has no checks today.** It is a Security Hub *aggregator*: it pulls
findings that AWS Security Hub's NIST 800-53 Rev 5 standard already evaluated, groups
them by control ID, and scores pass/fail. Several things the plan assumes are already
in place do not exist yet:

| Plan assumes | Reality |
|---|---|
| A check definition model to extend | None. No checks, no engine. AU-12 would be the **first native check ever**. |
| Per-account iteration / role assumption | None. No `AssumeRole` anywhere. Multi-account coverage comes entirely from Security Hub's delegated-admin aggregation. |
| Region handling | Single ambient region. No iteration. |
| Multi-framework mapping | `Finding` holds one `ControlID`, one `Family`, one `MinImpactLevel`. Live IL is hardcoded to `IL2`. |
| `not_applicable` / `error` results | Only `PASSED` / `FAILED`. N/A is silently dropped; any API error fails the whole run. |
| Mocked AWS calls | No mocking or interfaces. Tests cover pure functions only. |

**Recommendation: yes, Phase 1 is needed — and it is bigger than a mapping refactor.**
It needs a result model *and* an account×region execution layer. Details at the end.

---

## 1. Check definition model

There are no check definitions, neither as Go functions nor as data. The evaluation is done by
AWS (Security Hub's NIST standard). cloudcomply's job is filtering and aggregation in
`internal/awsclient/findings.go`:

- `GetNISTFindings` — `GetFindings` paginator filtered on
  `standards/nist-800-53/v/5.0.0` + `RecordState=ACTIVE`.
- `mergeFinding` — parses `Compliance.RelatedRequirements` for `"NIST.800-53.r5 <ID>"`,
  folds raw ASFF findings into one aggregate per control.
- `finalizeFindings` — aggregate → `nist.Finding`.

Closest thing to a "check", `findings.go:91`:

```go
func mergeFinding(agg map[string]*controlAggregate, f types.AwsSecurityFinding) {
	controlID, family, ok := parseNISTControlID(f.Compliance)
	if !ok {
		return
	}
	status, scorable := statusMap[f.Compliance.Status]
	if !scorable {
		return
	}
	a, exists := agg[controlID]
	if !exists {
		a = &controlAggregate{controlID: controlID, family: family,
			title: aws.ToString(f.Title), severity: mapSeverity(f.Severity),
			accounts: map[string]bool{}}
		agg[controlID] = a
	}
	if status == nist.StatusFailed {
		a.failed = true
		a.accounts[aws.ToString(f.AwsAccountId)] = true
		// ...escalate severity to the worst failing finding
	}
}
```

Demo data (`internal/nist/demo.go`) is hand-written positional struct literals, one row per
control.

**Implication:** Phase 2 is not "add a check to the engine". It's "design the check
pattern from scratch". The plan's "1 weekend" for AU-12 is optimistic unless Phase 1 lays
the groundwork.

Note: one finding hits only the first `NIST.800-53.r5` requirement it carries
(`parseNISTControlID` returns on first match). A Security Hub control mapped to
AC-4 *and* SC-7 is counted under one of them only. That's an existing limitation, and the
same multi-control issue the plan needs solved.

## 2. Collector / scorer separation

Partially, and in a good shape to copy:

- **Collector:** `internal/awsclient` is the only package importing the AWS SDK (stated
  in its package doc). Network calls live in `GetNISTFindings` / `GetOrgSummary`.
- **Evaluation/mapping:** `mergeFinding` / `finalizeFindings` / `parseNISTControlID` are
  pure functions over SDK types, which is why they're unit-testable.
- **Scoring:** `internal/nist/score.go`, pure, AWS-free.
- **Rendering:** `internal/report` (headless) and `internal/tui`, both fed through a
  single injected `FindingsFetcher func(ctx) ([]nist.Finding, nist.OrgSummary, error)`
  built in `cmd/fetch.go` (demo vs. live).

The new controls should mirror this: **collector** (AWS calls behind small
interfaces) → **pure evaluator** (collected snapshot → results) → shared scoring/rendering.
CLAUDE.md already plans the same pattern for `internal/drift`.

## 3. AWS SDK

- **SDK for Go v2** (`aws-sdk-go-v2 v1.42.1`). Service modules in use: `securityhub`,
  `organizations`, `sts`.
- **Construction:** `awsclient.New` calls `config.LoadDefaultConfig(ctx)` once and builds
  three clients from that single `aws.Config`. Credentials come from the ambient environment
  (CloudShell role, env vars, profile/SSO). Nothing is hardcoded.
- **Region:** whatever the ambient config resolves (`AWS_REGION` / profile / CloudShell's
  region). **No region iteration.** For Security Hub that's tolerable if cross-region
  aggregation is on. For Bedrock/SageMaker direct calls it means only one region is seen.
- **Timeout:** one global `fetchTimeout = 30s` for the entire fetch (duplicated in
  `cmd/fetch.go` and `internal/tui/model.go`). An accounts × regions × checks fan-out will
  not fit in 30s for a real org.
- **Housekeeping:** `go.mod` marks the AWS SDK modules `// indirect` even though they're
  imported directly. `go mod tidy` fixes it (5-line diff, not applied here).
- **Binary size:** adding `bedrock`, `sagemaker`, `iam`, `ec2`, `s3`, `cloudwatchlogs`
  modules is fine for the static/no-CGO constraint, but `ec2` in particular is large. Worth
  measuring against the "fast startup, one binary" goal.

## 4. Organizations handling

- `GetOrgSummary` calls `DescribeOrganization` + paginated `ListAccounts`, **only to
  display the org ID and account count**.
- If the caller isn't in an org (`AWSOrganizationsNotInUseException`), it falls back to
  single-account mode via `GetCallerIdentity`.
- **No `sts:AssumeRole`, no per-account loop, no per-account clients.** CLAUDE.md lists
  `sts:AssumeRole (if using cross-account checks)` as a planned IAM permission. Nothing
  implements it.

**Implication:** every AI check in the plan calls Bedrock/SageMaker/IAM/EC2/S3 APIs
directly. Those are per-account and per-region, and Security Hub won't aggregate them. Without
a new fan-out layer (assume an assessor role in each member account, discover enabled
regions, run collectors with bounded concurrency), the AI controls would assess **only the
account and region the tool runs in**. That's the single biggest gap versus the plan.

Decisions needed: assessor role name (`OrganizationAccountAccessRole` is
admin-equivalent and contradicts the least-privilege goal; a dedicated read-only role via
StackSets is the credible option), and how region scope is chosen (`account:ListRegions`
/ `ec2:DescribeRegions` vs. a `--regions` flag).

## 5. Control-to-framework mapping

- **800-53:** a single `ControlID string` per `Finding`, sourced from Security Hub's
  `RelatedRequirements`. No local catalog or titles; `Title` is Security Hub's
  per-security-control title (TODO `nistmap` in `findings.go`).
- **DoD SRG IL:** a single `MinImpactLevel` scalar per finding. Demo rows set it inline.
  **Live findings hardcode `IL2`** (TODO `nistmap`). There is no crosswalk table anywhere
  in the repo. ILs are treated as cumulative (`ImpactLevelAtOrBelow`).
- **AI RMF / OWASP LLM:** no representation.

**Can one check map to multiple controls, or to other frameworks?** No. `Finding` is
*one row per 800-53 control*, not one row per check, and has no slots for other frameworks.

**What needs to change:**

1. Introduce a per-check result (e.g. `CheckResult{CheckID, Status, Resource, Account,
   Region, Detail, Evidence}`) distinct from the per-control rollup row.
2. A static, cited crosswalk keyed by check ID:
   `CheckID → {NIST80053: []string, SRG: []ImpactLevel, AIRMF: []string, OWASPLLM: []string, Source: "nist-crosswalk" | "cloudcomply-interpretation"}`.
   Keep it as Go data in its own package, with no AWS dependency.
3. **IL-conditional pass criteria.** AI-AU-12-03 ("CMK, not SSE-S3, *for IL4+*") and
   AI-AU-12-04 (retention "≥ impact-level minimum") can't be expressed by the current model,
   which says *at which IL a control applies*, not *what passing means at each IL*. Either
   evaluate per target IL or emit one result per threshold. No retention-by-IL source data
   exists in the repo yet. The plan should name its authority (e.g. SRG / M-21-31) before
   this check is built.

## 6. Scoring model

- `FindingStatus` = `PASSED | FAILED` only.
- Security Hub `WARNING` → `FAILED`. `NOT_AVAILABLE` (and anything unknown) is **silently
  dropped**: not counted, not shown.
- **No N/A, no ERROR.** Any AWS error aborts the whole fetch (`cmd/fetch.go` returns on
  first error). That's safe (never a false pass), but all-or-nothing. One denied Bedrock
  call in one region would sink the entire report.
- `ComplianceScore` = passed ÷ total × 100 over all rows, equally weighted. No severity
  weighting.
- **No per-family rollup function.** The TUI recounts pass/fail per active filter inline in
  `findingsView` (duplicating `buildTable`'s filter logic). IL score =
  `ComplianceScore` over rows with `MinImpactLevel ≤ target`.
- An empty result set scores 0%, not 100%. That's good, and the right instinct for
  "graceful degradation".

The plan's cross-cutting requirements ("N/A is first-class and excluded from
denominators", "missing permission → `error` naming the denied action") require new
statuses, scoring that excludes N/A, and partial-failure handling instead of abort.

## 7. TUI rendering

- Two views (`viewDashboard`, `viewFindings`), following the `type view int` pattern.
- Findings browser = Bubbles `table` built by pure `buildTable(findings, familyFilter,
  impactFilter)`. 7 fixed columns, ~81 chars wide, already at the edge of a Termux
  screen.
- Family tabs are a **hardcoded list** in `initialModel`:
  `{"ALL","AC","AU","CM","IA","SC","SI"}`.

What a new family would need: one line in that list. But **the AI controls aren't a new
family.** AU-12, SC-7 and AC-6 already exist as families, and Security Hub already emits AU-12 /
SC-7 / AC-6 rows. So the real design question is how AI-workload results coexist with
Security Hub rows:

- **(a) Merge** into the same per-control rows. Simple, but an `AU-12` row then blends
  CloudTrail and Bedrock evidence and the AI story disappears.
- **(b) Separate "scope/source" filter** (`ALL | Security Hub | AI Workloads`) as a third
  tab bar. Keeps the AI findings visible and is consistent with the existing filter UX.
- **(c) New view** (`viewAIWorkloads`) with per-check rows.

There's no room for AI RMF / OWASP columns in the table. They belong in the
**finding detail pane** (CLAUDE.md roadmap item 2, Enter on a row), which doesn't exist
yet and becomes a prerequisite for showing the crosswalk at all.

Also: the dashboard's "Run Full NIST Compliance Scan" says "(demo mode)" even live
(`model.go:167`, known rough edge in TESTING.md).

## 8. Tests

- One test file: `internal/awsclient/findings_test.go`. It covers
  `parseNISTControlID`, aggregation across accounts, severity escalation, skipping
  non-NIST / `NOT_AVAILABLE`, and sort order.
- **No AWS mocking.** Tests hand-build SDK `types.AwsSecurityFinding` structs and call the
  pure functions. `Client` holds concrete `*securityhub.Client` etc., with no interfaces, so
  the network-calling methods (`GetNISTFindings`, `GetOrgSummary`) are untested.
- No tests for `nist` (scoring), `report`, `tui` (`buildTable`), or `cmd`.
- No fixtures directory.

For the plan's "pass / fail / N/A / access-denied per check using scrubbed recorded
fixtures": the idiomatic SDK v2 approach is a narrow per-collector interface (e.g.
`type bedrockAPI interface { GetModelInvocationLoggingConfiguration(...) }`) with a fake
in tests, plus JSON fixtures in `testdata/` unmarshalled into SDK output types. Access-denied
cases use a fake returning a `smithy.GenericAPIError{Code: "AccessDeniedException"}`.

---

## Recommendation

**Do the refactor first.** Proposed Phase 1, split so each half is a reviewable increment:

**1a. Result + mapping model** (pure Go, no AWS):
- `CheckResult` with `PASS | FAIL | NOT_APPLICABLE | ERROR`, resource/account/region,
  denied-action detail on `ERROR`.
- Crosswalk package with cited sources and an explicit `cloudcomply-interpretation` marker.
- Scoring that excludes N/A from denominators and surfaces ERROR separately (never counts
  it as pass), plus a real per-family rollup function the TUI uses instead of recounting.
- Existing Security Hub rows keep working through an adapter. `report nist --format json`
  stays backward compatible. New fields are additive and the `status` enum only grows. Roadmap
  item 6 (lock the JSON schema) hasn't happened yet, so **now is the cheapest time** to make
  this change.

**1b. Execution layer**:
- Per-account assume-role (dedicated read-only assessor role), region discovery, bounded
  concurrency, per-call timeouts replacing the global 30s, partial results instead of
  abort.
- Collector interfaces + fixture-based fakes, establishing the test pattern before the
  first real check.

Then AU-12 (Phase 2) becomes genuinely small: one collector, one evaluator, four crosswalk
entries, four fixture sets.

## Corrections / open questions for the plan

1. **Overlap with Security Hub.** Security Hub already ships SageMaker controls with NIST
   800-53 mappings (e.g. notebook direct-internet-access, which matches AI-SC-7-05; and
   SageMaker VPC/root-access controls). Those already flow into cloudcomply today. Verify the current
   Security Hub control list for SageMaker/Bedrock, and either skip duplicates or reuse
   their results, so the same issue isn't double-counted.
2. **Bedrock N/A detection.** "Absence of invocation activity" has no cheap direct API.
   The CloudWatch `AWS/Bedrock` `Invocations` metric per region is a practical signal
   (needs `cloudwatch:GetMetricStatistics`). Otherwise use the scope flag the plan mentions.
3. **IL-dependent pass conditions** (AI-AU-12-03/04) need a model decision (see §5) and a
   cited retention source.
4. **TUI placement** — merge vs. scope filter vs. new view (§7). Recommend (b).
5. **Assessor role** — dedicated least-privilege role deployed via StackSets vs. reusing
   `OrganizationAccountAccessRole` (§4). The plan's credibility argument favors the former.
6. **Timeline.** With Phase 1 split into 1a/1b, the plan's "1–2 sessions" for Phase 1 is
   likely low; the execution layer alone is comparable to the AU-12 weekend.

## Unrelated housekeeping noticed

- `go.mod`: AWS SDK modules wrongly marked `// indirect` (`go mod tidy`).
- `CLAUDE.md` "What's Done" is stale (Cobra CLI and Security Hub integration landed).
- `CLI.md` still says `report nist` always reads demo data (flagged in TESTING.md §G).
- `fetchTimeout` duplicated in `cmd/fetch.go` and `internal/tui/model.go`.
