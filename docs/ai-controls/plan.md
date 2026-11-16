# cloudcomply — AI Workload Controls

A build plan for extending cloudcomply to assess AI/ML workloads against NIST 800-53,
NIST AI RMF 1.0, and the OWASP LLM Top 10.

> **How to use this:** point Claude Code at this file. Phase 0 is reconnaissance — it reads
> the existing codebase and reports back before writing anything. Review its answers, correct
> the plan where it conflicts with reality, then proceed phase by phase. Do not let it
> implement all three controls in one pass.

> **Status:** Phase 0 complete — see [phase0-recon.md](phase0-recon.md). Phase 1a merged;
> Phase 1b implemented (in review). D1–D3 decided; D4–D6 open — see
> [Open decisions](#open-decisions). Next up: Phase 2 (AU-12), blocked on D4 for checks 01/02.

---

## Goal

Three machine-checkable controls covering AWS AI workloads, each mapped across all three
frameworks, shipped as a coherent increment of the existing tool.

**Non-goals for this phase** (explicitly out of scope — do not build these):
- Any LLM/agentic layer inside cloudcomply. That comes after the control coverage exists.
- Azure or GCP AI services.
- Controls that are primarily organizational process rather than configuration (AC-2 account
  lifecycle, PL family, PM family).
- Remediation. Assess only; report findings.

---

## Phase 0 — Reconnaissance ✅ done

Outcome ([full report](phase0-recon.md)): cloudcomply has **no native checks** today — it
aggregates Security Hub's already-evaluated NIST 800-53 findings. There is no check engine, no
per-account role assumption, no region iteration, no multi-framework mapping, only
`PASSED`/`FAILED` statuses, and no AWS mocking. Phase 1 below builds that foundation.

Original brief, kept for reference:

Read the codebase and answer these in a short written report. The answers determine how the
rest of the plan is implemented.

1. **Check definition model.** Are controls defined as Go functions, or as data (YAML/JSON/
   embedded structs) interpreted by a generic engine? Paste one existing check as an example.
2. **Collector/scorer separation.** Is there a distinct layer that makes AWS API calls versus
   one that evaluates results? Or are calls made inline inside each check?
3. **AWS SDK.** v1 or v2? How are clients constructed, and how is region handled? Does the tool
   iterate regions, or operate on one?
4. **Organizations handling.** How does it assume roles across member accounts? Is there an
   existing pattern for per-account iteration?
5. **Control-to-framework mapping.** How is the 800-53 → DoD SRG impact level mapping stored?
   Can a single check map to multiple controls, and to controls in *different* frameworks?
   If not, what would need to change?
6. **Scoring model.** How are pass/fail/not-applicable/error represented? How does a control
   family score roll up?
7. **TUI rendering.** How are findings surfaced? What would adding a new control family
   require on the display side?
8. **Tests.** What exists? Are AWS calls mocked, and if so how?

**Deliverable:** a markdown report answering all eight, plus a recommendation on whether the
framework-mapping model needs refactoring *before* the controls are added. If it does, that
refactor is Phase 1 and the controls shift back.

---

## Phase 1 — Foundation (required)

Split into two reviewable increments. Neither adds an AI check; both must leave existing
Security Hub behavior and `--demo` output unchanged.

### 1a. Result + mapping model (pure Go, no AWS) — merged (#16)

As built: `nist.CheckResult` + `nist.RollUp` (`internal/nist/rollup.go`), `nist.Tally` /
`Summarize` scoring (`score.go`), `internal/crosswalk` (empty table + `Validate`, tested so every
future entry is checked), and the Security Hub path rewritten as an adapter
(`awsclient.toCheckResult` → `RollUp`). Demo table/JSON output and the rendered TUI were diffed
against `main` and are byte-identical. Deviations from the bullets below:

- Statuses reuse the existing `FindingStatus` values — `PASSED`/`FAILED` plus new
  `NOT_APPLICABLE`/`ERROR` — rather than introducing `PASS`/`FAIL`, so the JSON enum only grows.
- Control-level status precedence is `FAILED > ERROR > PASSED > NOT_APPLICABLE`: one failure fails
  the control; any error with no failure means it can't be claimed as passing.
- `ERROR` stays in the score denominator (counts against the score); `NOT_APPLICABLE` is excluded.
- The crosswalk stores the SRG mapping as one `MinImpactLevel` (cumulative, matching the existing
  model) rather than a list of ILs.
- No `--impact-level` flag yet — per D1 it ships in Phase 2 with the first check that uses it.
- **Security Hub behavior** was deliberately preserved in 1a, then changed in a follow-up
  (decided 2026-11-16) once the new model made it possible:
  - A finding now counts toward **every** NIST control it lists, not just the first — matching
    how Security Hub's own NIST standard attributes it. Previously-hidden failures surface.
  - `NOT_AVAILABLE` findings are classified by `Compliance.StatusReasons` reason code per the
    Security Hub CSPM User Guide table: Config access denied, rule evaluation errors, rule not yet
    created, internal errors and throttling → `ERROR`; `CONFIG_RETURNS_NOT_APPLICABLE` →
    `NOT_APPLICABLE`; no reason or an unrecognized code → still dropped. A blanket
    `NOT_AVAILABLE → ERROR` was rejected: one out-of-scope resource would flip a well-covered
    control from PASSED to ERROR.
  - Security Hub `WARNING` now maps to `ERROR` instead of `FAILED`. Per the same AWS table every
    `WARNING` reason is a cross-account / cross-Region "can't check from here" case (e.g. an SNS
    topic or S3 bucket owned by another account), not a detected misconfiguration. It no longer
    adds to `AccountsAffected` or escalates severity, but still stops a control claiming PASSED.

Original scope:

- **Per-check result type**, distinct from today's per-control `nist.Finding` row:
  `CheckResult{CheckID, Status, Account, Region, Resource, Detail}` with
  `Status ∈ PASS | FAIL | NOT_APPLICABLE | ERROR`. `ERROR` carries the denied action / API error.
- **Crosswalk package** (no AWS dependency): `CheckID → {NIST80053 []string, SRG []ImpactLevel,
  AIRMF []string, OWASPLLM []string, Source}` where `Source` cites the published crosswalk or is
  explicitly `cloudcomply-interpretation`.
- **Scoring:** `NOT_APPLICABLE` excluded from denominators; `ERROR` reported separately and never
  counted as a pass; a real per-family rollup function that the TUI uses (replacing the inline
  recount in `findingsView`).
- **Security Hub adapter:** existing rows flow through the new model unchanged.
- **JSON compatibility:** `report nist --format json` stays backward compatible — new fields are
  additive, the `status` enum only grows. The schema isn't locked yet (CLAUDE.md roadmap item 6),
  so this is the cheapest time to make the change.

### 1b. Execution layer — implemented

As built (`internal/awsclient/scan.go`, `errors.go`; `deploy/`):

- `Client.Scan(ctx, collectors, ScanOptions)` lists ACTIVE accounts (single-account mode when not
  in an org), assumes `arn:<caller's partition>:iam::<acct>:role/<RoleName>` in every account but
  the caller's own, discovers enabled regions with `account:ListRegions` (or uses
  `ScanOptions.Regions`), then runs every `Collector` against every account × region with bounded
  concurrency (default 8) and a per-call timeout (default 60s).
- Per-account failures (role not assumable, region discovery denied) become `ERROR` results for
  every check in that account, naming the role ARN or pointing at `--regions`; the rest of the
  scan continues. Only global failures (no caller identity, `ListAccounts` failing, a check with no
  crosswalk entry) return an error.
- `Collector` is `CheckIDs()` + `Collect(ctx, Target) []CheckResult`. Collectors turn a failed AWS
  call into results with `ResultsForError`, which uses `ClassifyError`: access denied → `ERROR`
  naming `Service:Operation`; no DNS record for the regional endpoint → `NOT_APPLICABLE`; anything
  else → `ERROR`. Results get controls and IL from the crosswalk.
- Test pattern: `scanDeps` function fakes for the fan-out, scrubbed JSON fixtures under
  `internal/awsclient/testdata/` decoded into SDK output types, `apiError(...)` building
  `smithy.OperationError{GenericAPIError}`. Tests run under `-race`.
- `deploy/cloudformation/assessor-role.yaml` (cfn-lint clean) + `deploy/README.md`: StackSet and
  management-account deployment, caller policy, verification.
- The duplicated 30s `fetchTimeout` is now one constant owned by the live fetcher in
  `cmd/fetch.go`; the Security Hub path keeps a single overall bound, the scan engine uses per-call
  timeouts.

Deviations / carried into Phase 2:

- **`--assume-role-name` and `--regions` are not wired yet.** `ScanOptions` and `ParseRegions` are
  ready; the flags ship with the first check that calls `Scan`, as with `--impact-level` (D1).
  Live verification of the fan-out is therefore manual until Phase 2 (`deploy/README.md` step 4).
- **The TUI's 30s fetch bound will be too short once `Scan` joins the fetch** across a real org;
  Phase 2 must give the native-check fetch its own budget.
- Region discovery uses the Account Management API rather than `ec2:DescribeRegions`, keeping the
  large EC2 SDK module out until SC-7 needs it.
- `NOT_APPLICABLE` for a missing service relies on DNS NXDOMAIN for the regional endpoint; other
  DNS failures stay `ERROR`. Revisit if a collector meets a service that fails differently.
- Service-managed StackSets skip the management account; it needs its own stack (documented).

Original scope:

- **Account fan-out:** assume the dedicated read-only assessor role in each member account
  (D2: `cloudcomply-assessor` by default, `--assume-role-name` to override); single-account mode
  keeps working with no role assumption. Ship the StackSet template and IAM policy for the role.
- **Region discovery:** enumerate enabled regions per account, overridable with `--regions` (D3);
  a service that doesn't exist in a region yields `NOT_APPLICABLE`, not `ERROR`.
- **Timeouts and concurrency:** bounded concurrency and per-call timeouts, replacing the single
  global 30s `fetchTimeout` (currently duplicated in `cmd/fetch.go` and `internal/tui/model.go`).
- **Partial results:** one denied call in one account/region produces an `ERROR` result for that
  scope; it no longer aborts the whole run.
- **Test pattern:** narrow per-collector interfaces (SDK v2 idiom) with fakes, JSON fixtures under
  `testdata/` unmarshalled into SDK output types, and `AccessDeniedException` via
  `smithy.GenericAPIError`. Established here, before the first real check.

---

## Framework mapping model

The differentiating work is the crosswalk. A finding should carry all three.

```
Finding
├── 800-53 Rev 5 control(s)      e.g. AU-12
├── DoD SRG impact level(s)       e.g. IL4, IL5
├── AI RMF 1.0 function/category  e.g. MEASURE 2.7
└── OWASP LLM Top 10 risk(s)      e.g. LLM01, LLM10
```

Proposed mappings below are a **starting point, not authoritative**. Validate against
published crosswalks (NIST publishes 800-53 ↔ AI RMF mappings; OWASP publishes its own
framework alignment) and cite the source in code comments. Where no official mapping exists,
mark it as cloudcomply's own interpretation — being explicit about that is a credibility
feature, not a weakness.

**Impact-level-dependent pass conditions.** The current model only records the *lowest* IL at
which a control applies (`MinImpactLevel`). Some checks below (AI-AU-12-03, AI-AU-12-04) have a
*different pass condition* at different ILs. Phase 1a must support this — either by evaluating
against a target IL, or by emitting one result per IL threshold. Which approach is an
[open decision](#open-decisions).

---

## Control 1 — AU-12: Bedrock model invocation logging

**Why first:** one API call, binary answer, no ambiguity. Establishes the collector pattern
and the mapping structure with minimal surface area.

**Rationale:** you cannot investigate a prompt injection you never logged. Invocation logging
is the detection prerequisite for most LLM incident response.

### Checks

| ID | Check | API | Pass condition |
|---|---|---|---|
| AI-AU-12-01 | Invocation logging enabled | `bedrock:GetModelInvocationLoggingConfiguration` | `loggingConfig` present with ≥1 destination |
| AI-AU-12-02 | Text data delivery enabled | same | `textDataDeliveryEnabled == true` |
| AI-AU-12-03 | Log destination encrypted | `s3:GetBucketEncryption` or `logs:DescribeLogGroups` | KMS CMK, not SSE-S3 default, for IL4+ |
| AI-AU-12-04 | Retention meets baseline | `s3:GetBucketLifecycleConfiguration` / `logs:DescribeLogGroups` | ≥ impact-level minimum |

### Notes
- Logging config is **account-level and per-region**. Must iterate enabled regions.
- An account with no Bedrock usage should report `not_applicable`, not `fail`. There is no
  cheap API for "absence of invocation activity"; the detection method is an
  [open decision](#open-decisions).
- AI-AU-12-03 and AI-AU-12-04 depend on the IL-conditional pass model (see
  [Framework mapping model](#framework-mapping-model)). AI-AU-12-04 also needs a cited source for
  per-IL retention minimums — none exists in the repo yet. If either blocks, ship 01/02 first.
- Required IAM: `bedrock:GetModelInvocationLoggingConfiguration`, `s3:GetBucketEncryption`,
  `s3:GetBucketLifecycleConfiguration`, `logs:DescribeLogGroups` (+
  `cloudwatch:GetMetricStatistics` if the metric-based N/A detection is chosen).

### Mapping
- **800-53:** AU-12, AU-2, AU-9 (log protection), AU-11 (retention)
- **AI RMF:** MEASURE 2.x (monitoring), MANAGE 4.1 (post-deployment monitoring)
- **OWASP LLM:** LLM01 (prompt injection — detection), LLM10 (unbounded consumption)

---

## Control 2 — SC-7: AI inference endpoint exposure

**Why second:** more API surface, still a clean pass/fail. This is the control where findings
are most likely to be genuinely alarming in a real environment.

### Checks

| ID | Check | API | Pass condition |
|---|---|---|---|
| AI-SC-7-01 | SageMaker endpoints in VPC | `sagemaker:ListEndpoints` → `DescribeEndpointConfig` → `DescribeModel` | Model has `VpcConfig` with subnets + security groups |
| AI-SC-7-02 | Endpoint network isolation | `sagemaker:DescribeModel` | `EnableNetworkIsolation == true` |
| AI-SC-7-03 | Bedrock accessed via VPC endpoint | `ec2:DescribeVpcEndpoints` | Interface endpoint for `com.amazonaws.<region>.bedrock-runtime` exists |
| AI-SC-7-04 | VPC endpoint policy restricts principals | `ec2:DescribeVpcEndpoints` → `PolicyDocument` | Not `"Principal": "*"` with unrestricted actions |
| AI-SC-7-05 | Notebook instances not internet-facing | `sagemaker:ListNotebookInstances` → `DescribeNotebookInstance` | `DirectInternetAccess == "Disabled"` |
| AI-SC-7-06 | Guardrails configured | `bedrock:ListGuardrails` | ≥1 guardrail exists (advisory finding if none) |

### Notes
- A SageMaker endpoint without `VpcConfig` is not publicly exposed in the EC2 sense — traffic
  still goes over AWS's network and requires IAM auth. Word the finding precisely: this is
  about network path control and data egress, not an open port. Getting this nuance right
  matters for credibility with reviewers who know SageMaker.
- AI-SC-7-06 is a weak signal (guardrail existence ≠ guardrail attached to the right model).
  Mark advisory. A follow-on check could verify guardrail association per invocation path.
- **Overlap with Security Hub.** Security Hub already ships NIST-mapped SageMaker controls that
  flow into cloudcomply today — notably notebook direct internet access, which duplicates
  AI-SC-7-05, plus SageMaker VPC / root-access controls. Before building this phase, pull the
  current Security Hub control list for SageMaker and Bedrock, and for each overlap either skip the
  native check or reuse the Security Hub result, so one issue isn't counted twice.

### Mapping
- **800-53:** SC-7, SC-7(3) access points, AC-4 information flow, SC-8 transmission confidentiality
- **AI RMF:** MANAGE 2.x, MEASURE 2.6 (deployment security)
- **OWASP LLM:** LLM02 (sensitive information disclosure), LLM10

---

## Control 3 — AC-6: AI workload execution role privilege

**Why third:** highest value, hardest to get right. An overbroad SageMaker execution role is
the realistic breach path in most AI environments.

This is the workload-identity slice of account management — deliberately *not* AC-2 account
lifecycle, which is mostly organizational process and not machine-checkable.

### Checks

| ID | Check | API | Pass condition |
|---|---|---|---|
| AI-AC-6-01 | Enumerate AI execution roles | `sagemaker:ListNotebookInstances`, `ListTrainingJobs`, `ListModels`, `ListProcessingJobs`, `ListPipelines` | — (collection step) |
| AI-AC-6-02 | No AWS-managed full-access policies | `iam:ListAttachedRolePolicies` | No `AmazonSageMakerFullAccess`, `AdministratorAccess`, `PowerUserAccess` |
| AI-AC-6-03 | No wildcard actions in inline policies | `iam:ListRolePolicies` → `GetRolePolicy` | No `"Action": "*"` or `"<service>:*"` on sensitive services |
| AI-AC-6-04 | No wildcard resources on S3 | same + attached policy documents | No `"Resource": "*"` for `s3:GetObject` |
| AI-AC-6-05 | Trust policy scoped | `iam:GetRole` → `AssumeRolePolicyDocument` | Service principal only; no cross-account wildcard |
| AI-AC-6-06 | Unused permissions | `iam:GenerateServiceLastAccessedDetails` → `GetServiceLastAccessedDetails` | Flag services never accessed in 90 days |

### Notes
- AI-AC-6-06 is asynchronous — generate, poll for completion, then retrieve. Budget for the
  polling pattern; it's the most complex collector here. Consider making it opt-in behind a
  flag so the default run stays fast.
- Policy document parsing: handle both `Action` as string and as list; same for `Resource`.
  URL-decode inline policy documents.
- Training data access is the finding that matters most. A notebook role that can read the
  production training bucket is the lineage/poisoning risk — call that out specifically rather
  than burying it in generic wildcard findings.

### Mapping
- **800-53:** AC-6, AC-6(1), AC-3, AC-2(7) privileged role management, CM-5
- **AI RMF:** GOVERN 1.x (roles and responsibilities), MANAGE 2.2
- **OWASP LLM:** LLM06 (excessive agency), LLM03 (supply chain), LLM04 (data poisoning)

---

## Implementation order

Each phase ends with a working, committed increment. Do not start the next until the previous
passes tests and produces correct output against a real account.

| Phase | Deliverable | Rough size | Blocked on |
|---|---|---|---|
| 0 | Reconnaissance report | 1 session | ✅ done |
| 1a | Result + mapping model (statuses, crosswalk, scoring, SH adapter) | 1–2 sessions | ✅ merged (#16) |
| 1b | Execution layer (account/region fan-out, timeouts, partial results, test pattern) | ~1 weekend | ✅ implemented (in review) |
| 2 | AU-12 checks (first native check) + tests | 1 session for 01/02; 03/04 after their decisions | Bedrock N/A detection; retention source |
| 3 | TUI rendering for AI workload results + finding detail pane | 1–2 sessions | TUI placement decision |
| 4 | SC-7 checks + tests (after Security Hub overlap review) | 1 weekend | — |
| 5 | AC-6 checks (defer AI-AC-6-06 if it bogs down) + tests | 2 weekends | — |
| 6 | README, sample report, documented IAM policy for the assessor role | 1 session | — |

Phase 3 now includes the **finding detail pane** (CLAUDE.md roadmap item 2): the findings table is
already ~81 columns wide, so the AI RMF / OWASP mappings can only be shown there. Phase 3 is not a
new *family* — AU, SC and AC already exist as families and Security Hub already emits rows for
them.

---

## Cross-cutting requirements

**Least-privilege assessor role.** Ship a documented IAM policy containing exactly the
read-only permissions these checks need, and nothing more. For a compliance tool this is a
credibility artifact in its own right — reviewers will read it before they run the binary.

**Graceful degradation.** A missing permission must produce a clear `error` finding naming the
denied action, never a silent `pass`. A tool that reports compliance because it couldn't see
anything is worse than no tool.

**Not-applicable is a first-class result.** Most accounts run no AI workloads. Those should
report `not_applicable` and be excluded from scoring denominators, not scored as failures.

**Region and account iteration.** Bedrock and SageMaker are regional and availability varies by
region. Handle regions where the service does not exist without erroring. These APIs are also
per-account and are *not* aggregated by Security Hub, so without the Phase 1b fan-out the checks
would only see the account and region the tool runs in. Neither iteration exists today.

**Testing.** Mock AWS responses using recorded fixtures from a real account with identifiers
scrubbed. Each check needs a pass case, a fail case, a not-applicable case, and an
access-denied case.

---

## Open decisions

Owner decisions surfaced by Phase 0. Options are listed with the recon's recommendation where it
made one. Record each choice under [Decided](#decided) when made. **D1–D3 are decided; D4–D6 are
still open.**

| # | Decision | Options | Recon recommendation | Blocks |
|---|---|---|---|---|
| D1 | **IL-conditional pass criteria** | (a) evaluate against a target IL chosen at run time; (b) emit one result per IL threshold | — | 1a, AI-AU-12-03/04 |
| D2 | **Assessor role** in member accounts | (a) dedicated read-only role deployed via StackSets; (b) reuse `OrganizationAccountAccessRole` | (a) — (b) is admin-equivalent and undercuts the least-privilege credibility goal | 1b |
| D3 | **Region scope** | (a) discover enabled regions (`account:ListRegions` / `ec2:DescribeRegions`); (b) `--regions` flag; (c) both, flag overrides | — | 1b |

### Decided

- **D1 → (a) target IL, default IL4** *(2026-11-16)*. A `--impact-level IL2|IL4|IL5|IL6` flag
  selects the IL that IL-dependent checks are evaluated against; default `IL4`. Evaluators are
  pure functions of (collected snapshot, target IL), so the TUI can re-evaluate on an IL switch
  without new AWS calls. The flag itself lands in Phase 2 with the first IL-dependent check
  (AI-AU-12-03) — no unused flag ships in 1a. The dashboard's existing "DoD SRG (IL5 Mission
  Owner)" readiness score is a separate, scope-based number and is unchanged by this decision.
- **D2 → (a) dedicated read-only role** *(2026-11-16)*. `OrganizationAccountAccessRole` is
  rejected: it trusts only the management account (cloudcomply runs from the Security Hub
  delegated admin), exists only in accounts *created* through Organizations (not invited ones),
  and carries `AdministratorAccess`. Instead: a role (default name `cloudcomply-assessor`) with
  exactly the read-only actions the checks need, trusting the delegated admin account, deployed by
  a service-managed CloudFormation StackSet with auto-deployment to new accounts. An
  `--assume-role-name` flag lets an org point at an existing role. AWS-managed `SecurityAudit` is
  acceptable only as a testing stopgap.
- **D3 → (c) both** *(2026-11-16)*. Default: discover enabled regions per account. `--regions`
  overrides with one region or a comma-separated list (e.g. `--regions us-east-1` or
  `--regions us-east-1,us-gov-west-1`).
| D4 | **Bedrock not-applicable detection** | (a) CloudWatch `AWS/Bedrock` `Invocations` metric per region (needs `cloudwatch:GetMetricStatistics`); (b) explicit scope flag | (a), with (b) as override | AI-AU-12-01/02 |
| D5 | **Retention minimum source** for AI-AU-12-04 | Name the authority (e.g. DoD SRG, OMB M-21-31) | — | AI-AU-12-04 |
| D6 | **TUI placement** of AI workload results | (a) merge into existing per-control rows; (b) new "source" filter tab (`ALL / Security Hub / AI Workloads`); (c) new view | (b) — keeps AI findings visible, matches existing filter UX | 3 |

---

## Sequencing note

Build the control coverage before any agentic layer. An LLM interface over the control set
everyone already has is a commodity; an LLM interface over AI workload findings nobody else
collects is not. Controls first, agent second.
