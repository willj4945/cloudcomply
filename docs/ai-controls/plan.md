# cloudcomply — AI Workload Controls

A build plan for extending cloudcomply to assess AI/ML workloads against NIST 800-53,
NIST AI RMF 1.0, and the OWASP LLM Top 10.

> **How to use this:** point Claude Code at this file. Phase 0 is reconnaissance — it reads
> the existing codebase and reports back before writing anything. Review its answers, correct
> the plan where it conflicts with reality, then proceed phase by phase. Do not let it
> implement all three controls in one pass.

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

## Phase 0 — Reconnaissance (do this first, write no code)

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
- An account with no Bedrock usage should report `not_applicable`, not `fail`. Detect via
  `bedrock:ListFoundationModels` access plus absence of invocation activity, or make it a
  configurable scope flag.
- Required IAM: `bedrock:GetModelInvocationLoggingConfiguration`, `s3:GetBucketEncryption`,
  `s3:GetBucketLifecycleConfiguration`, `logs:DescribeLogGroups`.

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

| Phase | Deliverable | Rough size |
|---|---|---|
| 0 | Reconnaissance report | 1 session |
| 1 | Framework mapping model refactor *(only if Phase 0 says it's needed)* | 1–2 sessions |
| 2 | AU-12 checks + collector pattern + tests | 1 weekend |
| 3 | TUI rendering for the new control family | 1 session |
| 4 | SC-7 checks + tests | 1 weekend |
| 5 | AC-6 checks (defer AI-AC-6-06 if it bogs down) + tests | 2 weekends |
| 6 | README, sample report, documented IAM policy for the assessor role | 1 session |

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

**Region iteration.** Bedrock and SageMaker are regional and availability varies by region.
Handle regions where the service does not exist without erroring.

**Testing.** Mock AWS responses using recorded fixtures from a real account with identifiers
scrubbed. Each check needs a pass case, a fail case, a not-applicable case, and an
access-denied case.

---

## Sequencing note

Build the control coverage before any agentic layer. An LLM interface over the control set
everyone already has is a commodity; an LLM interface over AI workload findings nobody else
collects is not. Controls first, agent second.
