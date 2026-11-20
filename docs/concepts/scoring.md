# How findings are scored

cloudcomply doesn't evaluate AWS resources itself. It **aggregates** the per-resource findings Security Hub produces for the NIST SP 800-53 Rev. 5 standard into one result per NIST control.

## 1. Fetch

`securityhub:GetFindings` is paged to completion with two filters:

- `ComplianceAssociatedStandardsId = standards/nist-800-53/v/5.0.0`
- `RecordState = ACTIVE` (archived findings are ignored)

## 2. Map each finding to NIST controls

Each Security Hub finding lists NIST control IDs in `Compliance.RelatedRequirements`, e.g. `NIST.800-53.r5 AC-4`. A finding counts toward **every** `NIST.800-53.r5` control it lists, the same way Security Hub's own NIST standard attributes it. Duplicate and malformed entries are skipped. The family is the part of the control ID before the first `-`.

Findings with no NIST requirement are skipped.

## 3. Map statuses

| Security Hub `Compliance.Status` | cloudcomply |
|---|---|
| `PASSED` | `PASSED` |
| `FAILED` | `FAILED` |
| `WARNING` | `ERROR`: every documented `WARNING` reason is a cross-account or cross-Region resource Security Hub can't check from where it runs, not a detected misconfiguration |
| `NOT_AVAILABLE` | Classified by `Compliance.StatusReasons[].ReasonCode` (see below) |

`NOT_AVAILABLE` reason codes, per the reason-code table in the Security Hub CSPM User Guide:

| Reason code | cloudcomply |
|---|---|
| `CONFIG_ACCESS_DENIED`, `CONFIG_RULE_EVALUATION_ERROR`, `CONFIG_RULE_NOT_FOUND`, `INTERNAL_SERVICE_ERROR`, `THROTTLING_ERROR` | `ERROR` |
| `CONFIG_RETURNS_NOT_APPLICABLE` | `NOT_APPLICABLE` |
| No reason, or an unrecognized code | Skipped |

If a finding has several reasons, an error reason outranks a not-applicable one.

## 4. Aggregate per control

For each control ID, the status is the highest-ranked status among all its findings, across every account:

```text
FAILED  >  ERROR  >  PASSED  >  NOT_APPLICABLE
```

So one failure fails the control. With no failures, any error means the control can't be claimed as passing. A control is `NOT_APPLICABLE` only if every finding for it is.

- **Severity** is the highest severity among failing findings (`CRITICAL` > `HIGH` > `MEDIUM` > `LOW`; `INFORMATIONAL` counts as `LOW`). Errors don't raise it.
- **Accounts affected** is the number of distinct account IDs with at least one `FAILED` finding. Errors don't count.
- **RMF step** is `Assess` for `FAILED` or `ERROR`, and `Monitor` otherwise.

## 5. Score

```text
compliance % = floor( PASSED / (PASSED + FAILED + ERROR) × 100 )
```

- `NOT_APPLICABLE` controls are left out entirely.
- `ERROR` controls **count against** the score. A check that couldn't run is not evidence of compliance, and leaving it out would let permission gaps inflate the score.
- Every control counts the same. Severity and the number of affected accounts don't change the score; they're there for prioritizing.

The **Impact Level score** uses the same formula, limited to controls whose `min_impact_level` is at or below the target level.

Thresholds on the dashboard: **≥ 85%** green, **70–84%** orange, **< 70%** red. These colors are just a visual cue and don't come from any NIST or DoD source.

!!! tip "Fix ERROR rows first"
    `ERROR` usually means AWS Config can't evaluate the rule (access denied, rule missing, throttling) or the resource sits in another account or region. Fixing those gaps often raises the score more than any single remediation. The reason is in the Security Hub finding's `Compliance.StatusReasons`.

## Titles

Security Hub has no API for official NIST control titles. In live mode the title is the **Security Hub security-control title** from the first finding seen for that control (for example "S3 buckets should have server-side encryption enabled" rather than "Protection of Information at Rest"). A built-in NIST title catalog is planned.

## What this score is not

!!! warning "Read before putting the score in an ATO package"
    - It covers only controls with **automated Security Hub checks**. Many 800-53 controls are procedural (PL, PM, PS, AT…) and never appear.
    - It can't be better than your Security Hub coverage. Accounts or regions without Security Hub, or without the standard enabled, contribute nothing, so they look neither passing nor failing.
    - A control that passes here has passing *automated checks*. It isn't necessarily *implemented* in the RMF sense.

    Treat it as continuous-monitoring evidence that supports an assessment, not as the assessment itself.
