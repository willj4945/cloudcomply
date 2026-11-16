# How findings are scored

cloudcomply doesn't evaluate AWS resources itself. It **aggregates** the per-resource findings Security Hub produces for the NIST SP 800-53 Rev. 5 standard into one result per NIST control.

## 1. Fetch

`securityhub:GetFindings` is paged to completion with two filters:

- `ComplianceAssociatedStandardsId = standards/nist-800-53/v/5.0.0`
- `RecordState = ACTIVE` (archived findings are ignored)

## 2. Map each finding to a NIST control

Each Security Hub finding lists NIST control IDs in `Compliance.RelatedRequirements`, e.g. `NIST.800-53.r5 AC-4`. cloudcomply takes the **first** `NIST.800-53.r5` entry as the control ID and the part before the first `-` as the family.

Findings with no NIST requirement are skipped.

## 3. Map statuses

| Security Hub `Compliance.Status` | cloudcomply |
|---|---|
| `PASSED` | PASSED |
| `FAILED` | FAILED |
| `WARNING` | FAILED (conservative, since a warning isn't proof of compliance) |
| `NOT_AVAILABLE` | Skipped (can't be scored) |

## 4. Aggregate per control

For each control ID:

- **Status** is `FAILED` if **any** finding for the control failed in **any** account, and `PASSED` otherwise.
- **Severity** is the highest severity among failing findings (`CRITICAL` > `HIGH` > `MEDIUM` > `LOW`; `INFORMATIONAL` counts as `LOW`).
- **Accounts affected** is the number of distinct account IDs with at least one failing finding.
- **RMF step** is `Assess` if failing, `Monitor` if passing.

## 5. Score

```text
compliance % = floor( PASSED controls / total controls × 100 )
```

Every control counts the same. Severity and the number of affected accounts don't change the score; they're there for prioritizing.

The **Impact Level score** uses the same formula, limited to controls whose `min_impact_level` is at or below the target level.

Thresholds on the dashboard: **≥ 85%** green, **70–84%** orange, **< 70%** red. These colors are just a visual cue and don't come from any NIST or DoD source.

## Titles

Security Hub has no API for official NIST control titles. In live mode the title is the **Security Hub security-control title** from the first finding seen for that control (for example "S3 buckets should have server-side encryption enabled" rather than "Protection of Information at Rest"). A built-in NIST title catalog is planned.

## What this score is not

!!! warning "Read before putting the score in an ATO package"
    - It covers only controls with **automated Security Hub checks**. Many 800-53 controls are procedural (PL, PM, PS, AT…) and never appear.
    - It can't be better than your Security Hub coverage. Accounts or regions without Security Hub, or without the standard enabled, contribute nothing, so they look neither passing nor failing.
    - A control that passes here has passing *automated checks*. It isn't necessarily *implemented* in the RMF sense.

    Treat it as continuous-monitoring evidence that supports an assessment, not as the assessment itself.
