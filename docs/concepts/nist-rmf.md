# NIST SP 800-53 and the RMF

## NIST SP 800-53 Rev. 5

[NIST SP 800-53](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) is the catalog of security and privacy controls used by U.S. federal systems, FedRAMP and the DoD. Controls are grouped into families identified by two-letter prefixes.

The families that currently appear in cloudcomply (because AWS Security Hub has automated checks for them):

| Family | Name | Typical AWS evidence |
|---|---|---|
| AC | Access Control | IAM policies, S3 public access, security groups |
| AU | Audit and Accountability | CloudTrail, log file validation, log retention |
| CM | Configuration Management | AWS Config, SSM patch/inventory, default configurations |
| IA | Identification and Authentication | MFA, root account usage, access key rotation |
| SC | System and Communications Protection | Encryption at rest/in transit, VPC boundaries, KMS rotation |
| SI | System and Information Integrity | GuardDuty, Inspector, vulnerability findings |

Live data can include other families (for example `CP` for backups, or `RA`) if Security Hub maps checks to them. They show up in JSON output, though the TUI family filter currently lists only the six above.

Enhancements are shown in parentheses, e.g. `AC-2(1)`, `SC-28(1)`.

## Risk Management Framework (RMF)

[NIST SP 800-37](https://csrc.nist.gov/pubs/sp/800/37/r2/final) defines the RMF steps: **Prepare → Categorize → Select → Implement → Assess → Authorize → Monitor**.

Each cloudcomply finding carries a suggested `rmf_step`:

| Value | Meaning in cloudcomply |
|---|---|
| `Assess` | Automated checks are failing, so the control needs assessment and remediation (POA&M candidate) |
| `Monitor` | Automated checks pass, so the control stays under continuous monitoring |
| `Implement` | (Demo data) the control appears not to be implemented at all |

This tag helps with triage. It doesn't replace an assessor's determination.

## Using cloudcomply in an ATO workflow

| RMF activity | How cloudcomply helps |
|---|---|
| **Assess** (Step 5) | Export `report nist --format json` as point-in-time automated test evidence for the SAR. Failed controls feed POA&M drafting (see the [CSV recipe](../usage/json-schema.md#jq-recipes)). |
| **Authorize** (Step 6) | The family breakdown and Impact Level score summarize technical posture for the AO briefing. |
| **Monitor** (Step 7) | Scheduled runs produce a dated evidence trail for ConMon. See [scheduled evidence collection](../usage/automation.md#scheduled-evidence-collection). |

See [What this score is not](scoring.md#what-this-score-is-not) for the limits of automated evidence.
