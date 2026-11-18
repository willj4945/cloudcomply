# IAM permissions

cloudcomply is **read-only**. It never creates, modifies or deletes AWS resources, and it never changes the workflow status of Security Hub findings.

## Minimal policy

These are the only API actions cloudcomply calls today:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudcomplyReadSecurityHub",
      "Effect": "Allow",
      "Action": "securityhub:GetFindings",
      "Resource": "*"
    },
    {
      "Sid": "CloudcomplyReadOrganization",
      "Effect": "Allow",
      "Action": [
        "organizations:DescribeOrganization",
        "organizations:ListAccounts"
      ],
      "Resource": "*"
    }
  ]
}
```

`sts:GetCallerIdentity` doesn't need to be granted. AWS allows it for every principal and it can't be denied by IAM policy.

| Action | Used for |
|---|---|
| `securityhub:GetFindings` | Paging through active findings for the NIST SP 800-53 Rev. 5 standard |
| `organizations:DescribeOrganization` | Organization ID, and detecting single-account mode |
| `organizations:ListAccounts` | Account count on the dashboard |
| `sts:GetCallerIdentity` | Failing fast with a clear error when credentials are missing or invalid, and finding the account ID in single-account mode |

!!! note "Single-account only?"
    If you'll only ever run in a standalone account, you can drop the Organizations statement. cloudcomply falls back on its own when `DescribeOrganization` returns `AWSOrganizationsNotInUseException`. In an account that *is* in an organization, though, a denied Organizations call is an error.

## Using AWS managed policies

If you'd rather not maintain a custom policy, `arn:aws:iam::aws:policy/AWSSecurityHubReadOnlyAccess` plus `arn:aws:iam::aws:policy/AWSOrganizationsReadOnlyAccess` covers everything. Both grant far more read access than cloudcomply needs, so the custom policy above is the least-privilege choice.

## Example: dedicated role in the delegated admin account

```bash
aws iam create-role --role-name cloudcomply-readonly \
  --assume-role-policy-document file://trust.json
aws iam put-role-policy --role-name cloudcomply-readonly \
  --policy-name cloudcomply --policy-document file://cloudcomply-policy.json
```

`trust.json` should only let the specific principals that will run cloudcomply assume the role, for example an IAM Identity Center permission set role or a GitHub OIDC subject scoped to one repository and branch. See [CI/CD and automation](../usage/automation.md#github-actions-oidc-no-long-lived-keys).

## Service control policies

If an SCP denies `securityhub:GetFindings` or Organizations reads in the delegated admin account, cloudcomply fails with an `AccessDenied` error that names the action. cloudcomply needs no write permissions, so it works under the strictest "deny all writes" guardrails.

## Planned permissions

Future features will need more read access. These permissions will be documented here before they're required:

- Native AI workload checks (Bedrock / SageMaker `Get*`/`List*`, CloudTrail `GetEventSelectors`)
- Cross-account checks (`sts:AssumeRole` into a read-only role in member accounts)
- Writing results to S3 (`s3:PutObject` on a dedicated bucket, scheduled-Lambda deployments only)
