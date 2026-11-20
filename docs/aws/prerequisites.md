# AWS prerequisites

cloudcomply reads findings that **AWS Security Hub** has already evaluated. Before your first live run, check the following.

## 1. Security Hub is enabled

Enable Security Hub in the account and region you'll query. For organizations, use [Security Hub's Organizations integration](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-accounts-orgs.html) and designate a **delegated administrator** account, usually a dedicated Security Tooling or Audit account.

## 2. The NIST SP 800-53 Rev. 5 standard is enabled

In Security Hub → **Security standards**, enable **NIST Special Publication 800-53 Revision 5**. cloudcomply filters on exactly this standard (`standards/nist-800-53/v/5.0.0`).

If the standard is disabled, cloudcomply returns **zero findings** and a 0% score. That isn't an error; there is simply nothing to report.

With central configuration, enable the standard in a configuration policy so it applies to every member account. New standards can take up to 24 hours to produce their first findings.

## 3. Choose where to run it

| Scope you want | Run from | Region |
|---|---|---|
| Whole organization, all regions | Security Hub **delegated admin** account | The **aggregation (home) region** with [cross-region aggregation](https://docs.aws.amazon.com/securityhub/latest/userguide/finding-aggregation.html) enabled |
| Whole organization, one region | Delegated admin account | That region |
| One account | That account | Any region with Security Hub enabled |

cloudcomply queries the **one** region from your SDK configuration. Without a finding aggregator it sees only that region's findings.

## 4. Organizations access (optional)

`DescribeOrganization` and `ListAccounts` fill in the org ID and account count on the dashboard.

- If the account **isn't in an organization**, cloudcomply switches to single-account mode on its own.
- `ListAccounts` works only from the **management account** or a **delegated administrator for AWS Organizations**. A Security Hub delegated admin is *not* automatically an Organizations delegated admin. If yours isn't, the call is denied and the run fails with `fetching organization summary: … AccessDenied`. To fix it, register the account as an Organizations delegated admin with a [resource-based delegation policy](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_delegate_policies.html) that allows `organizations:ListAccounts` and `organizations:DescribeOrganization`, or run from the management account.

## 5. Credentials

Any source in the [standard SDK credential chain](https://docs.aws.amazon.com/sdkref/latest/guide/standardized-credentials.html) works: CloudShell, IAM Identity Center (SSO) profiles, `AWS_PROFILE`, instance or task roles, or web identity (OIDC). Prefer short-lived role credentials over IAM user access keys.

Check that it works first:

```bash
aws sts get-caller-identity
aws securityhub get-findings --max-items 1 \
  --filters '{"ComplianceAssociatedStandardsId":[{"Value":"standards/nist-800-53/v/5.0.0","Comparison":"EQUALS"}]}'
```

If both succeed, cloudcomply will too.

## Supported partitions

cloudcomply uses the AWS SDK's endpoint resolution, so commercial (`aws`) and GovCloud (`aws-us-gov`) partitions work by setting the region. Other isolated partitions haven't been tested.
