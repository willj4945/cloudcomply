# Deploying the cloudcomply assessor role

cloudcomply's native checks (see [docs/ai-controls/plan.md](../docs/ai-controls/plan.md)) call AWS APIs directly in every account and region they assess. In each account other than the one it runs from, cloudcomply assumes a read-only role, **`cloudcomply-assessor`** by default. This directory contains that role.

> **Status:** the cross-account scan engine exists, but no native check uses it yet. The role currently grants only `account:ListRegions`. Each check phase adds its own read-only actions to the template alongside the check. The `--assume-role-name` and `--regions` flags described below arrive with the first check (Phase 2). Until then, you can deploy the role now and verify it with step 4.

## Why a dedicated role

The alternative, `OrganizationAccountAccessRole`, doesn't work for this:
- It trusts only the **management** account, and cloudcomply runs from the Security Hub delegated administrator.
- It exists only in accounts *created* through Organizations, not in invited ones.
- It carries `AdministratorAccess`.

The dedicated role has exactly the read-only actions cloudcomply calls and trusts only the account cloudcomply runs from. Reviewers can read [`cloudformation/assessor-role.yaml`](cloudformation/assessor-role.yaml) to see everything the tool can touch.

## 1. Member accounts: service-managed StackSet

Run this from the **management account**, or from a CloudFormation StackSets delegated administrator. Trusted access for CloudFormation StackSets must be enabled in Organizations.

```bash
ASSESSOR_ACCOUNT=123456789012                                   # where cloudcomply runs
ASSESSOR_PRINCIPAL=arn:aws:iam::123456789012:role/SecurityAudit # role you run cloudcomply as
ROOT_OU=r-abcd                                                  # or a list of OU IDs

aws cloudformation create-stack-set \
  --stack-set-name cloudcomply-assessor \
  --template-body file://deploy/cloudformation/assessor-role.yaml \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters ParameterKey=AssessorAccountId,ParameterValue=$ASSESSOR_ACCOUNT \
               ParameterKey=AssessorPrincipalArn,ParameterValue=$ASSESSOR_PRINCIPAL

aws cloudformation create-stack-instances \
  --stack-set-name cloudcomply-assessor \
  --deployment-targets OrganizationalUnitIds=$ROOT_OU \
  --regions us-east-1          # IAM is global: deploy to ONE region only
```

- **One region only.** IAM roles are global. Stack instances in a second region would fail with a name collision.
- **Auto-deployment** puts the role into accounts that join the targeted OUs later, and removes it when they leave.
- **`AssessorPrincipalArn`** is optional but recommended. It narrows trust from "any principal in the assessor account" to the one role you run cloudcomply as.
- **GovCloud:** use `arn:aws-us-gov:…` principal ARNs and a GovCloud region. Confirm that service-managed StackSets are available in your partition; if not, deploy the same template with self-managed StackSets or as individual stacks.

## 2. Management account: regular stack

Service-managed StackSets **never deploy to the management account**. If cloudcomply should assess it, deploy the same template there as an ordinary stack:

```bash
aws cloudformation create-stack \
  --stack-name cloudcomply-assessor \
  --template-body file://deploy/cloudformation/assessor-role.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters ParameterKey=AssessorAccountId,ParameterValue=$ASSESSOR_ACCOUNT \
               ParameterKey=AssessorPrincipalArn,ParameterValue=$ASSESSOR_PRINCIPAL
```

The account cloudcomply runs from doesn't need the role: cloudcomply uses its own credentials there.

## 3. Permissions for the identity that runs cloudcomply

These permissions go on the role or user you run cloudcomply as, in the assessor account. They're in addition to the Security Hub permissions in the [README](../README.md#aws-permissions).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListOrganizationAccounts",
      "Effect": "Allow",
      "Action": "organizations:ListAccounts",
      "Resource": "*"
    },
    {
      "Sid": "AssumeAssessorRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/cloudcomply-assessor"
    },
    {
      "Sid": "DiscoverRegionsInOwnAccount",
      "Effect": "Allow",
      "Action": "account:ListRegions",
      "Resource": "*"
    }
  ]
}
```

In GovCloud, use `arn:aws-us-gov:iam::*:role/cloudcomply-assessor`. cloudcomply builds role ARNs in the caller's own partition automatically.

## 4. Verify

From the assessor account, as the identity you run cloudcomply with:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::<member-account-id>:role/cloudcomply-assessor \
  --role-session-name cloudcomply-verify
```

An account where the role is missing or untrusted doesn't stop a scan. Its checks come back as `ERROR` results naming the role ARN that couldn't be assumed, and every other account is still assessed.

## What a scan does

1. Calls `sts:GetCallerIdentity` to learn its own account and partition.
2. Calls `organizations:ListAccounts` and keeps `ACTIVE` accounts. If the caller isn't in an organization, it runs in single-account mode against its own account only.
3. For each account (its own excepted), assumes `arn:<partition>:iam::<account>:role/<role-name>`.
4. Discovers the account's enabled regions with `account:ListRegions`. `--regions` skips discovery, which is useful if region discovery is blocked or you only care about some regions.
5. Runs every check against every account × region. Concurrency is bounded and each call has its own timeout. A failure in one account or region becomes an `ERROR` result for that scope only.
