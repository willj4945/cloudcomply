package awsclient

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/willj4945/cloudcomply/internal/nist"
)

// GetOrgSummary fetches the org identifier and total account count.
// AWS Organizations has no "display name" concept for an organization, so
// the org's ID (e.g. "o-abc123xyz") is used in place of demo mode's
// fabricated "Acme Federal Org" name.
//
// Credentials that aren't part of an Organization at all (a standalone
// account, or org access still pending approval) fall back to
// singleAccountSummary rather than failing the whole fetch — org-wide
// access is frequently gated behind separate bureaucracy from Security Hub
// access, and cloudcomply should still be useful against the one account
// you can already reach.
func (c *Client) GetOrgSummary(ctx context.Context) (nist.OrgSummary, error) {
	desc, err := c.org.DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{})
	if err != nil {
		var notInOrg *orgtypes.AWSOrganizationsNotInUseException
		if errors.As(err, &notInOrg) {
			return c.singleAccountSummary(ctx)
		}
		return nist.OrgSummary{}, fmt.Errorf("describe organization: %w", err)
	}

	var count int
	p := organizations.NewListAccountsPaginator(c.org, &organizations.ListAccountsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nist.OrgSummary{}, fmt.Errorf("list accounts: %w", err)
		}
		count += len(page.Accounts)
	}

	return nist.OrgSummary{
		Name:         aws.ToString(desc.Organization.Id),
		AccountCount: count,
		IsOrgMode:    true,
	}, nil
}

// singleAccountSummary scores exactly one account — the one the current
// credentials belong to — using its account ID in place of an org ID.
func (c *Client) singleAccountSummary(ctx context.Context) (nist.OrgSummary, error) {
	out, err := c.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nist.OrgSummary{}, fmt.Errorf("get caller identity: %w", err)
	}
	return nist.OrgSummary{
		Name:         aws.ToString(out.Account),
		AccountCount: 1,
		IsOrgMode:    false,
	}, nil
}
