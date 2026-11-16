// Package awsclient wraps live AWS Security Hub and Organizations calls,
// mapping results into the same internal/nist types the demo data path uses.
// This is the only package that imports the AWS SDK — internal/tui and
// internal/report never need to know whether findings came from here or
// from internal/nist.DemoFindings().
package awsclient

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type Client struct {
	cfg aws.Config
	sh  *securityhub.Client
	org *organizations.Client
	sts *sts.Client
}

// New builds a Client from the ambient AWS config (CloudShell instance
// role, environment variables, SSO, or ~/.aws/credentials) — no credential
// material is ever hardcoded or read directly by this package.
func New(ctx context.Context) (*Client, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}
	return &Client{
		cfg: cfg,
		sh:  securityhub.NewFromConfig(cfg),
		org: organizations.NewFromConfig(cfg),
		sts: sts.NewFromConfig(cfg),
	}, nil
}

// WhoAmI validates that credentials exist and are usable, so callers can
// fail fast with a clear message before hitting Security Hub/Organizations,
// whose own errors on bad credentials are less obviously actionable.
func (c *Client) WhoAmI(ctx context.Context) (string, error) {
	out, err := c.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", err
	}
	return aws.ToString(out.Arn), nil
}
