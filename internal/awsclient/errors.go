package awsclient

import (
	"errors"
	"fmt"
	"net"
	"regexp"

	"github.com/aws/smithy-go"

	"cloudcomply/internal/crosswalk"
	"cloudcomply/internal/nist"
)

var regionRe = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-\d+$`)

// lookupMapping is a seam so tests can supply mappings for fake checks while
// the real crosswalk table is still empty.
var lookupMapping = crosswalk.Lookup

var accessDeniedCodes = map[string]bool{
	"AccessDenied":          true,
	"AccessDeniedException": true,
	"UnauthorizedOperation": true,
	"AuthorizationError":    true,
}

// ClassifyError maps a collector's AWS call error to a result status and a
// detail naming the failed action. Access denied names the IAM action so the
// operator knows exactly what to grant. A region with no endpoint for the
// service is NOT_APPLICABLE: there is nothing there to assess. Everything
// else is ERROR — never PASSED.
func ClassifyError(err error) (nist.FindingStatus, string) {
	action := "AWS call"
	var opErr *smithy.OperationError
	if errors.As(err, &opErr) {
		action = fmt.Sprintf("%s:%s", opErr.Service(), opErr.Operation())
	}

	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && accessDeniedCodes[apiErr.ErrorCode()] {
		return nist.StatusError, fmt.Sprintf("access denied: %s (%s)", action, apiErr.ErrorCode())
	}
	// No DNS record for the regional endpoint is how an SDK call to a
	// service that doesn't exist in that region fails.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return nist.StatusNotApplicable, fmt.Sprintf("%s: service not available in this region", action)
	}
	return nist.StatusError, fmt.Sprintf("%s failed: %v", action, err)
}

// ResultsForError builds one result per check for a call that failed for
// all of them, classified by ClassifyError.
func ResultsForError(checkIDs []string, t Target, err error) []nist.CheckResult {
	status, detail := ClassifyError(err)
	return ResultsForStatus(checkIDs, t, status, detail)
}

// ResultsForStatus builds one result per check with the given status,
// filling controls and impact level from the crosswalk so the result rolls
// up under the right NIST controls.
func ResultsForStatus(checkIDs []string, t Target, status nist.FindingStatus, detail string) []nist.CheckResult {
	out := make([]nist.CheckResult, 0, len(checkIDs))
	for _, id := range checkIDs {
		m, _ := lookupMapping(id)
		out = append(out, nist.CheckResult{
			CheckID:        id,
			Title:          id,
			Controls:       m.NIST80053,
			Status:         status,
			Severity:       nist.SeverityMedium,
			Account:        t.Account,
			Region:         t.Region,
			Detail:         detail,
			MinImpactLevel: m.MinImpactLevel,
		})
	}
	return out
}
