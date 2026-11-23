package awsclient

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/aws/smithy-go"
)

// loadFixture unmarshals testdata/<path> into an SDK output struct. SDK
// structs carry no json tags, so fixtures use the API's own PascalCase field
// names, which encoding/json matches. Fixtures are recorded API responses
// with account IDs, ARNs and emails scrubbed to example values. Fakes that
// implement SDK interfaces have no *testing.T, so a bad fixture panics,
// which still fails the test loudly.
func loadFixture(path string, out any) {
	b, err := os.ReadFile(filepath.Join("testdata", path))
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		panic(fmt.Sprintf("decoding fixture %s: %v", path, err))
	}
}

// apiError builds the error an SDK call returns when the service rejects it,
// wrapped the way the SDK wraps it, e.g.
// apiError("Bedrock", "ListGuardrails", "AccessDeniedException").
func apiError(service, operation, code string) error {
	return apiErrorMessage(service, operation, code, "simulated")
}

// apiErrorMessage is apiError with the service's message, for tests that
// depend on it (e.g. AWS naming an SCP as the source of a denial).
func apiErrorMessage(service, operation, code, message string) error {
	return &smithy.OperationError{
		ServiceID:     service,
		OperationName: operation,
		Err:           &smithy.GenericAPIError{Code: code, Message: message},
	}
}
