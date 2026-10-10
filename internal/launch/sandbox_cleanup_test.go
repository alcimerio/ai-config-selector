package launch

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSandboxCleanupReportsAreSanitized(t *testing.T) {
	for _, status := range []error{errSandboxSessionCleanupRecovered, errSandboxSessionCleanupUnproven} {
		cause := errors.Join(errors.New("private Session path and process details"), fmt.Errorf("cleanup: %w", status))
		message := sandboxError(SandboxProcessWaitFailed, cause).Error()
		if !strings.Contains(message, status.Error()) || strings.Contains(message, "private Session") {
			t.Fatalf("cleanup report = %q", message)
		}
		process := sanitizedProcess{process: &stubLifecycleProcess{waitErr: errors.Join(
			errors.New("private process details"), sandboxError(SandboxProcessWaitFailed, cause),
		)}}
		message = process.Wait().Error()
		if !strings.Contains(message, status.Error()) || strings.Contains(message, "private process") {
			t.Fatalf("sanitized cleanup report = %q", message)
		}
	}
	process := sanitizedProcess{process: &stubLifecycleProcess{waitErr: &SandboxError{
		Category: SandboxProcessWaitFailed, remediation: "private process details",
	}}}
	if message := process.Wait().Error(); strings.Contains(message, "private process") {
		t.Fatalf("unrecognized cleanup report was retained: %q", message)
	}
}
