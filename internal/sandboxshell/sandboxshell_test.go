package sandboxshell

import (
	"errors"
	"os/exec"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestShellResultPreservesOrdinaryShellExit(t *testing.T) {
	err := exec.Command("/bin/sh", "-c", "exit 23").Run()
	if err == nil {
		t.Fatal("exit fixture unexpectedly succeeded")
	}
	code, result := shellResult(err)
	var targetExit *ExitError
	if code != 23 || !errors.As(result, &targetExit) || targetExit.ExitCode() != 23 {
		t.Fatalf("shell result = code %d error %v", code, result)
	}
}

func TestShellResultReportsInfrastructureFailure(t *testing.T) {
	code, err := shellResult(&launch.SandboxError{Category: launch.SandboxProcessWaitFailed})
	var sandboxErr *launch.SandboxError
	if code != 1 || !errors.As(err, &sandboxErr) || sandboxErr.Category != launch.SandboxProcessWaitFailed {
		t.Fatalf("shell result = code %d error %v", code, err)
	}
}
