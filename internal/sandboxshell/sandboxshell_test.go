package sandboxshell

import (
	"errors"
	"fmt"
	"os/exec"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/executor"
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

func TestShellResultReturnsCanonicalEnvironmentFailures(t *testing.T) {
	for _, expected := range []error{
		executor.ErrEnvironmentUnavailable,
		executor.ErrEnvironmentInvalid,
		executor.ErrEnvironmentTooLarge,
	} {
		t.Run(expected.Error(), func(t *testing.T) {
			private := fmt.Errorf("resolve /private/home/profile.json value=PRIVATE_ENV\n\x1b[31m: %w", expected)
			code, err := shellResult(private)
			if code != 1 || err != expected || err.Error() != expected.Error() {
				t.Fatalf("shell result = (%d, %q), want canonical environment failure %q", code, err, expected)
			}
		})
	}
}

func TestShellResultKeepsSandboxFailureAheadOfEnvironmentFailure(t *testing.T) {
	privateEnvironment := fmt.Errorf("private /private/home PRIVATE_ENV: %w", executor.ErrEnvironmentUnavailable)
	waitFailure := &launch.SandboxError{Category: launch.SandboxProcessWaitFailed}
	code, err := shellResult(errors.Join(privateEnvironment, waitFailure))
	var got *launch.SandboxError
	if code != 1 || err != waitFailure || !errors.As(err, &got) || got.Category != launch.SandboxProcessWaitFailed {
		t.Fatalf("shell result lost sandbox failure precedence: (%d, %v)", code, err)
	}
}
