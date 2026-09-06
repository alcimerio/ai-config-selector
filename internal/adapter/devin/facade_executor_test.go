package devin

import (
	"context"
	"errors"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"github.com/alcimerio/ai-config-selector/internal/executor"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"strings"
	"testing"
)

type resultExecutor struct {
	code int
	err  error
}

func (r resultExecutor) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return launch.SandboxReadiness{}, nil
}
func (r resultExecutor) RunDevin(context.Context, executor.DevinRequest) (int, error) {
	return r.code, r.err
}

type fixtureTargetExit int

func (e fixtureTargetExit) Error() string { return "PRIVATE_TARGET_OUTPUT" }
func (e fixtureTargetExit) ExitCode() int { return int(e) }

func TestLaunchPreservesExecutorErrorIdentityAndRedactsPrivateDetails(t *testing.T) {
	tests := []struct {
		name     string
		result   resultExecutor
		category PreflightErrorCategory
		sandbox  launch.SandboxErrorCategory
		exit     bool
	}{
		{name: "skills", result: resultExecutor{1, devinruntime.NewPreflightError(devinruntime.CapabilitySkillIsolation, devinruntime.ReasonCatalogMismatch)}, category: SkillPreflightFailed},
		{name: "authentication", result: resultExecutor{1, devinruntime.NewPreflightError(devinruntime.CapabilityAuthentication, devinruntime.ReasonAuthenticationUnavailable)}, category: AuthenticationPreflightFailed},
		{name: "cleanup outranks preflight", result: resultExecutor{1, errors.Join(devinruntime.NewPreflightError(devinruntime.CapabilityAuthentication, devinruntime.ReasonAuthenticationUnavailable), &launch.SandboxError{Category: launch.SandboxProcessWaitFailed})}, sandbox: launch.SandboxProcessWaitFailed},
		{name: "ordinary target exit", result: resultExecutor{23, fixtureTargetExit(23)}, exit: true},
		{name: "private infrastructure failure", result: resultExecutor{1, errors.New("PRIVATE_TOKEN /private/session\n\x1b")}, sandbox: launch.SandboxSetupFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter := &Adapter{executor: test.result}
			code, err := adapter.Launch(context.Background(), "unused-sessions", "unused-workspace", category.ResolvedProfile{}, launch.Terminal{})
			if code != test.result.code || err == nil {
				t.Fatalf("result = (%d, %v)", code, err)
			}
			if test.category != "" {
				var value *PreflightError
				if !errors.As(err, &value) || value.Category() != test.category {
					t.Fatalf("public preflight identity lost: %v", err)
				}
			}
			if test.sandbox != "" {
				var value *launch.SandboxError
				if !errors.As(err, &value) || value.Category != test.sandbox {
					t.Fatalf("sandbox precedence lost: %v", err)
				}
			}
			if test.exit {
				var value *DevinExitError
				if !errors.As(err, &value) || value.ExitCode() != 23 {
					t.Fatalf("target exit lost: %v", err)
				}
			}
			for _, private := range []string{"PRIVATE_", "/private/session", "\n", "\x1b"} {
				if strings.Contains(err.Error(), private) {
					t.Fatalf("private detail leaked: %q", err.Error())
				}
			}
		})
	}
}
