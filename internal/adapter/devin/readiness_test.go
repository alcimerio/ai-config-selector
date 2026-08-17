package devin

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestPlanLaunchReportsReadOnlySandboxReadinessWithoutPreparingADevinProcess(t *testing.T) {
	sandbox := &readinessSandbox{readiness: launch.SandboxReadiness{
		RequiredMode: "native",
		Backend:      "Bubblewrap",
		Platform:     "Ubuntu 24.04.3 LTS on linux/arm64",
		Supported:    true,
		Ready:        true,
	}}
	adapter, err := newAdapter(Config{BinaryPath: "devin", ExistingHomeDir: t.TempDir()}, sandbox)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	plan, err := adapter.PlanLaunch(context.Background(), t.TempDir(), resolvedEmptyProfile(t, adapter))
	if err != nil {
		t.Fatalf("plan launch: %v", err)
	}
	if sandbox.readinessCalls != 1 {
		t.Fatalf("readiness calls = %d, want 1", sandbox.readinessCalls)
	}
	if sandbox.checkCalls != 0 || sandbox.prepareCalls != 0 {
		t.Fatalf("dry run invoked sandbox launch methods: check=%d prepare=%d", sandbox.checkCalls, sandbox.prepareCalls)
	}
	if len(plan.Sections) == 0 {
		t.Fatal("plan omitted the sandbox readiness section")
	}
	section := plan.Sections[len(plan.Sections)-1]
	if got, want := section.Title, "Sandbox readiness:"; got != want {
		t.Errorf("section title = %q, want %q", got, want)
	}
	output := planSectionText(section)
	for _, want := range []string{
		"required sandbox mode: native",
		"selected native backend: Bubblewrap",
		"supported platform: supported (Ubuntu 24.04.3 LTS on linux/arm64)",
		"backend readiness: ready",
		"ACS will not start Devin without the required sandbox.",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("sandbox readiness omitted %q: %q", want, output)
		}
	}
}

func TestPlanLaunchReportsSafeUnavailableSandboxReadiness(t *testing.T) {
	sandbox := &readinessSandbox{readiness: launch.SandboxReadiness{
		RequiredMode: "native",
		Backend:      "Bubblewrap",
		Platform:     "Ubuntu 24.04 LTS on linux/amd64",
		Supported:    true,
		Failure:      &launch.SandboxError{Category: launch.SandboxBackendUnavailable},
	}}
	adapter, err := newAdapter(Config{BinaryPath: "devin", ExistingHomeDir: t.TempDir()}, sandbox)
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	plan, err := adapter.PlanLaunch(context.Background(), t.TempDir(), resolvedEmptyProfile(t, adapter))
	if err != nil {
		t.Fatalf("plan launch: %v", err)
	}
	output := planSectionText(plan.Sections[len(plan.Sections)-1])
	if !strings.Contains(output, "backend readiness: not ready (backend_unavailable:") {
		t.Errorf("unavailable backend was not reported categorically: %q", output)
	}
	if sandbox.checkCalls != 0 || sandbox.prepareCalls != 0 {
		t.Fatalf("dry run invoked sandbox launch methods: check=%d prepare=%d", sandbox.checkCalls, sandbox.prepareCalls)
	}
}

func TestPreflightErrorsUseStableRedactedCategories(t *testing.T) {
	tests := []struct {
		name       string
		capability Capability
		want       PreflightErrorCategory
	}{
		{name: "Skills", capability: CapabilitySkillIsolation, want: SkillPreflightFailed},
		{name: "authentication", capability: CapabilityAuthentication, want: AuthenticationPreflightFailed},
		{name: "unknown control characters", capability: "private\n\x1b", want: DevinPreflightFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := &PreflightError{Capability: test.capability, reason: reasonVerificationInterrupted}
			if got := err.Category(); got != test.want {
				t.Errorf("category = %q, want %q", got, test.want)
			}
			if !strings.HasPrefix(err.Error(), string(test.want)+":") {
				t.Errorf("error omits stable category %q: %q", test.want, err)
			}
			if strings.ContainsAny(err.Error(), "\n\r\x1b") || strings.Contains(err.Error(), "private") {
				t.Errorf("preflight error exposed untrusted capability text: %q", err)
			}
		})
	}
}

func TestDevinExitErrorPreservesAnActionableStableCategoryWithoutTargetOutput(t *testing.T) {
	err := &DevinExitError{Code: 23}
	if got, want := err.ExitCode(), 23; got != want {
		t.Errorf("exit code = %d, want %d", got, want)
	}
	if got, want := err.Error(), "devin_exited: Devin exited with status 23; inspect the attached Devin terminal output"; got != want {
		t.Errorf("diagnostic = %q, want %q", got, want)
	}
	for _, private := range []string{"PRIVATE_DEVIN_OUTPUT", "\n", "\x1b"} {
		if strings.Contains(err.Error(), private) {
			t.Errorf("Devin exit diagnostic leaked %q: %q", private, err)
		}
	}
}

func TestSanitizeLaunchErrorRedactsUntrustedPreparationDetails(t *testing.T) {
	private := errors.New("prepare /private/home/alice/.acs/session token=PRIVATE_TOKEN\n\x1b[31m")
	err := sanitizeLaunchError(private)
	var sandboxFailure *launch.SandboxError
	if !errors.As(err, &sandboxFailure) || sandboxFailure.Category != launch.SandboxSetupFailed {
		t.Fatalf("sanitized error = %v, want setup_failed", err)
	}
	for _, leaked := range []string{"/private/home", "PRIVATE_TOKEN", "\n", "\x1b"} {
		if strings.Contains(err.Error(), leaked) {
			t.Errorf("sanitized error leaked %q: %q", leaked, err)
		}
	}
}

type readinessSandbox struct {
	readiness      launch.SandboxReadiness
	readinessErr   error
	readinessCalls int
	checkCalls     int
	prepareCalls   int
}

func (sandbox *readinessSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	sandbox.readinessCalls++
	return sandbox.readiness, sandbox.readinessErr
}

func (sandbox *readinessSandbox) Check(context.Context, launch.SandboxCheck) error {
	sandbox.checkCalls++
	return errors.New("unexpected launch check")
}

func (sandbox *readinessSandbox) Prepare(context.Context, launch.ProcessRequest) (launch.Process, error) {
	sandbox.prepareCalls++
	return nil, errors.New("unexpected process preparation")
}

func resolvedEmptyProfile(t *testing.T, adapter *Adapter) category.ResolvedProfile {
	t.Helper()
	resolved, err := adapter.Categories().Resolve(context.Background(), NewSkillsProfile("readiness", nil))
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func planSectionText(section launch.PlanSection) string {
	items := make([]string, 0, len(section.Items))
	for _, item := range section.Items {
		items = append(items, item.Label)
	}
	return strings.Join(items, "\n")
}
