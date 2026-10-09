package devin

import (
	"context"
	"errors"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/executor"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestPlanLaunchReportsReadOnlySandboxReadinessWithoutPreparingADevinProcess(t *testing.T) {
	sandbox := &readinessSandbox{readiness: launch.SandboxReadiness{
		RequiredMode: "native",
		Backend:      "Seatbelt",
		Platform:     "macOS 26.3 on darwin/arm64",
		Supported:    true,
		Ready:        true,
	}}
	adapter, err := newAdapter(Config{BinaryPath: "devin", ExistingHomeDir: t.TempDir()})
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	adapter.executor = sandbox
	plan, err := adapter.PlanLaunch(context.Background(), filepath.Join(t.TempDir(), "sessions"), t.TempDir(), resolvedEmptyProfile(t, adapter))
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
		"selected native backend: Seatbelt",
		"supported platform: supported (macOS 26.3 on darwin/arm64)",
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
		Backend:      "Seatbelt",
		Platform:     "macOS 26 on darwin/arm64",
		Supported:    true,
		Failure:      &launch.SandboxError{Category: launch.SandboxBackendUnavailable},
	}}
	adapter, err := newAdapter(Config{BinaryPath: "devin", ExistingHomeDir: t.TempDir()})
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}
	adapter.executor = sandbox
	plan, err := adapter.PlanLaunch(context.Background(), filepath.Join(t.TempDir(), "sessions"), t.TempDir(), resolvedEmptyProfile(t, adapter))
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

func (sandbox *readinessSandbox) RunDevin(context.Context, executor.DevinRequest) (int, error) {
	sandbox.prepareCalls++
	return 1, errors.New("unexpected process execution")
}

func TestPlanLaunchLabelsExcludedProjectSkills(t *testing.T) {
	home, workspace := t.TempDir(), t.TempDir()
	for _, name := range []string{"hidden", "permitted"} {
		path := filepath.Join(workspace, ".agents", "skills", name)
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "SKILL.md"), []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	adapter, err := newAdapter(Config{BinaryPath: "devin", ExistingHomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	sandbox := &readinessSandbox{}
	adapter.executor = sandbox
	candidate := NewSkillsProfile("preview", nil)
	encoded, err := commonprofile.EncodeExclusionSelection(commonprofile.ExclusionSelection{Entries: []commonprofile.ExclusionEntry{{ID: "hidden", Type: "directory", Reference: commonprofile.ExclusionReference{Kind: "workspace-relative", Path: ".agents/skills/hidden"}}}})
	if err != nil {
		t.Fatal(err)
	}
	candidate.Common["exclusions"] = profile.CommonPayload{Version: 1, Selection: encoded}
	resolved, err := adapter.Categories().Resolve(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := adapter.PlanLaunch(context.Background(), filepath.Join(home, ".acs", "sessions"), workspace, resolved)
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	for _, section := range plan.Sections {
		text.WriteString(section.Title)
		text.WriteString(planSectionText(section))
	}
	if !strings.Contains(text.String(), "hidden [excluded by Profile]") || !strings.Contains(text.String(), "permitted ") {
		t.Fatalf("plan=%s", text.String())
	}
	if sandbox.checkCalls != 0 || sandbox.prepareCalls != 0 {
		t.Fatal("planning started target")
	}
}

// The planner must check exclusion conflicts against the Sessions directory
// the launch request uses, not a home-derived default.
func TestPlanLaunchChecksExclusionConflictsAgainstRequestedSessionsDirectory(t *testing.T) {
	home, workspace := t.TempDir(), t.TempDir()
	adapter, err := newAdapter(Config{BinaryPath: "devin", ExistingHomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	sandbox := &readinessSandbox{}
	adapter.executor = sandbox
	candidate := NewSkillsProfile("preview", nil)
	encoded, err := commonprofile.EncodeExclusionSelection(commonprofile.ExclusionSelection{Entries: []commonprofile.ExclusionEntry{{ID: "state", Type: "directory", Reference: commonprofile.ExclusionReference{Kind: "workspace-relative", Path: "custom-sessions"}}}})
	if err != nil {
		t.Fatal(err)
	}
	candidate.Common["exclusions"] = profile.CommonPayload{Version: 1, Selection: encoded}
	resolved, err := adapter.Categories().Resolve(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}

	custom := filepath.Join(workspace, "custom-sessions")
	if _, err := adapter.PlanLaunch(context.Background(), custom, workspace, resolved); err == nil || !strings.Contains(err.Error(), "conflicts with required Session state") {
		t.Fatalf("non-default Sessions directory conflict was not detected: %v", err)
	}
	// The home-derived default does not overlap the excluded path, so the same
	// Profile plans when Sessions live there.
	if _, err := adapter.PlanLaunch(context.Background(), filepath.Join(home, ".acs", "sessions"), workspace, resolved); err != nil {
		t.Fatalf("default Sessions directory plan: %v", err)
	}
	if sandbox.checkCalls != 0 || sandbox.prepareCalls != 0 {
		t.Fatal("planning started target")
	}
}

// Profiles that already contain redundant exclusions keep resolving and
// planning; the dry run reports them as warnings instead of rejecting them.
func TestPlanLaunchWarnsAboutRedundantExclusionsWithoutRejectingProfile(t *testing.T) {
	home, workspace := t.TempDir(), t.TempDir()
	adapter, err := newAdapter(Config{BinaryPath: "devin", ExistingHomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	adapter.executor = &readinessSandbox{}
	candidate := NewSkillsProfile("redundant", nil)
	// Stored bytes bypass the editor, as an existing Profile on disk would.
	candidate.Common["exclusions"] = profile.CommonPayload{Version: 1, Selection: []byte(`{"entries":[{"id":"data","type":"directory","reference":{"kind":"workspace-relative","path":"data"}},{"id":"data-cache","type":"directory","reference":{"kind":"workspace-relative","path":"data/cache"}},{"id":"data-upper","type":"directory","reference":{"kind":"workspace-relative","path":"Data"}}]}`)}
	resolved, err := adapter.Categories().Resolve(context.Background(), candidate)
	if err != nil {
		t.Fatalf("existing redundant Profile rejected: %v", err)
	}
	plan, err := adapter.PlanLaunch(context.Background(), filepath.Join(home, ".acs", "sessions"), workspace, resolved)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	var warnings []string
	for _, section := range plan.Sections {
		if section.Title == commonprofile.ExclusionWarningsTitle {
			for _, item := range section.Items {
				warnings = append(warnings, item.Label)
			}
		}
	}
	want := []string{
		`exclusion "data-cache" is redundant: directory exclusion "data" already covers its path`,
		`exclusions "data" and "data-upper" differ only by letter case and name the same path on case-insensitive macOS volumes`,
		`exclusion "data-cache" is redundant: directory exclusion "data-upper" already covers its path`,
	}
	if strings.Join(warnings, "\n") != strings.Join(want, "\n") {
		t.Fatalf("warnings:\n%s", strings.Join(warnings, "\n"))
	}
}
