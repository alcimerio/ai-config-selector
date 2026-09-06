package genericrun

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/executor"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

type recordingExecutor struct {
	readinessCalls, runCalls int
	request                  executor.CommandRequest
}

func (fake *recordingExecutor) Readiness(context.Context) (launch.SandboxReadiness, error) {
	fake.readinessCalls++
	return launch.SandboxReadiness{RequiredMode: "native", Backend: "Seatbelt", Platform: "sanitized", Supported: true, Ready: true}, nil
}
func (fake *recordingExecutor) RunCommand(_ context.Context, request executor.CommandRequest) (int, error) {
	fake.runCalls++
	fake.request = request
	return 0, nil
}

type pathContribution string

func (value pathContribution) Plan(_ context.Context, _ string, plan *launch.Plan) error {
	plan.Sections = append(plan.Sections, launch.PlanSection{Title: "Legacy:", Items: []launch.PlanItem{{Label: "source", Details: []launch.PlanDetail{{Label: "path", Value: string(value)}}}}})
	return nil
}
func (pathContribution) Materialize(string) error                                 { return nil }
func (pathContribution) Verify(context.Context, launch.VerificationContext) error { return nil }

func TestPlanLaunchValidatesButHidesExecutableArgumentsAndLegacyPaths(t *testing.T) {
	privatePath := filepath.Join(t.TempDir(), "private-skill")
	resolved := authority.New([]authority.Contribution{{ID: "test", Value: pathContribution(privatePath)}}, launch.WorkspaceAccessReadOnly, 2, "")
	fake := &recordingExecutor{}
	target := &Target{executor: fake}
	plan, err := target.PlanLaunch(context.Background(), t.TempDir(), resolved, []string{"/usr/bin/true", "private-value", ""})
	if err != nil {
		t.Fatal(err)
	}
	var rendered strings.Builder
	for _, section := range plan.Sections {
		for _, item := range section.Items {
			rendered.WriteString(item.Label)
			for _, detail := range item.Details {
				rendered.WriteString(detail.Value)
			}
		}
	}
	if strings.Contains(rendered.String(), privatePath) || strings.Contains(rendered.String(), "/usr/bin/true") || strings.Contains(rendered.String(), "private-value") {
		t.Fatalf("plan leaked private input: %s", rendered.String())
	}
	for _, marker := range []string{"(validated path hidden)", "2 (values hidden)", "none"} {
		if !strings.Contains(rendered.String(), marker) {
			t.Fatalf("plan omitted %q: %s", marker, rendered.String())
		}
	}
	if fake.readinessCalls != 1 || fake.runCalls != 0 {
		t.Fatalf("calls readiness=%d run=%d", fake.readinessCalls, fake.runCalls)
	}
}

func TestLaunchSanitizesResolverFailure(t *testing.T) {
	target := &Target{executor: &recordingExecutor{}}
	resolved := authority.New(nil, launch.WorkspaceAccessReadOnly, 3, "")
	_, err := target.Launch(context.Background(), "sessions", t.TempDir(), resolved, []string{"./missing"}, launch.Terminal{})
	var failure *launch.SandboxError
	if !errors.As(err, &failure) || failure.Category != launch.SandboxSetupFailed {
		t.Fatalf("error = %T %v", err, err)
	}
}
