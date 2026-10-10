package cli_test

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/executor"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

func TestExplainLinuxReadinessIncludesUnsupportedBackendGuidance(t *testing.T) {
	home := t.TempDir()
	target, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	store := profile.NewStore(filepath.Join(home, ".acs"), target.Categories())
	candidate, err := target.Categories().NewProfile("example", target.Categories().NewDraft())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Create(candidate); err != nil {
		t.Fatal(err)
	}
	for _, jsonOutput := range []bool{false, true} {
		var output, stderr bytes.Buffer
		app := cli.App{Categories: target.Categories(), Profiles: store, NativeReadiness: executor.New(),
			WorkingDirectory: home, Output: &output, ErrorOutput: &stderr}
		args := []string{"explain", "devin", "--profile", "example", "--check-native-readiness"}
		if jsonOutput {
			args = append(args, "--json")
		}
		if code := app.Run(context.Background(), args); code != 1 {
			t.Fatalf("explain exit = %d, stderr = %s", code, stderr.String())
		}
		for _, want := range []string{"Linux sandbox backend is not available yet", "ACS never runs targets unsandboxed", "docs/design/linux-support.md"} {
			if !strings.Contains(output.String(), want) {
				t.Errorf("explanation output %q does not contain %q", output.String(), want)
			}
		}
	}
}
