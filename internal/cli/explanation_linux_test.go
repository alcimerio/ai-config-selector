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
		code := app.Run(context.Background(), args)
		text := output.String()
		if strings.Contains(text, "backend_ready") {
			if code != 0 {
				t.Fatalf("ready Linux explain exit = %d, stderr = %s", code, stderr.String())
			}
			continue
		}
		if code != 1 || !strings.Contains(text, "ACS will not start the requested process without the required sandbox") {
			t.Fatalf("unready Linux explain = %d %q", code, text)
		}
	}
}
