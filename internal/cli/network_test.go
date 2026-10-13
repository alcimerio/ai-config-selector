package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

func TestExplainAndDryRunReportLoopbackPortsAndDefaultDenial(t *testing.T) {
	for _, test := range []struct {
		name  string
		ports []int
	}{{"denied", nil}, {"selected", []int{8080, 1455}}} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			target, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: home})
			if err != nil {
				t.Fatal(err)
			}
			draft := target.Categories().NewDraft()
			if err := target.SetNetworkSelection(&draft, commonprofile.NetworkSelection{LoopbackPorts: test.ports}); err != nil {
				t.Fatal(err)
			}
			candidate, err := target.Categories().NewProfile(test.name, draft)
			if err != nil {
				t.Fatal(err)
			}
			store := profile.NewStore(filepath.Join(home, ".acs"), target.Categories())
			if _, err := store.Create(candidate); err != nil {
				t.Fatal(err)
			}
			for _, args := range [][]string{{"explain", "devin", "--profile", test.name, "--json"}, {"explain", "devin", "--profile", test.name}, {"devin", "--profile", test.name, "--dry-run"}} {
				var stdout, stderr bytes.Buffer
				app := cli.App{Planner: resolvedPlanner{}, Categories: target.Categories(), Profiles: store, WorkingDirectory: home, Output: &stdout, ErrorOutput: &stderr}
				if code := app.Run(context.Background(), args); code != 0 {
					t.Fatalf("args=%v code=%d error=%s", args, code, stderr.String())
				}
				output := stdout.String()
				if !strings.Contains(output, "denied") {
					t.Fatalf("missing loopback denial: %s", output)
				}
				if len(test.ports) > 0 && (!strings.Contains(output, "1455") || !strings.Contains(output, "8080")) {
					t.Fatalf("missing selected ports: %s", output)
				}
				if runtime.GOOS == "linux" && !strings.Contains(output, commonprofile.LinuxLoopbackGap) {
					t.Fatalf("missing Linux enforcement gap: %s", output)
				}
				if args[len(args)-1] == "--json" {
					var document struct {
						Plan struct {
							Effective []struct {
								ID    string
								Value struct {
									Mode  string
									Names []string
								}
							}
						}
					}
					if err := json.Unmarshal(stdout.Bytes(), &document); err != nil {
						t.Fatal(err)
					}
					found := false
					for _, fact := range document.Plan.Effective {
						if fact.ID == "runtime.network.loopback" {
							found = true
							if len(fact.Value.Names) != len(test.ports) {
								t.Fatalf("ports=%v", fact.Value.Names)
							}
						}
					}
					if !found {
						t.Fatal("loopback fact absent")
					}
				}
			}
		})
	}
}
