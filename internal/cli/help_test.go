package cli_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

func TestContextualHelpWithoutRuntime(t *testing.T) {
	for _, command := range []string{"", "profile", "profile list", "profile show", "devin", "devin create-profile", "sandbox", "codex", "codex auth", "codex auth login", "codex auth list", "codex auth status", "codex auth recover", "codex auth logout", "version"} {
		for _, args := range [][]string{strings.Fields("help " + command), strings.Fields(command + " --help")} {
			t.Run(strings.Join(args, " "), func(t *testing.T) {
				var out, errOut bytes.Buffer
				// No runtime dependencies: any attempted dispatch would panic or fail.
				app := cli.App{Output: &out, ErrorOutput: &errOut, Interactive: func(io.Reader, io.Writer) bool { t.Fatal("help checked terminal"); return false }}
				if code := app.Run(context.Background(), args); code != 0 || errOut.Len() != 0 {
					t.Fatalf("code=%d stderr=%q", code, errOut.String())
				}
				for _, want := range []string{"Usage:", "acs " + command, "Examples:", "--help"} {
					if !strings.Contains(out.String(), want) {
						t.Errorf("help missing %q: %s", want, &out)
					}
				}
			})
		}
	}
}

func TestContextualUsageErrorsDoNotEchoValues(t *testing.T) {
	for _, tc := range []struct{ args, want, help string }{
		{"devni", "devni", "acs help"},
		{"devin create-profil", "create-profil", "acs devin --help"},
		{"codex auth logni", "logni", "acs codex auth --help"},
		{"devin --profile private-value --backend=secret-value", "--backend", "acs devin --help"},
		{"sandbox --profile private-value --dry-run --dry-run", "--dry-run", "acs sandbox --help"},
		{"devin --profile --dry-run", "--profile", "acs devin --help"},
		{"codex auth login --device-auth --name", "--name", "acs codex auth login --help"},
		{"devin --profile private-value secret-value", "positional", "acs devin --help"},
		{"devin --profile=secret-value", "--profile", "acs devin --help"},
		{"sandbox --profile private-value -- secret-value", "--", "acs sandbox --help"},
		{"devin --help --unknown=secret-value", "--unknown", "acs devin --help"},
	} {
		t.Run(tc.args, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := (cli.App{Output: &out, ErrorOutput: &errOut}).Run(context.Background(), strings.Fields(tc.args))
			if code != 1 || out.Len() != 0 {
				t.Fatalf("code=%d stdout=%q", code, &out)
			}
			for _, want := range []string{tc.want, tc.help} {
				if !strings.Contains(errOut.String(), want) {
					t.Errorf("missing %q: %s", want, &errOut)
				}
			}
			for _, secret := range []string{"private-value", "secret-value"} {
				if strings.Contains(errOut.String(), secret) {
					t.Fatalf("disclosed value: %s", &errOut)
				}
			}
		})
	}
}

func TestLoginFlagsCanBeReordered(t *testing.T) {
	var out, errOut bytes.Buffer
	registry := &recordingCodexAuthRegistry{}
	app := cli.App{CodexAuth: registry, Output: &out, ErrorOutput: &errOut, Interactive: func(io.Reader, io.Writer) bool { return true }}
	if code := app.Run(context.Background(), strings.Fields("codex auth login --device-auth --name work")); code != 0 {
		t.Fatalf("code=%d: %s", code, &errOut)
	}
	if registry.loginCalls != 1 || registry.loginRequest.Name != "work" || !registry.loginRequest.DeviceAuth {
		t.Fatalf("incorrect dispatch: %#v", registry)
	}
}

func TestLaunchFlagPermutationsDispatchOnlyThePlanner(t *testing.T) {
	for _, target := range []string{"devin", "sandbox"} {
		for _, flags := range []string{"--profile reviews --dry-run", "--dry-run --profile reviews"} {
			t.Run(target+" "+flags, func(t *testing.T) {
				adapter, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: t.TempDir()})
				if err != nil {
					t.Fatal(err)
				}
				store := profile.NewStore(t.TempDir(), adapter.Categories())
				if _, err := store.Create(devin.NewSkillsProfile("reviews", nil)); err != nil {
					t.Fatal(err)
				}
				var out, errOut bytes.Buffer
				app := cli.App{Profiles: store, Categories: adapter.Categories(), Planner: resolvedPlanner{}, SandboxPlanner: resolvedPlanner{}, Output: &out, ErrorOutput: &errOut}
				if code := app.Run(context.Background(), strings.Fields(target+" "+flags)); code != 0 {
					t.Fatalf("code=%d: %s", code, &errOut)
				}
				if !strings.Contains(out.String(), `Dry run for Profile "reviews"`) || errOut.Len() != 0 {
					t.Fatalf("stdout=%q stderr=%q", &out, &errOut)
				}
			})
		}
	}
}

func TestUnknownExplicitHelpPathIdentifiesCommandSafely(t *testing.T) {
	for _, path := range []string{"sandbox", "devin create-profile", "codex auth login"} {
		for _, word := range []string{"typo", "private/path", "typo\x1b[31m"} {
			t.Run(path+"/"+word, func(t *testing.T) {
				var out, errOut bytes.Buffer
				args := append(strings.Fields("help "+path), word)
				code := (cli.App{Output: &out, ErrorOutput: &errOut}).Run(context.Background(), args)
				if code != 1 || out.Len() != 0 {
					t.Fatalf("code=%d stdout=%q", code, &out)
				}
				want := `unknown command "typo"`
				if word != "typo" {
					want = "unknown command (unrecognized spelling)"
				}
				if !strings.Contains(errOut.String(), want) || !strings.Contains(errOut.String(), "acs "+path+" --help") {
					t.Fatalf("stderr=%q", &errOut)
				}
				if word != "typo" && strings.Contains(errOut.String(), word) {
					t.Fatal("unsafe command spelling was echoed")
				}
			})
		}
	}
}
