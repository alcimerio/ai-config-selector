package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	codexadapter "github.com/alcimerio/ai-config-selector/internal/adapter/codex"
	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

type explanationReadiness struct{ calls int }

func (probe *explanationReadiness) Readiness(context.Context) (launch.SandboxReadiness, error) {
	probe.calls++
	return launch.SandboxReadiness{RequiredMode: "native", Backend: "Seatbelt", Platform: "macOS 26 on darwin/arm64", Supported: true, Ready: true}, nil
}

func TestExplainJSONUsesResolvedAuthorityWithoutNativeProbe(t *testing.T) {
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
	probe := &explanationReadiness{}
	var stdout, stderr bytes.Buffer
	app := cli.App{Categories: target.Categories(), Profiles: store, NativeReadiness: probe, WorkingDirectory: home, Output: &stdout, ErrorOutput: &stderr}
	if code := app.Run(context.Background(), []string{"explain", "devin", "--profile", "example", "--json"}); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if probe.calls != 0 {
		t.Fatalf("default explanation ran native probe %d times", probe.calls)
	}
	var result struct {
		FormatVersion int `json:"formatVersion"`
		Plan          struct {
			Digest    string `json:"authorityDigest"`
			Effective []struct {
				ID string `json:"id"`
			} `json:"effective"`
		} `json:"plan"`
		Checks []struct{ ID, Status string } `json:"checks"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.FormatVersion != 1 || !strings.HasPrefix(result.Plan.Digest, "sha256:") {
		t.Fatalf("result=%s", stdout.String())
	}
	for _, private := range []string{home, "authRef", "sandbox-exec"} {
		if strings.Contains(stdout.String(), private) {
			t.Fatalf("private value %q escaped: %s", private, stdout.String())
		}
	}
	if !strings.Contains(stdout.String(), `"id":"runtime.network"`) || !strings.Contains(stdout.String(), "local-ip-socket-bind-no-listen-coarse-outbound-ip-macos-dns") {
		t.Fatalf("network facts incomplete: %s", stdout.String())
	}
}

func TestExplainNativeReadinessIsExplicitAndNarrow(t *testing.T) {
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
	probe := &explanationReadiness{}
	var stdout, stderr bytes.Buffer
	app := cli.App{Categories: target.Categories(), Profiles: store, NativeReadiness: probe, WorkingDirectory: home, Output: &stdout, ErrorOutput: &stderr}
	if code := app.Run(context.Background(), []string{"explain", "devin", "--profile", "example", "--check-native-readiness"}); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if probe.calls != 1 || !strings.Contains(stdout.String(), "native.backend: pass (backend_ready)") || !strings.Contains(stdout.String(), "runtime.enforcement: unchecked") {
		t.Fatalf("output=%s calls=%d", stdout.String(), probe.calls)
	}
}

func TestExplainLegacyProfilesPreservesCompatibilityAuthority(t *testing.T) {
	for _, fixture := range []struct {
		name string
		raw  string
	}{
		{name: "v1", raw: `{"version":1,"name":"example","target":"devin","skillReferences":[]}`},
		{name: "v2", raw: `{"version":2,"name":"example","target":"devin","categories":{"skills":{"schemaVersion":1,"selection":[]}}}`},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			home := t.TempDir()
			target, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: home})
			if err != nil {
				t.Fatal(err)
			}
			profilesDirectory := filepath.Join(home, ".acs", "profiles")
			if err := os.MkdirAll(profilesDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(profilesDirectory, "example.json"), []byte(fixture.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			store := profile.NewStore(filepath.Join(home, ".acs"), target.Categories())
			for _, invocation := range [][]string{
				{"explain", "sandbox", "--profile", "example", "--json"},
				{"explain", "devin", "--profile", "example", "--json"},
				{"explain", "run", "--profile", "example", "--json", "--", "/usr/bin/true"},
			} {
				var stdout, stderr bytes.Buffer
				app := cli.App{Categories: target.Categories(), Profiles: store, WorkingDirectory: home, Output: &stdout, ErrorOutput: &stderr}
				if code := app.Run(context.Background(), invocation); code != 0 {
					t.Fatalf("%q code=%d stderr=%q", invocation, code, stderr.String())
				}
				for _, want := range []string{`"compatibility":"legacy"`, `"id":"common.workspace"`, `"access":"read-write"`, `"reason":"legacy_compatibility_default"`} {
					if !strings.Contains(stdout.String(), want) {
						t.Fatalf("%q lacks %q: %s", invocation, want, stdout.String())
					}
				}
			}
		})
	}
}

func TestExplainJSONFailureIsVersionedAndDoesNotExposeWrappedError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := cli.App{Categories: nil, Profiles: nil, Output: &stdout, ErrorOutput: &stderr}
	if code := app.Run(context.Background(), []string{"explain", "devin", "--profile", "missing", "--json"}); code != 1 {
		t.Fatalf("code=%d", code)
	}
	var result struct {
		FormatVersion int             `json:"formatVersion"`
		Plan          json.RawMessage `json:"plan"`
		Diagnostic    struct {
			Code   string `json:"code"`
			Detail string `json:"detail"`
		} `json:"diagnostic"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.FormatVersion != 1 || string(result.Plan) != "null" || result.Diagnostic.Code != "explanation_unavailable" || stderr.Len() != 0 {
		t.Fatalf("result=%s stderr=%q", stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := app.Run(context.Background(), []string{"explain", "devin", "--profile", "missing", "--json", "--json"}); code != 1 {
		t.Fatalf("syntax code=%d", code)
	}
	if !strings.Contains(stdout.String(), `"diagnostic":{"code":"invalid_invocation"`) || strings.Contains(stdout.String(), "duplicate flag") {
		t.Fatalf("unsafe or unversioned syntax diagnostic: %s", stdout.String())
	}
}

func TestExplainAllIntentsUseTypedRecipeFactsAndHideArgumentValues(t *testing.T) {
	home := t.TempDir()
	devinTarget, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	devinStore := profile.NewStore(filepath.Join(home, ".acs-devin"), devinTarget.Categories())
	devinProfile, err := devinTarget.Categories().NewProfile("example", devinTarget.Categories().NewDraft())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := devinStore.Create(devinProfile); err != nil {
		t.Fatal(err)
	}
	codexTarget, err := codexadapter.New(codexadapter.Config{BinaryPath: "codex", ExistingHomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	codexStore := profile.NewStore(filepath.Join(home, ".acs-codex"), codexTarget.Categories())
	codexProfile, err := codexTarget.Categories().NewProfileWithOverlay("example", codexTarget.Categories().NewDraft(), profile.OverlayPayload{Version: 1, AuthRef: "private-auth-reference"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := codexStore.Create(codexProfile); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, recipe string
		args         []string
		codex        bool
	}{
		{name: "sandbox", recipe: "shell", args: []string{"explain", "sandbox", "--profile", "example", "--json"}},
		{name: "devin", recipe: "devin", args: []string{"explain", "devin", "--profile", "example", "--json"}},
		{name: "codex", recipe: "codex", args: []string{"explain", "codex", "--profile", "example", "--json"}, codex: true},
		{name: "run", recipe: "command", args: []string{"explain", "run", "--profile", "example", "--json", "--", "/usr/bin/true", "PRIVATE_ARGUMENT"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			app := cli.App{Categories: devinTarget.Categories(), Profiles: devinStore, WorkingDirectory: home, Output: &stdout, ErrorOutput: &stderr}
			if test.codex {
				app.CodexTarget, app.CodexCategories, app.CodexProfiles = codexTarget, codexTarget.Categories(), codexStore
			}
			if code := app.Run(context.Background(), test.args); code != 0 {
				t.Fatalf("code=%d stderr=%q", code, stderr.String())
			}
			if !strings.Contains(stdout.String(), `"recipe":"`+test.recipe+`"`) || strings.Contains(stdout.String(), "PRIVATE_ARGUMENT") || strings.Contains(stdout.String(), "private-auth-reference") {
				t.Fatalf("output=%s", stdout.String())
			}
			if test.name == "run" && (!strings.Contains(stdout.String(), `"count":1`) || !strings.Contains(stdout.String(), "absolute path (hidden)")) {
				t.Fatalf("run requested facts omit form/count: %s", stdout.String())
			}
			if test.name == "codex" && (!strings.Contains(stdout.String(), `"id":"codex.sandbox"`) || !strings.Contains(stdout.String(), `"id":"codex.approval"`)) {
				t.Fatalf("Codex generated configuration facts missing: %s", stdout.String())
			}
		})
	}
}
