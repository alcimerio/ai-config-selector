package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	codexadapter "github.com/alcimerio/ai-config-selector/internal/adapter/codex"
	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type rejectedExplanationWriter struct{ calls int }

func (writer *rejectedExplanationWriter) Write([]byte) (int, error) {
	writer.calls++
	return 0, errors.New("rejected output")
}

type explanationReadiness struct {
	calls     int
	readiness launch.SandboxReadiness
}

func (probe *explanationReadiness) Readiness(context.Context) (launch.SandboxReadiness, error) {
	probe.calls++
	if probe.readiness.RequiredMode != "" {
		return probe.readiness, nil
	}
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

func TestExplainUnknownInactiveOverlaysAreSanitizedLimitationsOutsidePlanAndDigest(t *testing.T) {
	var baselineDigest string
	for index, overlays := range []string{
		`"devin":{"version":1},"PRIVATE-OVERLAY-B":{"version":41,"payload":"PRIVATE-PAYLOAD-B"},"PRIVATE-OVERLAY-A":{"version":99,"payload":"PRIVATE-PAYLOAD-A"}`,
		`"PRIVATE-OVERLAY-A":{"version":99,"payload":"PRIVATE-PAYLOAD-A"},"PRIVATE-OVERLAY-B":{"version":41,"payload":"PRIVATE-PAYLOAD-B"},"devin":{"version":1}`,
	} {
		home := t.TempDir()
		target, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: home})
		if err != nil {
			t.Fatal(err)
		}
		profiles := filepath.Join(home, ".acs", "profiles")
		if err := os.MkdirAll(profiles, 0o700); err != nil {
			t.Fatal(err)
		}
		name := fmt.Sprintf("unknown-overlays-%d", index)
		document := fmt.Sprintf(`{"version":3,"name":%q,"common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{%s}}`, name, overlays)
		if err := os.WriteFile(filepath.Join(profiles, name+".json"), []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
		store := profile.NewStore(filepath.Join(home, ".acs"), target.Categories())
		var stdout, stderr bytes.Buffer
		app := cli.App{Categories: target.Categories(), Profiles: store, WorkingDirectory: home, Output: &stdout, ErrorOutput: &stderr}
		if code := app.Run(context.Background(), []string{"explain", "devin", "--profile", name, "--json"}); code != 0 {
			t.Fatalf("JSON code=%d stderr=%q", code, stderr.String())
		}
		for _, private := range []string{"PRIVATE-OVERLAY-A", "PRIVATE-OVERLAY-B", "PRIVATE-PAYLOAD-A", "PRIVATE-PAYLOAD-B"} {
			if strings.Contains(stdout.String(), private) {
				t.Fatalf("unknown overlay data escaped: %s", stdout.String())
			}
		}
		var result struct {
			Plan struct {
				Digest      string `json:"authorityDigest"`
				Unsupported []struct {
					ID string `json:"id"`
				} `json:"unsupported"`
			} `json:"plan"`
			Limitations []struct {
				Code, Detail string
			} `json:"limitations"`
		}
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if index == 0 {
			baselineDigest = result.Plan.Digest
		} else if result.Plan.Digest != baselineDigest {
			t.Fatalf("unknown overlay order changed digest: %q != %q", result.Plan.Digest, baselineDigest)
		}
		wantCodes := []string{"inactive_overlay_unknown", "inactive_overlay_unknown", "native_readiness_not_launch_readiness", "semantic_digest_only"}
		if len(result.Limitations) != len(wantCodes) {
			t.Fatalf("limitations = %#v, want codes %v", result.Limitations, wantCodes)
		}
		for position, want := range wantCodes {
			if result.Limitations[position].Code != want || result.Limitations[position].Detail == "" {
				t.Fatalf("limitation %d = %#v, want code %q with detail", position, result.Limitations[position], want)
			}
		}
		for _, fact := range result.Plan.Unsupported {
			if strings.HasPrefix(fact.ID, "overlay.inactive.unknown-") {
				t.Fatalf("unknown inactive overlay fabricated a plan fact: %#v", fact)
			}
		}
		stdout.Reset()
		stderr.Reset()
		if code := app.Run(context.Background(), []string{"explain", "devin", "--profile", name}); code != 0 || strings.Count(stdout.String(), "inactive_overlay_unknown:") != 2 {
			t.Fatalf("human code=%d output=%s stderr=%s", code, stdout.String(), stderr.String())
		}
	}
}

func TestExplainUnknownInactiveOverlayAndLimitationBoundsFailWithoutPartialPlan(t *testing.T) {
	for _, test := range []struct {
		name, reason string
		unknowns     int
	}{
		// The selected overlay plus 15 unknown overlays meets the overlay maximum,
		// while the 15 per-overlay limitations plus two fixed limitations exceed
		// the limitation maximum.
		{name: "limitation count", unknowns: 15, reason: "actual limitations exceed their maximum"},
		// The selected overlay plus 16 unknown overlays exceeds the overlay maximum.
		{name: "overlay count", unknowns: 16, reason: "stored overlays exceed their maximum"},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			target, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: home})
			if err != nil {
				t.Fatal(err)
			}
			var overlays strings.Builder
			overlays.WriteString(`"devin":{"version":1}`)
			for index := 0; index < test.unknowns; index++ {
				fmt.Fprintf(&overlays, `,"PRIVATE-OVERLAY-%d":{"version":%d,"payload":"PRIVATE-PAYLOAD-%d"}`, index, index+2, index)
			}
			profiles := filepath.Join(home, ".acs", "profiles")
			if err := os.MkdirAll(profiles, 0o700); err != nil {
				t.Fatal(err)
			}
			document := fmt.Sprintf(`{"version":3,"name":"bounded-overlays","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{%s}}`, overlays.String())
			if err := os.WriteFile(filepath.Join(profiles, "bounded-overlays.json"), []byte(document), 0o600); err != nil {
				t.Fatal(err)
			}
			store := profile.NewStore(filepath.Join(home, ".acs"), target.Categories())
			for _, format := range []struct {
				name string
				args []string
			}{
				{name: "json", args: []string{"explain", "devin", "--profile", "bounded-overlays", "--json"}},
				{name: "human", args: []string{"explain", "devin", "--profile", "bounded-overlays"}},
			} {
				t.Run(format.name, func(t *testing.T) {
					var stdout, stderr bytes.Buffer
					app := cli.App{Categories: target.Categories(), Profiles: store, WorkingDirectory: home, Output: &stdout, ErrorOutput: &stderr}
					if code := app.Run(context.Background(), format.args); code != 1 {
						t.Fatalf("%s: code=%d stdout=%s stderr=%s", test.reason, code, stdout.String(), stderr.String())
					}
					output := stdout.String()
					if format.name == "json" && (!strings.Contains(output, `"plan":null`) || !strings.Contains(output, `"code":"explanation_too_large"`)) {
						t.Fatalf("%s omitted safe JSON diagnostic: %s", test.reason, output)
					}
					if format.name == "human" {
						output = stderr.String()
						if stdout.Len() != 0 || !strings.Contains(output, "explanation_too_large") {
							t.Fatalf("%s omitted safe human diagnostic: stdout=%s stderr=%s", test.reason, stdout.String(), output)
						}
					}
					if strings.Contains(output, "authorityDigest") || strings.Contains(output, "PRIVATE-OVERLAY") || strings.Contains(output, "PRIVATE-PAYLOAD") {
						t.Fatalf("%s exposed a partial/private result: %s", test.reason, output)
					}
				})
			}
		})
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
				if !strings.Contains(stdout.String(), `"id":"skills.target-projection"`) || !strings.Contains(stdout.String(), `"reason":"registered_projection"`) {
					t.Fatalf("%q omitted legacy target placement: %s", invocation, stdout.String())
				}
			}
		})
	}
}

func TestExplainMissingSelectedReferenceFailsWithoutPlanProbeOrPrivatePath(t *testing.T) {
	home := t.TempDir()
	target, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	store := profile.NewStore(filepath.Join(home, ".acs"), target.Categories())
	candidate := devin.NewSkillsProfile("example", []skills.SkillReference{{Source: "shared-agents", RelativePath: "PRIVATE-MISSING-REFERENCE"}})
	if _, err := store.Create(candidate); err != nil {
		t.Fatal(err)
	}
	probe := &explanationReadiness{}
	var stdout, stderr bytes.Buffer
	app := cli.App{Categories: target.Categories(), Profiles: store, NativeReadiness: probe, WorkingDirectory: home, Output: &stdout, ErrorOutput: &stderr}
	if code := app.Run(context.Background(), []string{"explain", "devin", "--profile", "example", "--json", "--check-native-readiness"}); code != 1 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if probe.calls != 0 || !strings.Contains(stdout.String(), `"plan":null`) || !strings.Contains(stdout.String(), `"code":"profile_resolution_failed"`) {
		t.Fatalf("failure emitted a plan or reached readiness: calls=%d output=%s", probe.calls, stdout.String())
	}
	for _, private := range []string{home, "PRIVATE-MISSING-REFERENCE"} {
		if strings.Contains(stdout.String(), private) || strings.Contains(stderr.String(), private) {
			t.Fatalf("failure exposed private source detail %q: stdout=%s stderr=%s", private, stdout.String(), stderr.String())
		}
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

func TestExplainReportsFailureWhenTheBufferedResultCannotBeWritten(t *testing.T) {
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
	output := &rejectedExplanationWriter{}
	app := cli.App{Categories: target.Categories(), Profiles: store, WorkingDirectory: home, Output: output, ErrorOutput: &bytes.Buffer{}}
	if code := app.Run(context.Background(), []string{"explain", "sandbox", "--profile", "example", "--json"}); code != 1 || output.calls != 1 {
		t.Fatalf("write failure code=%d calls=%d", code, output.calls)
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

			humanArguments := withoutArgument(test.args, "--json")
			stdout.Reset()
			stderr.Reset()
			if code := app.Run(context.Background(), humanArguments); code != 0 || !strings.Contains(stdout.String(), "Native readiness: unchecked (not probed); this is not launch readiness.") {
				t.Fatalf("default human %s code=%d output=%s stderr=%s", test.name, code, stdout.String(), stderr.String())
			}
			if !strings.Contains(stdout.String(), "reason=") || !strings.Contains(stdout.String(), "source=") {
				t.Fatalf("human %s omitted typed provenance: %s", test.name, stdout.String())
			}
			if test.name == "codex" && !strings.Contains(stdout.String(), "value omitted") {
				t.Fatalf("Codex human output omitted explicit auth-value boundary: %s", stdout.String())
			}

			passProbe := &explanationReadiness{}
			app.NativeReadiness = passProbe
			stdout.Reset()
			stderr.Reset()
			if code := app.Run(context.Background(), insertBeforeLiteralBoundary(humanArguments, "--check-native-readiness")); code != 0 || passProbe.calls != 1 || !strings.Contains(stdout.String(), "Native readiness: narrowly observed; supported platform and backend readiness passed. This is not launch readiness.") {
				t.Fatalf("observed human %s code=%d calls=%d output=%s stderr=%s", test.name, code, passProbe.calls, stdout.String(), stderr.String())
			}

			failProbe := &explanationReadiness{readiness: launch.SandboxReadiness{RequiredMode: "native", Backend: "Seatbelt", Platform: "unsupported", Supported: false, Ready: false}}
			app.NativeReadiness = failProbe
			stdout.Reset()
			stderr.Reset()
			if code := app.Run(context.Background(), insertBeforeLiteralBoundary(humanArguments, "--check-native-readiness")); code != 1 || failProbe.calls != 1 || !strings.Contains(stdout.String(), "Native readiness: narrowly observed; the requested platform/backend observation did not pass. This is not launch readiness.") {
				t.Fatalf("failed human observation %s code=%d calls=%d output=%s stderr=%s", test.name, code, failProbe.calls, stdout.String(), stderr.String())
			}
		})
	}
}

func withoutArgument(arguments []string, remove string) []string {
	result := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		if argument != remove {
			result = append(result, argument)
		}
	}
	return result
}

func insertBeforeLiteralBoundary(arguments []string, value string) []string {
	result := append([]string(nil), arguments...)
	for index, argument := range result {
		if argument == "--" {
			result = append(result, "")
			copy(result[index+1:], result[index:])
			result[index] = value
			return result
		}
	}
	return append(result, value)
}
