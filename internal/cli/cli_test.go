package cli_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func TestVersionPrintsTheInjectedBuildVersion(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := cli.App{Version: "v0.1.0", Output: &stdout, ErrorOutput: &stderr}

	if exitCode := application.Run(context.Background(), []string{"version"}); exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	if stdout.String() != "acs v0.1.0\n" {
		t.Fatalf("version output = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("version stderr = %q", stderr.String())
	}
}

func TestUsageIncludesTheVersionCommand(t *testing.T) {
	var stderr bytes.Buffer
	application := cli.App{Output: &bytes.Buffer{}, ErrorOutput: &stderr}

	if exitCode := application.Run(context.Background(), nil); exitCode == 0 {
		t.Fatal("empty command unexpectedly succeeded")
	}
	if !strings.Contains(stderr.String(), "acs version") {
		t.Fatalf("usage omits version command: %q", stderr.String())
	}
}

func TestDryRunReportsResolvedGlobalAndInheritedProjectSkillBundlesWithoutCreatingSession(t *testing.T) {
	existingHome := t.TempDir()
	acsHome := filepath.Join(existingHome, ".acs")
	adapter, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: existingHome})
	if err != nil {
		t.Fatal(err)
	}
	profiles := profile.NewStore(acsHome, adapter.Categories())
	workingDirectory := t.TempDir()

	globalBundle := filepath.Join(existingHome, ".config", "devin", "skills", "review")
	projectBundle := filepath.Join(workingDirectory, ".agents", "skills", "project-review")
	for _, bundlePath := range []string{globalBundle, projectBundle} {
		if err := os.MkdirAll(bundlePath, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bundlePath, "SKILL.md"), []byte("# fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := profiles.Create(devin.NewSkillsProfile("reviews", []skills.SkillReference{{
		Source:       devin.GlobalSourceDevinConfig,
		RelativePath: "review",
	}})); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := cli.App{
		Categories:       adapter.Categories(),
		DraftEditor:      adapter,
		Planner:          adapter,
		Profiles:         profiles,
		WorkingDirectory: workingDirectory,
		Input:            strings.NewReader(""),
		Output:           &stdout,
		ErrorOutput:      &stderr,
	}
	exitCode := application.Run(context.Background(), []string{"devin", "--profile", "reviews", "--dry-run"})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}

	for _, detail := range []string{
		`Dry run for Profile "reviews"`,
		"Selected global Skill Bundles managed by ACS:",
		"review [devin-config]",
		"source: " + globalBundle,
		"Session: <session>/home/.config/devin/skills/review",
		"Project-local Skill Bundles inherited by Devin (not managed by ACS):",
		"project-review " + projectBundle,
		"No Session was created and Devin was not started.",
	} {
		if !strings.Contains(stdout.String(), detail) {
			t.Errorf("dry-run output does not contain %q:\n%s", detail, stdout.String())
		}
	}
	if _, err := os.Stat(filepath.Join(acsHome, "sessions")); !os.IsNotExist(err) {
		t.Fatalf("dry run created a Session directory: %v", err)
	}
}

type noteContribution struct{ value string }

func (contribution noteContribution) Plan(_ context.Context, _ string, plan *launch.Plan) error {
	plan.Sections = append(plan.Sections, launch.PlanSection{Title: "Notes:", Items: []launch.PlanItem{{Label: contribution.value}}})
	return nil
}
func (noteContribution) Materialize(string) error                                 { return nil }
func (noteContribution) Verify(context.Context, launch.VerificationContext) error { return nil }

type resolvedPlanner struct{}

func (resolvedPlanner) PlanLaunch(ctx context.Context, workingDirectory string, resolved category.ResolvedProfile) (launch.Plan, error) {
	return resolved.Plan(ctx, workingDirectory)
}

func TestDryRunCoordinatesAnUnrelatedCategoryWithoutCategorySpecificCLIChanges(t *testing.T) {
	notes, err := category.Bind(category.Definition[string, string, noteContribution]{
		ID:            "notes",
		SchemaVersion: 1,
		Empty:         func() string { return "" },
		Resolve:       func(_ context.Context, selection string) (string, error) { return strings.ToUpper(selection), nil },
		Contribute:    func(resolved string) (noteContribution, error) { return noteContribution{value: resolved}, nil },
		Count: func(selection string) int {
			if selection == "" {
				return 0
			}
			return 1
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", notes.Registration())
	if err != nil {
		t.Fatal(err)
	}
	draft := registry.NewDraft()
	if err := category.SetSelection(&draft, notes, "category-owned dry run"); err != nil {
		t.Fatal(err)
	}
	candidate, err := registry.NewProfile("modular", draft)
	if err != nil {
		t.Fatal(err)
	}
	store := profile.NewStore(t.TempDir(), registry)
	if _, err := store.Create(candidate); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	var errorOutput bytes.Buffer
	application := cli.App{
		Categories:       registry,
		Planner:          resolvedPlanner{},
		Profiles:         store,
		WorkingDirectory: t.TempDir(),
		Output:           &output,
		ErrorOutput:      &errorOutput,
	}
	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "modular", "--dry-run"}); exitCode != 0 {
		t.Fatalf("exit code = %d; stderr: %s", exitCode, errorOutput.String())
	}
	if !strings.Contains(output.String(), "Notes:\n  CATEGORY-OWNED DRY RUN") {
		t.Fatalf("generic dry-run output = %q", output.String())
	}
}

func TestDryRunLoadsVersionOneProfileWithoutRewritingIt(t *testing.T) {
	existingHome := t.TempDir()
	acsHome := filepath.Join(existingHome, ".acs")
	legacyPath, legacy := writeVersionOneProfile(t, acsHome, "legacy")
	bundlePath := filepath.Join(existingHome, ".config", "devin", "skills", "review")
	if err := os.MkdirAll(bundlePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundlePath, "SKILL.md"), []byte("# fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: existingHome})
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := cli.App{
		Categories:       adapter.Categories(),
		DraftEditor:      adapter,
		Planner:          adapter,
		Profiles:         profile.NewStore(acsHome, adapter.Categories()),
		WorkingDirectory: t.TempDir(),
		Input:            strings.NewReader(""),
		Output:           &stdout,
		ErrorOutput:      &stderr,
	}

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "legacy", "--dry-run"}); exitCode != 0 {
		t.Fatalf("version-1 dry run exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "review [devin-config]") {
		t.Fatalf("version-1 dry run did not resolve the selected Skill Bundle:\n%s", stdout.String())
	}
	assertFileContents(t, legacyPath, legacy, "dry run rewrote the version-1 Profile")
}

func TestLaunchRunsPreflightBeforeInteractiveDevinAndCleansUpSession(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	recorder := &recordingSandbox{delegate: directSandbox{}}
	fixture.sandbox = recorder
	workingDirectory := t.TempDir()

	eventsPath := filepath.Join(t.TempDir(), "events")
	t.Setenv("FAKE_DEVIN_EVENTS", eventsPath)
	script := `#!/bin/sh
if [ "$1" = "skills" ]; then
  printf 'preflight-skills\n' >> "$FAKE_DEVIN_EVENTS"
  printf '[{"name":"review","provider":"Devin","base_dir":"%s"}]\n' "$HOME/.config/devin/skills/review"
  exit 0
fi
if [ "$1" = "auth" ]; then
  printf 'preflight-auth\n' >> "$FAKE_DEVIN_EVENTS"
  printf 'Logged in (via fixture).\n'
  exit 0
fi
printf 'launch-args=%s:%s\n' "$#" "$*" >> "$FAKE_DEVIN_EVENTS"
IFS= read -r line
printf 'stdout:%s\n' "$line"
printf 'stderr:%s\n' "$line" >&2
exit 23
`
	binaryPath := writeFakeDevin(t, script)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := fixture.application(t, binaryPath, workingDirectory, strings.NewReader("terminal input\n"), &stdout, &stderr)

	exitCode := application.Run(context.Background(), []string{"devin", "--profile", "reviews"})
	if exitCode != 23 {
		t.Fatalf("exit code = %d, want child exit code 23; stderr: %s", exitCode, stderr.String())
	}
	if stdout.String() != "stdout:terminal input\n" {
		t.Fatalf("Devin stdout = %q, want attached terminal output", stdout.String())
	}
	if stderr.String() != "stderr:terminal input\n" {
		t.Fatalf("Devin stderr = %q, want attached terminal error output", stderr.String())
	}
	events, err := os.ReadFile(eventsPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(events), "preflight-skills\npreflight-auth\nlaunch-args=0:\n"; got != want {
		t.Fatalf("Devin events = %q, want %q", got, want)
	}
	if got, want := recorder.arguments, [][]string{{"skills", "list", "--json"}, {"auth", "status"}, nil}; !reflect.DeepEqual(got, want) {
		t.Fatalf("sandbox process arguments = %#v, want %#v", got, want)
	}
	entries, err := os.ReadDir(fixture.sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("launch left Session data behind: %v", entries)
	}
}

func TestLaunchRejectsUnavailableSandboxBeforeCreatingSession(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	fixture.sandbox = failingSandbox{checkErr: &launch.SandboxError{Category: launch.SandboxBackendUnavailable}}
	marker := filepath.Join(t.TempDir(), "target-started")
	script := "#!/bin/sh\ntouch " + strconv.Quote(marker) + "\n"
	var stderr bytes.Buffer
	application := fixture.application(t, writeFakeDevin(t, script), t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &stderr)

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "reviews"}); exitCode == 0 {
		t.Fatal("launch succeeded without a sandbox backend")
	}
	if !strings.Contains(stderr.String(), string(launch.SandboxBackendUnavailable)) && !strings.Contains(stderr.String(), "required system backend") {
		t.Fatalf("sandbox diagnostic lacks its stable category: %s", stderr.String())
	}
	if _, err := os.Stat(fixture.sessionsDirectory); !os.IsNotExist(err) {
		t.Fatalf("early sandbox failure created a Session: %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("target started after early sandbox failure: %v", err)
	}
}

func TestLaunchRemovesUnusedSessionWhenSandboxSetupFails(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	fixture.sandbox = failingSandbox{prepareErr: &launch.SandboxError{Category: launch.SandboxSetupFailed}}
	marker := filepath.Join(t.TempDir(), "target-started")
	script := "#!/bin/sh\ntouch " + strconv.Quote(marker) + "\n"
	application := fixture.application(t, writeFakeDevin(t, script), t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "reviews"}); exitCode == 0 {
		t.Fatal("launch succeeded after sandbox setup failed")
	}
	entries, err := os.ReadDir(fixture.sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("sandbox setup failure left Session data behind: %v", entries)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("target started after sandbox setup failure: %v", err)
	}
}

func TestLaunchLoadsVersionOneProfileWithoutRewritingIt(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	legacyPath, legacy := writeVersionOneProfile(t, filepath.Join(fixture.existingHome, ".acs"), "reviews")
	application := fixture.application(
		t,
		writeFakeDevin(t, successfulDevinScript("exit 0\n")),
		t.TempDir(),
		strings.NewReader(""),
		&bytes.Buffer{},
		&bytes.Buffer{},
	)

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "reviews"}); exitCode != 0 {
		t.Fatalf("version-1 launch exit code = %d, want 0", exitCode)
	}
	assertFileContents(t, legacyPath, legacy, "launch rewrote the version-1 Profile")
}

func TestLaunchRemovesAbandonedSessionFromAnEarlierRun(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	abandonedSession := filepath.Join(fixture.sessionsDirectory, "session-abandoned")
	if err := os.MkdirAll(filepath.Join(abandonedSession, "home"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(abandonedSession, "left-behind"), []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}

	script := successfulDevinScript("exit 0\n")
	application := fixture.application(
		t,
		writeFakeDevin(t, script),
		t.TempDir(),
		strings.NewReader(""),
		&bytes.Buffer{},
		&bytes.Buffer{},
	)

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "reviews"}); exitCode != 0 {
		t.Fatalf("launch exit code = %d, want 0", exitCode)
	}
	if _, err := os.Stat(abandonedSession); !os.IsNotExist(err) {
		t.Fatalf("later launch did not remove abandoned Session: %v", err)
	}
}

func TestLaterLaunchPreservesAConcurrentActiveSession(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	claimPath := filepath.Join(t.TempDir(), "first-claimed")
	readyPath := filepath.Join(t.TempDir(), "first-ready")
	releasePath := filepath.Join(t.TempDir(), "release-first")
	t.Setenv("FAKE_DEVIN_FIRST_CLAIM", claimPath)
	t.Setenv("FAKE_DEVIN_FIRST_READY", readyPath)
	t.Setenv("FAKE_DEVIN_RELEASE_FIRST", releasePath)
	script := successfulDevinScript(`if mkdir "$FAKE_DEVIN_FIRST_CLAIM" 2>/dev/null; then
  printf '%s\n' "$HOME" > "$FAKE_DEVIN_FIRST_READY"
  while [ ! -e "$FAKE_DEVIN_RELEASE_FIRST" ]; do sleep 0.05; done
fi
exit 0
`)
	binaryPath := writeFakeDevin(t, script)
	firstApplication := fixture.application(t, binaryPath, t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	secondApplication := fixture.application(t, binaryPath, t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})

	firstExitCodes := make(chan int, 1)
	go func() {
		firstExitCodes <- firstApplication.Run(context.Background(), []string{"devin", "--profile", "reviews"})
	}()
	waitForFile(t, readyPath)
	homeBytes, err := os.ReadFile(readyPath)
	if err != nil {
		t.Fatal(err)
	}
	firstSession := filepath.Dir(strings.TrimSpace(string(homeBytes)))

	secondExitCode := secondApplication.Run(context.Background(), []string{"devin", "--profile", "reviews"})
	_, activeSessionErr := os.Stat(firstSession)
	if err := os.WriteFile(releasePath, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}

	select {
	case firstExitCode := <-firstExitCodes:
		if firstExitCode != 0 {
			t.Errorf("first launch exit code = %d, want 0", firstExitCode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first launch to exit")
	}
	if secondExitCode != 0 {
		t.Errorf("second launch exit code = %d, want 0", secondExitCode)
	}
	if activeSessionErr != nil {
		t.Fatalf("later launch removed a concurrent active Session: %v", activeSessionErr)
	}
}

func TestLaunchForwardsSignalsToDevinAndCleansUpSession(t *testing.T) {
	fixture := newLaunchTestFixture(t)

	readyPath := filepath.Join(t.TempDir(), "ready")
	signalPath := filepath.Join(t.TempDir(), "signal")
	t.Setenv("FAKE_DEVIN_READY", readyPath)
	t.Setenv("FAKE_DEVIN_SIGNAL", signalPath)
	script := successfulDevinScript(`trap 'printf "SIGTERM\n" > "$FAKE_DEVIN_SIGNAL"; exit 42' TERM
touch "$FAKE_DEVIN_READY"
while :; do sleep 1; done
`)
	binaryPath := writeFakeDevin(t, script)
	application := fixture.application(t, binaryPath, t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})

	exitCodes := make(chan int, 1)
	go func() {
		exitCodes <- application.Run(context.Background(), []string{"devin", "--profile", "reviews"})
	}()
	waitForFile(t, readyPath)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	select {
	case exitCode := <-exitCodes:
		if exitCode != 42 {
			t.Fatalf("exit code = %d, want signaled Devin exit code 42", exitCode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for signaled Devin to exit")
	}
	signal, err := os.ReadFile(signalPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(signal) != "SIGTERM\n" {
		t.Fatalf("forwarded signal record = %q, want SIGTERM", signal)
	}
	entries, err := os.ReadDir(fixture.sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("signaled launch left Session data behind: %v", entries)
	}
}

func TestLaunchForwardsTerminalResizeEventToDevin(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	readyPath := filepath.Join(t.TempDir(), "ready")
	resizePath := filepath.Join(t.TempDir(), "resize")
	t.Setenv("FAKE_DEVIN_READY", readyPath)
	t.Setenv("FAKE_DEVIN_RESIZE", resizePath)
	script := successfulDevinScript(`trap 'printf "SIGWINCH\n" > "$FAKE_DEVIN_RESIZE"' WINCH
touch "$FAKE_DEVIN_READY"
while [ ! -e "$FAKE_DEVIN_RESIZE" ]; do sleep 0.05; done
exit 0
`)
	application := fixture.application(
		t,
		writeFakeDevin(t, script),
		t.TempDir(),
		strings.NewReader(""),
		&bytes.Buffer{},
		&bytes.Buffer{},
	)

	exitCodes := make(chan int, 1)
	go func() {
		exitCodes <- application.Run(context.Background(), []string{"devin", "--profile", "reviews"})
	}()
	waitForFile(t, readyPath)
	if err := syscall.Kill(os.Getpid(), syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}

	select {
	case exitCode := <-exitCodes:
		if exitCode != 0 {
			t.Fatalf("exit code = %d, want 0 after resize", exitCode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for resized Devin to exit")
	}
	resize, err := os.ReadFile(resizePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(resize) != "SIGWINCH\n" {
		t.Fatalf("resize record = %q, want SIGWINCH", resize)
	}
}

func TestLaunchSignalDuringPreflightCancelsVerificationAndCleansUpSession(t *testing.T) {
	fixture := newLaunchTestFixture(t)
	readyPath := filepath.Join(t.TempDir(), "preflight-ready")
	t.Setenv("FAKE_DEVIN_PREFLIGHT_READY", readyPath)
	script := `#!/bin/sh
if [ "$1" = "skills" ]; then
  touch "$FAKE_DEVIN_PREFLIGHT_READY"
  sleep 30
  exit 0
fi
exit 64
`
	binaryPath := writeFakeDevin(t, script)
	var stderr bytes.Buffer
	application := fixture.application(t, binaryPath, t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &stderr)

	exitCodes := make(chan int, 1)
	go func() {
		exitCodes <- application.Run(context.Background(), []string{"devin", "--profile", "reviews"})
	}()
	waitForFile(t, readyPath)
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}

	select {
	case exitCode := <-exitCodes:
		if exitCode == 0 {
			t.Fatal("launch succeeded after preflight was interrupted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for interrupted preflight to exit")
	}
	if !strings.Contains(stderr.String(), "verification was canceled or timed out") {
		t.Fatalf("interrupted-preflight error is unclear: %s", stderr.String())
	}
	entries, err := os.ReadDir(fixture.sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("interrupted preflight left Session data behind: %v", entries)
	}
}

func TestLaunchPreflightFailureReportsSanitizedCatalogAndCleansUpSession(t *testing.T) {
	fixture := newLaunchTestFixture(t)

	launchMarker := filepath.Join(t.TempDir(), "launched")
	t.Setenv("FAKE_DEVIN_LAUNCH_MARKER", launchMarker)
	script := `#!/bin/sh
if [ "$1" = "skills" ]; then
  printf '[{"name":"token=SUPER_SECRET_STDOUT","provider":"Devin","base_dir":"%s"}]\n' "$HOME/.config/devin/skills/SUPER_SECRET_PATH"
  printf 'token=SUPER_SECRET\n' >&2
  exit 0
fi
if [ "$1" = "auth" ]; then
  printf 'Logged in (via fixture).\n'
  exit 0
fi
touch "$FAKE_DEVIN_LAUNCH_MARKER"
exit 0
`
	binaryPath := writeFakeDevin(t, script)
	var stderr bytes.Buffer
	application := fixture.application(t, binaryPath, t.TempDir(), strings.NewReader(""), &bytes.Buffer{}, &stderr)

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "reviews"}); exitCode == 0 {
		t.Fatal("launch succeeded after Adapter Preflight catalog mismatch")
	}
	for _, detail := range []string{"skill isolation", "global Skill Catalog did not match", "incompatible"} {
		if !strings.Contains(stderr.String(), detail) {
			t.Errorf("preflight diagnostic does not contain %q: %s", detail, stderr.String())
		}
	}
	for _, sensitive := range []string{"SUPER_SECRET", "devin-config:review"} {
		if strings.Contains(stderr.String(), sensitive) {
			t.Fatalf("preflight diagnostic leaked catalog data: %s", stderr.String())
		}
	}
	if _, err := os.Stat(launchMarker); !os.IsNotExist(err) {
		t.Fatalf("Devin started after failed preflight: %v", err)
	}
	entries, err := os.ReadDir(fixture.sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("failed preflight left Session data behind: %v", entries)
	}
}

func TestLaunchStrictResolutionFailureDoesNotCreateSession(t *testing.T) {
	existingHome := t.TempDir()
	acsHome := filepath.Join(existingHome, ".acs")
	adapter, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: existingHome})
	if err != nil {
		t.Fatal(err)
	}
	profiles := profile.NewStore(acsHome, adapter.Categories())
	if _, err := profiles.Create(devin.NewSkillsProfile("missing", []skills.SkillReference{{
		Source:       devin.GlobalSourceDevinConfig,
		RelativePath: "not-installed\n\x1b[31m",
	}})); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	sessionsDirectory := filepath.Join(acsHome, "sessions")
	application := cli.App{
		Categories:        adapter.Categories(),
		DraftEditor:       adapter,
		Planner:           adapter,
		Launcher:          adapter,
		Profiles:          profiles,
		SessionsDirectory: sessionsDirectory,
		WorkingDirectory:  t.TempDir(),
		Input:             strings.NewReader(""),
		Output:            &bytes.Buffer{},
		ErrorOutput:       &stderr,
	}

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "missing"}); exitCode == 0 {
		t.Fatal("launch succeeded with a missing Skill Reference")
	}
	if !strings.Contains(stderr.String(), `Skill Reference "devin-config:not-installed\n\x1b[31m" is missing`) {
		t.Fatalf("strict-resolution error is unclear: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), "observed Skill References []") {
		t.Fatalf("strict-resolution error omits the sanitized observed catalog: %s", stderr.String())
	}
	if strings.ContainsAny(strings.TrimSuffix(stderr.String(), "\n"), "\n\r\x1b") {
		t.Fatalf("strict-resolution error contains terminal control characters: %q", stderr.String())
	}
	if _, err := os.Stat(sessionsDirectory); !os.IsNotExist(err) {
		t.Fatalf("strict resolution created a Session directory: %v", err)
	}
}

func TestLaunchRejectsDevinPassThroughOptions(t *testing.T) {
	var stderr bytes.Buffer
	application := cli.App{ErrorOutput: &stderr}

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "reviews", "--dangerous-devin-option"}); exitCode == 0 {
		t.Fatal("launch accepted an arbitrary Devin pass-through option")
	}
	if !strings.Contains(stderr.String(), "usage: acs devin") {
		t.Fatalf("rejected pass-through option did not report ACS usage: %s", stderr.String())
	}
}

func TestLaunchRejectsProfileForAnotherTargetBeforeCreatingSession(t *testing.T) {
	existingHome := t.TempDir()
	acsHome := filepath.Join(existingHome, ".acs")
	adapter, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: existingHome})
	if err != nil {
		t.Fatal(err)
	}
	profiles := profile.NewStore(acsHome, adapter.Categories())
	profilesDirectory := filepath.Join(acsHome, "profiles")
	if err := os.MkdirAll(profilesDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profilesDirectory, "other-cli.json"), []byte(`{"version":2,"name":"other-cli","target":"codex","categories":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	sessionsDirectory := filepath.Join(acsHome, "sessions")
	application := cli.App{
		Categories:        adapter.Categories(),
		Profiles:          profiles,
		SessionsDirectory: sessionsDirectory,
		ErrorOutput:       &stderr,
	}

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "other-cli"}); exitCode == 0 {
		t.Fatal("launch accepted a Profile for another CLI")
	}
	if !strings.Contains(stderr.String(), `Profile "other-cli" targets "codex", not devin`) {
		t.Fatalf("wrong-target error is unclear: %s", stderr.String())
	}
	if _, err := os.Stat(sessionsDirectory); !os.IsNotExist(err) {
		t.Fatalf("wrong-target Profile created a Session directory: %v", err)
	}
}

func TestLaunchRejectsUnsupportedProfileSchemaVersionBeforeCreatingSession(t *testing.T) {
	existingHome := t.TempDir()
	acsHome := filepath.Join(existingHome, ".acs")
	adapter, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: existingHome})
	if err != nil {
		t.Fatal(err)
	}
	profiles := profile.NewStore(acsHome, adapter.Categories())
	profilesDirectory := filepath.Join(acsHome, "profiles")
	if err := os.MkdirAll(profilesDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(profilesDirectory, "future.json"),
		[]byte(`{"version":3,"name":"future","target":"devin","categories":{}}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	sessionsDirectory := filepath.Join(acsHome, "sessions")
	application := cli.App{
		Categories:        adapter.Categories(),
		Profiles:          profiles,
		SessionsDirectory: sessionsDirectory,
		ErrorOutput:       &stderr,
	}

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "future"}); exitCode == 0 {
		t.Fatal("launch accepted an unsupported Profile schema version")
	}
	if !strings.Contains(stderr.String(), `decode Profile "future": unsupported schema version 3`) {
		t.Fatalf("unsupported-version error is unclear: %s", stderr.String())
	}
	if _, err := os.Stat(sessionsDirectory); !os.IsNotExist(err) {
		t.Fatalf("unsupported Profile version created a Session directory: %v", err)
	}
}

func TestDryRunRejectsUnknownProfileCategoryBeforeDiscovery(t *testing.T) {
	acsHome := t.TempDir()
	profilesDirectory := filepath.Join(acsHome, "profiles")
	if err := os.MkdirAll(profilesDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(profilesDirectory, "unknown.json"),
		[]byte(`{"version":2,"name":"unknown","target":"devin","categories":{"agents":{"schemaVersion":1,"selection":[]}}}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	fixture := newStaticCategoryFixture(t, staticCatalog{err: errors.New("catalog should not be called")})
	application := cli.App{
		Categories:  fixture.registry,
		DraftEditor: fixture,
		Profiles:    profile.NewStore(acsHome, fixture.registry),
		ErrorOutput: &stderr,
	}

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "unknown", "--dry-run"}); exitCode == 0 {
		t.Fatal("dry run accepted an unknown Profile category")
	}
	if !strings.Contains(stderr.String(), `unknown Profile category "agents"`) {
		t.Fatalf("unknown-category error is unclear: %s", stderr.String())
	}
}

func TestDryRunRequiresAnExistingNamedProfile(t *testing.T) {
	existingHome := t.TempDir()
	adapter, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: existingHome})
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	application := cli.App{
		Categories:       adapter.Categories(),
		DraftEditor:      adapter,
		Planner:          adapter,
		Profiles:         profile.NewStore(filepath.Join(existingHome, ".acs"), adapter.Categories()),
		WorkingDirectory: t.TempDir(),
		Input:            strings.NewReader(""),
		Output:           &bytes.Buffer{},
		ErrorOutput:      &stderr,
	}

	exitCode := application.Run(context.Background(), []string{"devin", "--profile", "missing", "--dry-run"})
	if exitCode == 0 {
		t.Fatal("dry run succeeded without an existing named Profile")
	}
	if !strings.Contains(stderr.String(), `load Profile "missing"`) || !strings.Contains(stderr.String(), "no such file") {
		t.Fatalf("missing-Profile error is unclear: %s", stderr.String())
	}
}

func TestDryRunRejectsMissingMovedAndAmbiguousSkillReferences(t *testing.T) {
	tests := []struct {
		name          string
		reference     skills.SkillReference
		catalog       []skills.SkillBundle
		wantErrorText string
	}{
		{
			name:      "moved",
			reference: skills.SkillReference{Source: "devin-config", RelativePath: "original-review"},
			catalog: []skills.SkillBundle{{
				Reference:   skills.SkillReference{Source: "devin-config", RelativePath: "moved-review"},
				DisplayName: "review",
				BundlePath:  "/global/devin/skills/moved-review",
			}},
			wantErrorText: `Skill Reference "devin-config:original-review" is missing`,
		},
		{
			name:      "ambiguous",
			reference: skills.SkillReference{Source: "devin-config", RelativePath: "review"},
			catalog: []skills.SkillBundle{
				{Reference: skills.SkillReference{Source: "devin-config", RelativePath: "review"}, DisplayName: "review", BundlePath: "/first/review"},
				{Reference: skills.SkillReference{Source: "devin-config", RelativePath: "review"}, DisplayName: "review", BundlePath: "/second/review"},
			},
			wantErrorText: `Skill Reference "devin-config:review" is ambiguous`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newStaticCategoryFixture(t, staticCatalog{bundles: test.catalog})
			profiles := profile.NewStore(t.TempDir(), fixture.registry)
			if _, err := profiles.Create(devin.NewSkillsProfile(test.name, []skills.SkillReference{test.reference})); err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			application := cli.App{
				Categories:       fixture.registry,
				DraftEditor:      fixture,
				Profiles:         profiles,
				WorkingDirectory: t.TempDir(),
				Input:            strings.NewReader(""),
				Output:           &bytes.Buffer{},
				ErrorOutput:      &stderr,
			}

			exitCode := application.Run(context.Background(), []string{"devin", "--profile", test.name, "--dry-run"})
			if exitCode == 0 {
				t.Fatalf("dry run succeeded with a %s Skill Reference", test.name)
			}
			if !strings.Contains(stderr.String(), test.wantErrorText) {
				t.Fatalf("%s-reference error is unclear: %s", test.name, stderr.String())
			}
		})
	}
}

func TestCreateProfileSelectsSameNamedSkillBundlesIndependently(t *testing.T) {
	acsHome := t.TempDir()
	catalog := staticCatalog{bundles: []skills.SkillBundle{
		{
			Reference:   skills.SkillReference{Source: "devin-config", RelativePath: "review"},
			DisplayName: "review",
			BundlePath:  "/global/devin/skills/review",
		},
		{
			Reference:   skills.SkillReference{Source: "shared-agents", RelativePath: "review"},
			DisplayName: "review",
			BundlePath:  "/global/agents/skills/review",
		},
	}}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	fixture := newStaticCategoryFixture(t, catalog)
	profiles := profile.NewStore(acsHome, fixture.registry)
	application := cli.App{
		Categories:  fixture.registry,
		DraftEditor: fixture,
		Profiles:    profiles,
		Input:       strings.NewReader("2,1\n"),
		Output:      &stdout,
		ErrorOutput: &stderr,
	}

	exitCode := application.Run(context.Background(), []string{"devin", "create-profile", "--name", "reviews"})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	for _, sourceDetail := range []string{
		"review [devin-config] /global/devin/skills/review",
		"review [shared-agents] /global/agents/skills/review",
	} {
		if !strings.Contains(stdout.String(), sourceDetail) {
			t.Errorf("selector output does not identify source %q:\n%s", sourceDetail, stdout.String())
		}
	}

	saved, err := profiles.Load("reviews")
	if err != nil {
		t.Fatalf("load created Profile: %v", err)
	}
	if saved.Version != profile.CurrentVersion {
		t.Fatalf("saved Profile version = %d, want %d", saved.Version, profile.CurrentVersion)
	}
	references, err := devin.SkillReferences(saved)
	if err != nil {
		t.Fatal(err)
	}
	wantReferences := []skills.SkillReference{
		{Source: "devin-config", RelativePath: "review"},
		{Source: "shared-agents", RelativePath: "review"},
	}
	if !reflect.DeepEqual(references, wantReferences) {
		t.Fatalf("saved Skill References = %#v, want %#v", references, wantReferences)
	}

	wantPath := filepath.Join(acsHome, "profiles", "reviews.json")
	if !strings.Contains(stdout.String(), wantPath) {
		t.Errorf("success output does not report Profile path %q:\n%s", wantPath, stdout.String())
	}
}

func TestCreateProfileEscapesCatalogControlCharactersInSelector(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	fixture := newStaticCategoryFixture(t, staticCatalog{bundles: []skills.SkillBundle{{
		Reference:   skills.SkillReference{Source: "devin-config", RelativePath: "review\nforged"},
		DisplayName: "review\nforged",
		BundlePath:  "/global/review\x1b[31m",
	}}})
	profiles := profile.NewStore(t.TempDir(), fixture.registry)
	application := cli.App{
		Categories:  fixture.registry,
		DraftEditor: fixture,
		Profiles:    profiles,
		Input:       strings.NewReader("1\n"),
		Output:      &stdout,
		ErrorOutput: &stderr,
	}

	if exitCode := application.Run(context.Background(), []string{"devin", "create-profile", "--name", "escaped"}); exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if strings.ContainsAny(stdout.String(), "\x1b") || strings.Contains(stdout.String(), "review\nforged") {
		t.Fatalf("selector contains raw terminal control characters: %q", stdout.String())
	}
	for _, escaped := range []string{`review\nforged`, `review\x1b[31m`} {
		if !strings.Contains(stdout.String(), escaped) {
			t.Errorf("selector does not visibly escape %q: %q", escaped, stdout.String())
		}
	}
}

func TestCreateProfileSavesEmptySelectionOnlyAfterExplicitConfirmation(t *testing.T) {
	acsHome := t.TempDir()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	fixture := newStaticCategoryFixture(t, staticCatalog{})
	profiles := profile.NewStore(acsHome, fixture.registry)
	application := cli.App{
		Categories:  fixture.registry,
		DraftEditor: fixture,
		Profiles:    profiles,
		Input:       strings.NewReader("\ny\n"),
		Output:      &stdout,
		ErrorOutput: &stderr,
	}

	exitCode := application.Run(context.Background(), []string{"devin", "create-profile", "--name", "empty"})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Create an empty Profile? [y/N]") {
		t.Fatalf("empty selection was not explicitly confirmed:\n%s", stdout.String())
	}
	saved, err := profiles.Load("empty")
	if err != nil {
		t.Fatalf("load empty Profile: %v", err)
	}
	references, err := devin.SkillReferences(saved)
	if err != nil {
		t.Fatal(err)
	}
	if references == nil || len(references) != 0 {
		t.Fatalf("saved Skill References = %#v, want a deliberate empty selection", references)
	}
	contents, err := os.ReadFile(filepath.Join(acsHome, "profiles", "empty.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(contents), `"selection": []`) || strings.Contains(string(contents), "skillReferences") {
		t.Fatalf("empty Profile does not persist an explicit version-2 Skills selection:\n%s", contents)
	}
}

func TestCreateProfileDoesNotSaveDeclinedEmptySelection(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	fixture := newStaticCategoryFixture(t, staticCatalog{})
	profiles := profile.NewStore(t.TempDir(), fixture.registry)
	application := cli.App{
		Categories:  fixture.registry,
		DraftEditor: fixture,
		Profiles:    profiles,
		Input:       strings.NewReader("\nn\n"),
		Output:      &stdout,
		ErrorOutput: &stderr,
	}

	exitCode := application.Run(context.Background(), []string{"devin", "create-profile", "--name", "declined"})
	if exitCode == 0 {
		t.Fatal("declined empty Profile was saved")
	}
	if !strings.Contains(stderr.String(), "not confirmed") {
		t.Fatalf("declined empty Profile error is unclear: %s", stderr.String())
	}
	if _, err := profiles.Load("declined"); !os.IsNotExist(err) {
		t.Fatalf("declined empty Profile exists: %v", err)
	}
}

func TestCreateProfileRejectsInvalidNameBeforeDiscoveryOrWrite(t *testing.T) {
	acsHome := t.TempDir()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	fixture := newStaticCategoryFixture(t, staticCatalog{err: errors.New("catalog should not be called")})
	profiles := profile.NewStore(acsHome, fixture.registry)
	application := cli.App{
		Categories:  fixture.registry,
		DraftEditor: fixture,
		Profiles:    profiles,
		Input:       strings.NewReader(""),
		Output:      &stdout,
		ErrorOutput: &stderr,
	}

	exitCode := application.Run(context.Background(), []string{"devin", "create-profile", "--name", "../escape"})
	if exitCode == 0 {
		t.Fatal("invalid Profile name was accepted")
	}
	if !strings.Contains(stderr.String(), "invalid Profile name") {
		t.Fatalf("invalid-name error is unclear: %s", stderr.String())
	}
	if _, err := os.Stat(filepath.Join(acsHome, "escape.json")); !os.IsNotExist(err) {
		t.Fatal("invalid Profile name escaped the Profile directory")
	}
	if stdout.Len() != 0 {
		t.Fatalf("invalid name started interactive discovery:\n%s", stdout.String())
	}
}

func TestCreateProfileRejectsDuplicateNameWithoutOverwriting(t *testing.T) {
	catalog := staticCatalog{bundles: []skills.SkillBundle{
		{Reference: skills.SkillReference{Source: "devin-config", RelativePath: "first"}, DisplayName: "first", BundlePath: "/devin/first"},
		{Reference: skills.SkillReference{Source: "shared-agents", RelativePath: "second"}, DisplayName: "second", BundlePath: "/agents/second"},
	}}
	fixture := newStaticCategoryFixture(t, catalog)
	profiles := profile.NewStore(t.TempDir(), fixture.registry)
	run := func(input string) (int, string) {
		t.Helper()
		var stderr bytes.Buffer
		application := cli.App{
			Categories:  fixture.registry,
			DraftEditor: fixture,
			Profiles:    profiles,
			Input:       strings.NewReader(input),
			Output:      &bytes.Buffer{},
			ErrorOutput: &stderr,
		}
		return application.Run(context.Background(), []string{"devin", "create-profile", "--name", "unique"}), stderr.String()
	}

	if exitCode, stderr := run("1\n"); exitCode != 0 {
		t.Fatalf("initial create failed with exit %d: %s", exitCode, stderr)
	}
	if exitCode, stderr := run("2\n"); exitCode == 0 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("duplicate create exit = %d, stderr = %q", exitCode, stderr)
	}
	saved, err := profiles.Load("unique")
	if err != nil {
		t.Fatal(err)
	}
	want := skills.SkillReference{Source: "devin-config", RelativePath: "first"}
	references, err := devin.SkillReferences(saved)
	if err != nil {
		t.Fatal(err)
	}
	if len(references) != 1 || references[0] != want {
		t.Fatalf("duplicate create overwrote original Profile: %#v", saved)
	}
}

func TestCreateProfileUsesTheInteractiveBuilderAndPersistsItsDraft(t *testing.T) {
	fixture := newStaticCategoryFixture(t, staticCatalog{})
	draft := fixture.registry.NewDraft()
	want := skills.SkillReference{Source: "devin-config", RelativePath: "review"}
	if err := category.SetSelection(&draft, fixture.binding, []skills.SkillReference{want}); err != nil {
		t.Fatal(err)
	}
	profileBuilder := &staticBuilder{outcome: builder.Outcome{Draft: draft, Create: true}}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	profiles := profile.NewStore(t.TempDir(), fixture.registry)
	application := cli.App{
		Categories:  fixture.registry,
		Builder:     profileBuilder,
		Profiles:    profiles,
		Input:       strings.NewReader(""),
		Output:      &stdout,
		ErrorOutput: &stderr,
		Interactive: func(io.Reader, io.Writer) bool { return true },
	}

	if exitCode := application.Run(context.Background(), []string{"devin", "create-profile", "--name", "reviews"}); exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
	}
	if !profileBuilder.called || profileBuilder.name != "reviews" {
		t.Fatalf("interactive Builder call = %#v, want one call for reviews", profileBuilder)
	}
	if strings.Contains(stdout.String(), "comma-separated numbers") {
		t.Fatalf("legacy numbered prompt was used:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "skills: 1 selected") {
		t.Fatalf("success summary does not contain category count:\n%s", stdout.String())
	}
	saved, err := profiles.Load("reviews")
	if err != nil {
		t.Fatal(err)
	}
	references, err := devin.SkillReferences(saved)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(references, []skills.SkillReference{want}) {
		t.Fatalf("saved references = %#v, want %#v", references, []skills.SkillReference{want})
	}
}

func TestCreateProfilePersistsSummarizesAndCancelsWithMultipleCategories(t *testing.T) {
	fixture := newStaticCategoryFixture(t, staticCatalog{})
	notes, err := category.Bind(category.Definition[string, string, noteContribution]{
		ID: "notes", SchemaVersion: 1, Empty: func() string { return "" },
		Resolve:    func(_ context.Context, selection string) (string, error) { return strings.ToUpper(selection), nil },
		Contribute: func(resolved string) (noteContribution, error) { return noteContribution{value: resolved}, nil },
		Count: func(selection string) int {
			if selection == "" {
				return 0
			}
			return 1
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", fixture.binding.Registration(), notes.Registration())
	if err != nil {
		t.Fatal(err)
	}
	draft := registry.NewDraft()
	if err := category.SetSelection(&draft, fixture.binding, []skills.SkillReference{{Source: "devin-config", RelativePath: "review"}}); err != nil {
		t.Fatal(err)
	}
	if err := category.SetSelection(&draft, notes, "category neutral"); err != nil {
		t.Fatal(err)
	}

	t.Run("create", func(t *testing.T) {
		profileBuilder := &staticBuilder{outcome: builder.Outcome{Draft: draft, Create: true}}
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		profiles := profile.NewStore(t.TempDir(), registry)
		application := cli.App{
			Categories: registry, Builder: profileBuilder, Profiles: profiles,
			Input: strings.NewReader(""), Output: &stdout, ErrorOutput: &stderr,
			Interactive: func(io.Reader, io.Writer) bool { return true },
		}
		if exitCode := application.Run(context.Background(), []string{"devin", "create-profile", "--name", "multi"}); exitCode != 0 {
			t.Fatalf("exit code = %d, stderr = %s", exitCode, stderr.String())
		}
		for _, summary := range []string{"skills: 1 selected", "notes: 1 selected"} {
			if !strings.Contains(stdout.String(), summary) {
				t.Errorf("success output omits %q:\n%s", summary, stdout.String())
			}
		}
		saved, err := profiles.Load("multi")
		if err != nil {
			t.Fatal(err)
		}
		if len(saved.Categories) != 2 {
			t.Fatalf("saved categories = %#v", saved.Categories)
		}
	})

	t.Run("cancel", func(t *testing.T) {
		profileBuilder := &staticBuilder{outcome: builder.Outcome{Draft: draft, Cancelled: true}}
		var stdout bytes.Buffer
		profiles := profile.NewStore(t.TempDir(), registry)
		application := cli.App{
			Categories: registry, Builder: profileBuilder, Profiles: profiles,
			Input: strings.NewReader(""), Output: &stdout, ErrorOutput: &bytes.Buffer{},
			Interactive: func(io.Reader, io.Writer) bool { return true },
		}
		if exitCode := application.Run(context.Background(), []string{"devin", "create-profile", "--name", "cancel-multi"}); exitCode != 130 {
			t.Fatalf("exit code = %d, want 130", exitCode)
		}
		if stdout.String() != "Profile creation cancelled.\n" {
			t.Fatalf("cancellation output = %q", stdout.String())
		}
		if _, err := profiles.Load("cancel-multi"); !os.IsNotExist(err) {
			t.Fatalf("cancelled multi-category Profile was written: %v", err)
		}
	})
}

func TestCreateProfileCancellationPrintsSummaryAndReturnsSignalExitCodeWithoutSaving(t *testing.T) {
	fixture := newStaticCategoryFixture(t, staticCatalog{})
	profileBuilder := &staticBuilder{outcome: builder.Outcome{Draft: fixture.registry.NewDraft(), Cancelled: true}}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	profiles := profile.NewStore(t.TempDir(), fixture.registry)
	application := cli.App{
		Categories: fixture.registry, Builder: profileBuilder, Profiles: profiles,
		Input: strings.NewReader(""), Output: &stdout, ErrorOutput: &stderr,
		Interactive: func(io.Reader, io.Writer) bool { return true },
	}

	if exitCode := application.Run(context.Background(), []string{"devin", "create-profile", "--name", "cancelled"}); exitCode != 130 {
		t.Fatalf("exit code = %d, want 130; stderr = %s", exitCode, stderr.String())
	}
	if stdout.String() != "Profile creation cancelled.\n" {
		t.Fatalf("cancellation summary = %q", stdout.String())
	}
	if _, err := profiles.Load("cancelled"); !os.IsNotExist(err) {
		t.Fatalf("cancelled Profile was written: %v", err)
	}
}

func TestCreateProfileRejectsNonInteractiveStreamsBeforeBuilderStarts(t *testing.T) {
	fixture := newStaticCategoryFixture(t, staticCatalog{})
	builder := &staticBuilder{}
	var stderr bytes.Buffer
	application := cli.App{
		Categories:  fixture.registry,
		Builder:     builder,
		Profiles:    profile.NewStore(t.TempDir(), fixture.registry),
		Input:       strings.NewReader(""),
		Output:      &bytes.Buffer{},
		ErrorOutput: &stderr,
		Interactive: func(io.Reader, io.Writer) bool { return false },
	}

	if exitCode := application.Run(context.Background(), []string{"devin", "create-profile", "--name", "reviews"}); exitCode == 0 {
		t.Fatal("non-interactive Profile creation succeeded")
	}
	if builder.called {
		t.Fatal("Builder started for non-interactive streams")
	}
	if !strings.Contains(stderr.String(), "interactive stdin and stdout") {
		t.Fatalf("TTY error = %q", stderr.String())
	}
}

type staticCatalog struct {
	bundles []skills.SkillBundle
	err     error
}

type staticBuilder struct {
	called  bool
	name    string
	outcome builder.Outcome
	err     error
}

func (stub *staticBuilder) BuildProfile(ctx context.Context, name string, _ category.Draft, save builder.SaveFunc, _ io.Reader, _ io.Writer) (builder.Outcome, error) {
	stub.called = true
	stub.name = name
	if stub.err == nil && stub.outcome.Create {
		path, err := save(ctx, stub.outcome.Draft)
		if err != nil {
			return builder.Outcome{}, err
		}
		stub.outcome.Path = path
	}
	return stub.outcome, stub.err
}

type staticCategoryFixture struct {
	registry *category.Registry
	binding  category.Binding[[]skills.SkillReference, []skills.SkillBundle, staticContribution]
	catalog  staticCatalog
}

type staticContribution struct{}

func (staticContribution) Plan(context.Context, string, *launch.Plan) error { return nil }
func (staticContribution) Materialize(string) error                         { return nil }
func (staticContribution) Verify(context.Context, launch.VerificationContext) error {
	return nil
}

func newStaticCategoryFixture(t *testing.T, catalog staticCatalog) staticCategoryFixture {
	t.Helper()
	binding, err := category.Bind(category.Definition[[]skills.SkillReference, []skills.SkillBundle, staticContribution]{
		ID:            "skills",
		SchemaVersion: 1,
		Empty:         func() []skills.SkillReference { return []skills.SkillReference{} },
		Encode: func(references []skills.SkillReference) (json.RawMessage, error) {
			ordered := append([]skills.SkillReference(nil), references...)
			if ordered == nil {
				ordered = []skills.SkillReference{}
			}
			sort.Slice(ordered, func(left, right int) bool {
				if ordered[left].Source != ordered[right].Source {
					return ordered[left].Source < ordered[right].Source
				}
				return ordered[left].RelativePath < ordered[right].RelativePath
			})
			return json.Marshal(ordered)
		},
		Resolve: func(ctx context.Context, references []skills.SkillReference) ([]skills.SkillBundle, error) {
			bundles, err := catalog.DiscoverGlobalSkillCatalog(ctx)
			if err != nil {
				return nil, err
			}
			return skills.ResolveReferences(references, bundles)
		},
		Contribute: func([]skills.SkillBundle) (staticContribution, error) { return staticContribution{}, nil },
		Count:      func(references []skills.SkillReference) int { return len(references) },
	})
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	return staticCategoryFixture{registry: registry, binding: binding, catalog: catalog}
}

func (fixture staticCategoryFixture) EditProfileDraft(ctx context.Context, draft category.Draft, input io.Reader, output io.Writer) (category.Draft, error) {
	bundles, err := fixture.catalog.DiscoverGlobalSkillCatalog(ctx)
	if err != nil {
		return draft, err
	}
	fmt.Fprintln(output, "Select global Skill Bundles:")
	for index, bundle := range bundles {
		fmt.Fprintf(output, "  %d. %s [%s] %s\n", index+1, escaped(bundle.DisplayName), escaped(string(bundle.Reference.Source)), escaped(bundle.BundlePath))
	}
	fmt.Fprint(output, "\nEnter comma-separated numbers (blank for none): ")
	reader := bufio.NewReader(input)
	line, readErr := reader.ReadString('\n')
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return draft, readErr
	}
	line = strings.TrimSpace(line)
	selected := make([]skills.SkillReference, 0)
	seen := make(map[int]bool)
	if line != "" {
		for _, raw := range strings.Split(line, ",") {
			index, conversionErr := strconv.Atoi(strings.TrimSpace(raw))
			if conversionErr != nil || index < 1 || index > len(bundles) {
				return draft, fmt.Errorf("invalid selection: %q is not a displayed Skill Bundle number", raw)
			}
			if !seen[index] {
				selected = append(selected, bundles[index-1].Reference)
				seen[index] = true
			}
		}
	} else {
		fmt.Fprint(output, "Create an empty Profile? [y/N] ")
		confirmation, confirmationErr := reader.ReadString('\n')
		if confirmationErr != nil && !errors.Is(confirmationErr, io.EOF) {
			return draft, confirmationErr
		}
		answer := strings.ToLower(strings.TrimSpace(confirmation))
		if answer != "y" && answer != "yes" {
			return draft, errors.New("empty Profile was not confirmed; Profile not created")
		}
	}
	if err := category.SetSelection(&draft, fixture.binding, selected); err != nil {
		return draft, err
	}
	return draft, nil
}

func escaped(value string) string {
	quoted := strconv.QuoteToASCII(value)
	return quoted[1 : len(quoted)-1]
}

type launchTestFixture struct {
	existingHome      string
	profiles          *profile.Store
	sessionsDirectory string
	sandbox           launch.ProcessSandbox
}

func newLaunchTestFixture(t *testing.T) launchTestFixture {
	t.Helper()
	existingHome := t.TempDir()
	acsHome := filepath.Join(existingHome, ".acs")
	bundlePath := filepath.Join(existingHome, ".config", "devin", "skills", "review")
	if err := os.MkdirAll(bundlePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundlePath, "SKILL.md"), []byte("# review\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	adapter, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: existingHome})
	if err != nil {
		t.Fatal(err)
	}
	profiles := profile.NewStore(acsHome, adapter.Categories())
	if _, err := profiles.Create(devin.NewSkillsProfile("reviews", []skills.SkillReference{{
		Source:       devin.GlobalSourceDevinConfig,
		RelativePath: "review",
	}})); err != nil {
		t.Fatal(err)
	}
	return launchTestFixture{
		existingHome:      existingHome,
		profiles:          profiles,
		sessionsDirectory: filepath.Join(acsHome, "sessions"),
		sandbox:           directSandbox{},
	}
}

func (fixture launchTestFixture) application(
	t *testing.T,
	binaryPath string,
	workingDirectory string,
	input io.Reader,
	output io.Writer,
	errorOutput io.Writer,
) cli.App {
	t.Helper()
	adapter, err := newAdapterWithSandbox(devin.Config{BinaryPath: binaryPath, ExistingHomeDir: fixture.existingHome}, fixture.sandbox)
	if err != nil {
		t.Fatal(err)
	}
	return cli.App{
		Categories:        adapter.Categories(),
		DraftEditor:       adapter,
		Planner:           adapter,
		Launcher:          adapter,
		Profiles:          fixture.profiles,
		SessionsDirectory: fixture.sessionsDirectory,
		WorkingDirectory:  workingDirectory,
		Input:             input,
		Output:            output,
		ErrorOutput:       errorOutput,
	}
}

type recordingSandbox struct {
	delegate  launch.ProcessSandbox
	arguments [][]string
}

func (sandbox *recordingSandbox) Check(ctx context.Context, request launch.SandboxCheck) error {
	return sandbox.delegate.Check(ctx, request)
}

func (sandbox *recordingSandbox) Prepare(ctx context.Context, request launch.ProcessRequest) (launch.Process, error) {
	sandbox.arguments = append(sandbox.arguments, append([]string(nil), request.Arguments...))
	return sandbox.delegate.Prepare(ctx, request)
}

type failingSandbox struct {
	checkErr   error
	prepareErr error
}

func (sandbox failingSandbox) Check(context.Context, launch.SandboxCheck) error {
	return sandbox.checkErr
}

func (sandbox failingSandbox) Prepare(context.Context, launch.ProcessRequest) (launch.Process, error) {
	return nil, sandbox.prepareErr
}

func writeFakeDevin(t *testing.T, script string) string {
	t.Helper()
	binaryPath := filepath.Join(t.TempDir(), "devin")
	if err := os.WriteFile(binaryPath, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return binaryPath
}

func successfulDevinScript(interactiveBody string) string {
	return `#!/bin/sh
if [ "$1" = "skills" ]; then
  printf '[{"name":"review","provider":"Devin","base_dir":"%s"}]\n' "$HOME/.config/devin/skills/review"
  exit 0
fi
if [ "$1" = "auth" ]; then
  printf 'Logged in (via fixture).\n'
  exit 0
fi
` + interactiveBody
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q", path)
}

func writeVersionOneProfile(t *testing.T, acsHome, name string) (string, []byte) {
	t.Helper()
	profilesDirectory := filepath.Join(acsHome, "profiles")
	if err := os.MkdirAll(profilesDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	contents := []byte(fmt.Sprintf(
		`{"version":1,"name":%q,"target":"devin","skillReferences":[{"source":"devin-config","relativePath":"review"}]}`,
		name,
	))
	path := filepath.Join(profilesDirectory, name+".json")
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, contents
}

func assertFileContents(t *testing.T, path string, want []byte, message string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: %s", message, got)
	}
}

func (catalog staticCatalog) DiscoverGlobalSkillCatalog(context.Context) ([]skills.SkillBundle, error) {
	return catalog.bundles, catalog.err
}
