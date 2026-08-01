package cli_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func TestDryRunReportsResolvedGlobalAndInheritedProjectSkillBundlesWithoutCreatingSession(t *testing.T) {
	existingHome := t.TempDir()
	acsHome := filepath.Join(existingHome, ".acs")
	profiles := profile.NewStore(acsHome)
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
	if _, err := profiles.Create(profile.Profile{
		Version: profile.CurrentVersion,
		Name:    "reviews",
		Target:  "devin",
		SkillReferences: []skills.SkillReference{{
			Source:       devin.GlobalSourceDevinConfig,
			RelativePath: "review",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	adapter, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: existingHome})
	if err != nil {
		t.Fatal(err)
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := cli.App{
		Catalog:          adapter,
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

func TestLaunchRunsPreflightBeforeInteractiveDevinAndCleansUpSession(t *testing.T) {
	fixture := newLaunchTestFixture(t)
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
	entries, err := os.ReadDir(fixture.sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("launch left Session data behind: %v", entries)
	}
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
  printf '[{"name":"unselected","provider":"Devin","base_dir":"%s"}]\n' "$HOME/.config/devin/skills/unselected"
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
	for _, identity := range []string{"expected global Skill Catalog [devin-config:review]", "observed [devin-config:unselected]"} {
		if !strings.Contains(stderr.String(), identity) {
			t.Errorf("preflight diagnostic does not contain %q: %s", identity, stderr.String())
		}
	}
	if strings.Contains(stderr.String(), "SUPER_SECRET") {
		t.Fatalf("preflight diagnostic leaked subprocess output: %s", stderr.String())
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
	profiles := profile.NewStore(acsHome)
	if _, err := profiles.Create(profile.Profile{
		Version: profile.CurrentVersion,
		Name:    "missing",
		Target:  "devin",
		SkillReferences: []skills.SkillReference{{
			Source:       devin.GlobalSourceDevinConfig,
			RelativePath: "not-installed\n\x1b[31m",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	adapter, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: existingHome})
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	sessionsDirectory := filepath.Join(acsHome, "sessions")
	application := cli.App{
		Catalog:           adapter,
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
	profiles := profile.NewStore(acsHome)
	if _, err := profiles.Create(profile.Profile{
		Version:         profile.CurrentVersion,
		Name:            "other-cli",
		Target:          "codex",
		SkillReferences: []skills.SkillReference{},
	}); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	sessionsDirectory := filepath.Join(acsHome, "sessions")
	application := cli.App{
		Profiles:          profiles,
		SessionsDirectory: sessionsDirectory,
		ErrorOutput:       &stderr,
	}

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "other-cli"}); exitCode == 0 {
		t.Fatal("launch accepted a Profile for another CLI")
	}
	if !strings.Contains(stderr.String(), `Profile "other-cli" targets "codex", not Devin`) {
		t.Fatalf("wrong-target error is unclear: %s", stderr.String())
	}
	if _, err := os.Stat(sessionsDirectory); !os.IsNotExist(err) {
		t.Fatalf("wrong-target Profile created a Session directory: %v", err)
	}
}

func TestLaunchRejectsUnsupportedProfileSchemaVersionBeforeCreatingSession(t *testing.T) {
	existingHome := t.TempDir()
	acsHome := filepath.Join(existingHome, ".acs")
	profiles := profile.NewStore(acsHome)
	if _, err := profiles.Create(profile.Profile{
		Version:         profile.CurrentVersion + 1,
		Name:            "future",
		Target:          "devin",
		SkillReferences: []skills.SkillReference{},
	}); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	sessionsDirectory := filepath.Join(acsHome, "sessions")
	application := cli.App{
		Profiles:          profiles,
		SessionsDirectory: sessionsDirectory,
		ErrorOutput:       &stderr,
	}

	if exitCode := application.Run(context.Background(), []string{"devin", "--profile", "future"}); exitCode == 0 {
		t.Fatal("launch accepted an unsupported Profile schema version")
	}
	if !strings.Contains(stderr.String(), `Profile "future" uses unsupported schema version 2`) {
		t.Fatalf("unsupported-version error is unclear: %s", stderr.String())
	}
	if _, err := os.Stat(sessionsDirectory); !os.IsNotExist(err) {
		t.Fatalf("unsupported Profile version created a Session directory: %v", err)
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
		Catalog:          adapter,
		Planner:          adapter,
		Profiles:         profile.NewStore(filepath.Join(existingHome, ".acs")),
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
			profiles := profile.NewStore(t.TempDir())
			if _, err := profiles.Create(profile.Profile{
				Version:         profile.CurrentVersion,
				Name:            test.name,
				Target:          "devin",
				SkillReferences: []skills.SkillReference{test.reference},
			}); err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			application := cli.App{
				Catalog:          staticCatalog{bundles: test.catalog},
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
	profiles := profile.NewStore(acsHome)
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
	application := cli.App{
		Catalog:     catalog,
		Profiles:    profiles,
		Input:       strings.NewReader("1,2\n"),
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
	want := profile.Profile{
		Version: 1,
		Name:    "reviews",
		Target:  "devin",
		SkillReferences: []skills.SkillReference{
			{Source: "devin-config", RelativePath: "review"},
			{Source: "shared-agents", RelativePath: "review"},
		},
	}
	if !reflect.DeepEqual(saved, want) {
		t.Fatalf("saved Profile = %#v, want %#v", saved, want)
	}

	wantPath := filepath.Join(acsHome, "profiles", "reviews.json")
	if !strings.Contains(stdout.String(), wantPath) {
		t.Errorf("success output does not report Profile path %q:\n%s", wantPath, stdout.String())
	}
}

func TestCreateProfileEscapesCatalogControlCharactersInSelector(t *testing.T) {
	profiles := profile.NewStore(t.TempDir())
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := cli.App{
		Catalog: staticCatalog{bundles: []skills.SkillBundle{{
			Reference:   skills.SkillReference{Source: "devin-config", RelativePath: "review\nforged"},
			DisplayName: "review\nforged",
			BundlePath:  "/global/review\x1b[31m",
		}}},
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
	profiles := profile.NewStore(t.TempDir())
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := cli.App{
		Catalog:     staticCatalog{},
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
	if saved.SkillReferences == nil || len(saved.SkillReferences) != 0 {
		t.Fatalf("saved Skill References = %#v, want a deliberate empty selection", saved.SkillReferences)
	}
}

func TestCreateProfileDoesNotSaveDeclinedEmptySelection(t *testing.T) {
	profiles := profile.NewStore(t.TempDir())
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := cli.App{
		Catalog:     staticCatalog{},
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
	profiles := profile.NewStore(acsHome)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	application := cli.App{
		Catalog:     staticCatalog{err: errors.New("catalog should not be called")},
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
	profiles := profile.NewStore(t.TempDir())
	catalog := staticCatalog{bundles: []skills.SkillBundle{
		{Reference: skills.SkillReference{Source: "devin-config", RelativePath: "first"}, DisplayName: "first", BundlePath: "/devin/first"},
		{Reference: skills.SkillReference{Source: "shared-agents", RelativePath: "second"}, DisplayName: "second", BundlePath: "/agents/second"},
	}}
	run := func(input string) (int, string) {
		t.Helper()
		var stderr bytes.Buffer
		application := cli.App{
			Catalog:     catalog,
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
	if len(saved.SkillReferences) != 1 || saved.SkillReferences[0] != want {
		t.Fatalf("duplicate create overwrote original Profile: %#v", saved)
	}
}

type staticCatalog struct {
	bundles []skills.SkillBundle
	err     error
}

type launchTestFixture struct {
	existingHome      string
	profiles          *profile.Store
	sessionsDirectory string
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
	profiles := profile.NewStore(acsHome)
	if _, err := profiles.Create(profile.Profile{
		Version: profile.CurrentVersion,
		Name:    "reviews",
		Target:  "devin",
		SkillReferences: []skills.SkillReference{{
			Source:       devin.GlobalSourceDevinConfig,
			RelativePath: "review",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	return launchTestFixture{
		existingHome:      existingHome,
		profiles:          profiles,
		sessionsDirectory: filepath.Join(acsHome, "sessions"),
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
	adapter, err := devin.New(devin.Config{BinaryPath: binaryPath, ExistingHomeDir: fixture.existingHome})
	if err != nil {
		t.Fatal(err)
	}
	return cli.App{
		Catalog:           adapter,
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

func (catalog staticCatalog) DiscoverGlobalSkillCatalog(context.Context) ([]skills.SkillBundle, error) {
	return catalog.bundles, catalog.err
}
