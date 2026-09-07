//go:build darwin

package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/charmbracelet/x/term"
	"github.com/creack/pty"
)

const (
	fakeDevinConfigurationName  = ".acs-native-candidate-fixture.json"
	fakeDevinResultName         = ".acs-native-candidate-result.json"
	fakeDevinSkillsProbeMarker  = ".acs-native-skills-probe"
	fakeDevinAuthProbeMarker    = ".acs-native-auth-probe"
	privateEnvironmentValue     = "candidate-secret-value"
	privateDescriptorValue      = "candidate-descriptor-value"
	fakeDevinDescendantExitWait = 3 * time.Second
)

// TestMain also makes this test executable a credential-free fake Devin. The
// installed ACS candidate resolves it like a normal target executable; no test
// hook, build tag, or environment variable is available to the candidate.
func TestMain(m *testing.M) {
	if runPromotedArtifactGenericHelper(os.Args[1:]) {
		return
	}
	if runPromotedArtifactFakeDevin(os.Args[1:]) {
		return
	}
	os.Exit(m.Run())
}

func TestFakeDevinDescendantWaitsForControlledRelease(t *testing.T) {
	workspace := t.TempDir()
	command := exec.Command(os.Args[0], "--acs-native-candidate-descendant")
	command.Dir = workspace
	command.Env = os.Environ()
	command.Stdin = nil
	command.Stdout = nil
	command.Stderr = nil
	if err := command.Start(); err != nil {
		t.Fatal("could not start the descendant fixture")
	}

	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	finished := false
	t.Cleanup(func() {
		if !finished {
			_ = releaseFakeDevinDescendant(workspace)
			select {
			case <-done:
				finished = true
			case <-time.After(fakeDevinDescendantExitWait):
				_ = command.Process.Kill()
				select {
				case <-done:
					finished = true
				case <-time.After(fakeDevinDescendantExitWait):
					t.Error("descendant fixture did not exit after bounded cleanup")
				}
			}
		}
	})

	if !waitForFakeDevinMarker(filepath.Join(workspace, "descendant-ready"), time.Second) {
		t.Fatal("descendant fixture did not become ready")
	}
	deadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			finished = true
			t.Fatalf("descendant fixture exited before the controlled release: %v", err)
		default:
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := releaseFakeDevinDescendant(workspace); err != nil {
		t.Fatal("could not release descendant fixture")
	}
	if !waitForFakeDevinMarker(filepath.Join(workspace, "descendant-acknowledged"), time.Second) {
		t.Fatal("descendant fixture did not acknowledge the controlled release")
	}
	select {
	case err := <-done:
		finished = true
		if err != nil {
			t.Fatal("descendant fixture failed after the controlled release")
		}
	case <-time.After(fakeDevinDescendantExitWait):
		t.Fatal("descendant fixture did not exit after the controlled release")
	}
}

func TestReleaseFakeDevinDescendantReportsReleaseMarkerWriteFailure(t *testing.T) {
	workspace := filepath.Join(t.TempDir(), "not-a-workspace")
	if err := os.WriteFile(workspace, []byte("fixture\n"), 0o600); err != nil {
		t.Fatal("could not create the release fixture")
	}

	if err := releaseFakeDevinDescendant(workspace); err == nil {
		t.Fatal("release helper did not report a release-marker write failure")
	}
}

func TestPromotedArtifactNativeContainmentContract(t *testing.T) {
	_ = promotedBinary(t)
	if promotedSandboxCapability(t) != "available" {
		t.Skip("native containment requires the configured native backend")
	}

	t.Run("readiness is native and sanitized", assertPromotedArtifactNativeReadiness)
	t.Run("effective explanation is linked and narrowly observed", assertPromotedArtifactEffectiveExplanation)
	t.Run("sandbox shell is credential-free contained and cleaned", assertPromotedArtifactSandboxShell)
	t.Run("v3 common material and workspace modes are enforced", assertPromotedArtifactV3WorkspaceModes)
	t.Run("generic literal command uses candidate containment", assertPromotedArtifactGenericRun)
	t.Run("filesystem environment descriptors sockets IP preflight and descendants", assertPromotedArtifactNativeContainment)
	t.Run("preflight failure is categorized without target details", assertPromotedArtifactNativePreflightFailureIsSafe)
	t.Run("missing backend OR invalid policy cannot start a marker", assertPromotedArtifactMissingBackendFailsClosed)
}

func assertPromotedArtifactEffectiveExplanation(t *testing.T) {
	binary := promotedBinary(t)
	home, path := prepareRuntimeHome(t)
	writeSharedTargetProfile(t, home, "explanation", "read-only")
	workspace := realTemporaryDirectory(t)
	helper, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, recipe string
		explain      []string
		execute      []string
	}{
		{name: "sandbox", recipe: "shell", explain: []string{"explain", "sandbox", "--profile", "explanation", "--json"}, execute: []string{"sandbox", "--profile", "explanation", "--dry-run"}},
		{name: "devin", recipe: "devin", explain: []string{"explain", "devin", "--profile", "explanation", "--json"}, execute: []string{"devin", "--profile", "explanation", "--dry-run"}},
		{name: "codex", recipe: "codex", explain: []string{"explain", "codex", "--profile", "explanation", "--auth", "work", "--json"}, execute: []string{"codex", "--profile", "explanation", "--auth", "work", "--dry-run"}},
		{name: "run", recipe: "command", explain: []string{"explain", "run", "--profile", "explanation", "--json", "--", helper, "PRIVATE_NATIVE_ARGUMENT"}, execute: []string{"run", "--profile", "explanation", "--dry-run", "--", helper, "PRIVATE_NATIVE_ARGUMENT"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command(binary, test.explain...)
			command.Dir, command.Env = workspace, nativeCandidateEnvironment(home, path, nil)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("explain: %v; output=%s", err, output)
			}
			if bytes.Contains(output, []byte("PRIVATE_NATIVE_ARGUMENT")) || bytes.Contains(output, []byte(home)) || bytes.Contains(output, []byte(workspace)) {
				t.Fatalf("explanation exposed a private binding: %s", output)
			}
			var result struct {
				FormatVersion int `json:"formatVersion"`
				Intent        struct {
					Recipe string `json:"recipe"`
				} `json:"intent"`
				Plan struct {
					Digest      string                  `json:"authorityDigest"`
					Requested   []nativeExplanationFact `json:"requested"`
					TargetAdded []nativeExplanationFact `json:"targetAdded"`
					Effective   []nativeExplanationFact `json:"effective"`
					Unsupported []nativeExplanationFact `json:"unsupported"`
				} `json:"plan"`
				Checks []nativeExplanationCheck `json:"checks"`
			}
			if err := json.Unmarshal(output, &result); err != nil || result.FormatVersion != 1 || result.Intent.Recipe != test.recipe || !strings.HasPrefix(result.Plan.Digest, "sha256:") {
				t.Fatalf("invalid explanation: %v; output=%s", err, output)
			}
			for _, id := range []string{"runtime.devices", "runtime.mach-services", "runtime.metadata", "runtime.network", "runtime.sysctls"} {
				found := false
				for _, fact := range result.Plan.Effective {
					found = found || fact.ID == id
				}
				if !found {
					t.Fatalf("explanation omitted %s: %s", id, output)
				}
			}
			for _, id := range []string{"execution.recipe", "common.workspace"} {
				if !nativeExplanationHasFact(result.Plan.Requested, id) {
					t.Fatalf("requested facts omitted %s: %s", id, output)
				}
			}
			for _, id := range []string{"unsupported.arbitrary-executables", "unsupported.arbitrary-host-paths", "unsupported.host-environment", "unsupported.network-destinations", "unsupported.raw-policy", "unsupported.sandbox-bypass", "unsupported.target-pass-through"} {
				if !nativeExplanationHasFact(result.Plan.Unsupported, id) {
					t.Fatalf("unsupported facts omitted %s: %s", id, output)
				}
			}
			if !nativeExplanationHasCheck(result.Checks, "native.platform", "unchecked", "not_probed") || !nativeExplanationHasCheck(result.Checks, "native.backend", "unchecked", "not_probed") {
				t.Fatalf("default explanation performed or misreported native readiness: %s", output)
			}
			for _, id := range map[string][]string{
				"sandbox": {"sandbox.shell"},
				"devin":   {"devin.credentials", "devin.preflight.authentication", "devin.preflight.skills", "devin.project-skills", "target.executable"},
				"codex":   {"codex.approval", "codex.auth-storage", "codex.credentials", "codex.mcp", "codex.plugins", "codex.sandbox", "target.executable"},
				"run":     {"run.command"},
			}[test.name] {
				if !nativeExplanationHasFact(result.Plan.TargetAdded, id) {
					t.Fatalf("target-added facts omitted %s: %s", id, output)
				}
			}
			facts := map[string]struct {
				Mode  string
				Names []string
			}{}
			for _, fact := range result.Plan.Effective {
				facts[fact.ID] = struct {
					Mode  string
					Names []string
				}{fact.Value.Mode, fact.Value.Names}
			}
			if got := facts["runtime.network"].Mode; got != "local-ip-bind-and-coarse-outbound-ip-macos-dns" {
				t.Fatalf("network declaration = %q", got)
			}
			if got := facts["runtime.sysctls"].Names; !reflect.DeepEqual(got, []string{"hw.pagesize", "hw.pagesize_compat", "hw.ncpu"}) {
				t.Fatalf("sysctl declaration = %q", got)
			}
			if got := facts["runtime.mach-services"].Names; !reflect.DeepEqual(got, []string{"com.apple.SecurityServer", "com.apple.trustd.agent"}) {
				t.Fatalf("Mach-service declaration = %q", got)
			}
			linked := append(append([]string(nil), test.execute...), "--expect-authority-digest", result.Plan.Digest)
			// The run grammar requires the expectation before the literal boundary.
			if test.name == "run" {
				linked = []string{"run", "--profile", "explanation", "--dry-run", "--expect-authority-digest", result.Plan.Digest, "--", helper, "PRIVATE_NATIVE_ARGUMENT"}
			}
			linkedCommand := exec.Command(binary, linked...)
			linkedCommand.Dir, linkedCommand.Env = workspace, nativeCandidateEnvironment(home, path, nil)
			if linkedOutput, err := linkedCommand.CombinedOutput(); err != nil {
				t.Fatalf("linked dry-run: %v; output=%s", err, linkedOutput)
			}
			assertNoSessions(t, home)
			mismatch := "sha256:" + strings.Repeat("0", 64)
			mismatchArguments := []string{test.name, "--profile", "explanation", "--expect-authority-digest", mismatch}
			switch test.name {
			case "codex":
				mismatchArguments = append(mismatchArguments, "--auth", "work")
			case "run":
				mismatchArguments = append(mismatchArguments, "--", helper, "PRIVATE_NATIVE_ARGUMENT")
			}
			mismatchCommand := exec.Command(binary, mismatchArguments...)
			mismatchCommand.Dir, mismatchCommand.Env = workspace, nativeCandidateEnvironment(home, path, nil)
			mismatchOutput, mismatchErr := mismatchCommand.CombinedOutput()
			if mismatchErr == nil || !bytes.Contains(mismatchOutput, []byte("authority_plan_changed")) {
				t.Fatalf("mismatch did not fail at semantic guard: err=%v output=%s", mismatchErr, mismatchOutput)
			}
			assertNoSessions(t, home)
		})
	}
	readiness := exec.Command(binary, "explain", "sandbox", "--profile", "explanation", "--check-native-readiness", "--json")
	readiness.Dir, readiness.Env = workspace, nativeCandidateEnvironment(home, path, nil)
	output, err := readiness.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte(`"id":"native.backend","status":"pass","code":"backend_ready"`)) || !bytes.Contains(output, []byte(`"id":"runtime.enforcement","status":"unchecked"`)) {
		t.Fatalf("bounded native readiness: %v; output=%s", err, output)
	}
	assertNoSessions(t, home)
}

type nativeExplanationFact struct {
	ID    string `json:"id"`
	Value struct {
		Access string   `json:"access"`
		Mode   string   `json:"mode"`
		Names  []string `json:"names"`
	} `json:"value"`
}

type nativeExplanationCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Code   string `json:"code"`
}

func nativeExplanationHasFact(facts []nativeExplanationFact, id string) bool {
	for _, fact := range facts {
		if fact.ID == id {
			return true
		}
	}
	return false
}

func nativeExplanationFactByID(facts []nativeExplanationFact, id string) (nativeExplanationFact, bool) {
	for _, fact := range facts {
		if fact.ID == id {
			return fact, true
		}
	}
	return nativeExplanationFact{}, false
}

func nativeExplanationHasCheck(checks []nativeExplanationCheck, id, status, code string) bool {
	for _, check := range checks {
		if check.ID == id && check.Status == status && check.Code == code {
			return true
		}
	}
	return false
}

type genericHelperObservation struct {
	Arguments       []string `json:"arguments"`
	Input           string   `json:"input"`
	SafePath        bool     `json:"safePath"`
	HostSecretGone  bool     `json:"hostSecretGone"`
	HomeIsSynthetic bool     `json:"homeIsSynthetic"`
	WorkspaceWrite  bool     `json:"workspaceWrite"`
	ExternalRead    bool     `json:"externalRead"`
	ExternalWrite   bool     `json:"externalWrite"`
}

func runPromotedArtifactGenericHelper(arguments []string) bool {
	if len(arguments) == 0 || arguments[0] != "--acs-generic-command-helper" {
		return false
	}
	if len(arguments) >= 2 {
		switch arguments[1] {
		case "--exit-23":
			os.Exit(23)
		case "--wait-signal":
			signals := make(chan os.Signal, 1)
			signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
			_ = os.WriteFile("generic-signal-ready", []byte("ready\n"), 0o600)
			<-signals
			os.Exit(42)
		case "--descendant-parent":
			if len(arguments) < 3 {
				os.Exit(96)
			}
			child := exec.Command(os.Args[0], "--acs-generic-command-helper", "--descendant-child", arguments[2])
			child.Dir, child.Env = mustGetwd(), os.Environ()
			if err := child.Start(); err != nil || !waitForFakeDevinMarker(arguments[2], 2*time.Second) {
				os.Exit(95)
			}
			return true
		case "--descendant-child":
			if len(arguments) < 3 || os.WriteFile(arguments[2], []byte(strconv.Itoa(os.Getpid())), 0o600) != nil {
				os.Exit(94)
			}
			select {}
		case "--pty-resize":
			if !term.IsTerminal(os.Stdin.Fd()) || !term.IsTerminal(os.Stdout.Fd()) || !term.IsTerminal(os.Stderr.Fd()) {
				os.Exit(93)
			}
			signals := make(chan os.Signal, 1)
			signal.Notify(signals, syscall.SIGWINCH)
			_, _ = fmt.Fprintln(os.Stdout, "generic-pty-ready")
			<-signals
			width, height, err := term.GetSize(os.Stdin.Fd())
			if err != nil {
				os.Exit(92)
			}
			_, _ = fmt.Fprintf(os.Stdout, "generic-pty-size:%d:%d\n", width, height)
			return true
		}
	}
	if len(arguments) < 3 {
		os.Exit(97)
	}
	input, _ := io.ReadAll(os.Stdin)
	observation := genericHelperObservation{
		Arguments: append([]string(nil), arguments[3:]...), Input: string(input),
		SafePath:        os.Getenv("PATH") == "/usr/local/bin:/usr/bin:/bin",
		HostSecretGone:  os.Getenv("ACS_GENERIC_HOST_SECRET") == "",
		HomeIsSynthetic: strings.Contains(os.Getenv("HOME"), string(filepath.Separator)+"sessions"+string(filepath.Separator)),
	}
	observation.WorkspaceWrite = os.WriteFile("generic-workspace-write", []byte("ok\n"), 0o600) == nil
	_, readErr := os.ReadFile(arguments[1])
	observation.ExternalRead = readErr == nil
	observation.ExternalWrite = os.WriteFile(arguments[2], []byte("bad\n"), 0o600) == nil
	_ = json.NewEncoder(os.Stdout).Encode(observation)
	_, _ = fmt.Fprintln(os.Stderr, "generic-stderr-ok")
	return true
}

func assertPromotedArtifactGenericRun(t *testing.T) {
	binary := promotedBinary(t)
	helper, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	home, path := prepareRuntimeHome(t)
	sharedSkill := filepath.Join(home, ".agents", "skills", "delivery")
	if err := os.MkdirAll(sharedSkill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sharedSkill, "SKILL.md"), []byte("# delivery\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeSharedTargetProfile(t, home, "generic-readwrite", "read-write")
	writeSharedTargetProfile(t, home, "generic-readonly", "read-only")
	workspace := realTemporaryDirectory(t)
	external := realTemporaryDirectory(t)
	externalSecret := filepath.Join(external, "secret")
	externalWrite := filepath.Join(external, "write")
	if err := os.WriteFile(externalSecret, []byte("private\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	privateArgument := "private-argument-must-not-appear"
	dryRun := exec.Command(binary, "run", "--dry-run", "--profile", "generic-readwrite", "--", helper, privateArgument)
	dryRun.Dir = workspace
	dryRun.Env = nativeCandidateEnvironment(home, path, map[string]string{"ACS_GENERIC_HOST_SECRET": "hidden"})
	requireEnvironmentEntry(t, dryRun.Env, "ACS_GENERIC_HOST_SECRET=hidden")
	dryOutput, err := dryRun.CombinedOutput()
	if err != nil {
		t.Fatalf("generic dry-run: %v; output=%s", err, dryOutput)
	}
	if bytes.Contains(dryOutput, []byte(helper)) || bytes.Contains(dryOutput, []byte(privateArgument)) {
		t.Fatalf("generic dry-run leaked executable or argument: %s", dryOutput)
	}
	for _, marker := range []string{"literal child arguments: 1 (values hidden)", "implicit evaluation: none", "No Session or process was created."} {
		if !bytes.Contains(dryOutput, []byte(marker)) {
			t.Fatalf("generic dry-run omitted %q: %s", marker, dryOutput)
		}
	}
	assertNoSessions(t, home)

	command := exec.Command(binary, "run", "--profile", "generic-readwrite", "--", helper,
		"--acs-generic-command-helper", externalSecret, externalWrite, "space value", "", "--", "*.go", "$HOME")
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, path, map[string]string{"ACS_GENERIC_HOST_SECRET": "hidden"})
	requireEnvironmentEntry(t, command.Env, "ACS_GENERIC_HOST_SECRET=hidden")
	command.Stdin = strings.NewReader("pipe-input")
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("generic run: %v; stderr=%s", err, stderr.String())
	}
	var observation genericHelperObservation
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &observation); err != nil {
		t.Fatalf("decode observation: %v; output=%s", err, stdout.String())
	}
	wantArguments := []string{"space value", "", "--", "*.go", "$HOME"}
	if !reflect.DeepEqual(observation.Arguments, wantArguments) || observation.Input != "pipe-input" ||
		!observation.SafePath || !observation.HostSecretGone || !observation.HomeIsSynthetic ||
		!observation.WorkspaceWrite || observation.ExternalRead || observation.ExternalWrite {
		t.Fatalf("generic observation = %#v", observation)
	}
	if stderr.String() != "generic-stderr-ok\n" {
		t.Fatalf("stderr = %q", stderr.String())
	}
	assertMarkerExists(t, filepath.Join(workspace, "generic-workspace-write"))
	assertNoSessions(t, home)

	readOnlyWorkspace := realTemporaryDirectory(t)
	readOnly := exec.Command(binary, "run", "--profile", "generic-readonly", "--", helper,
		"--acs-generic-command-helper", externalSecret, externalWrite)
	readOnly.Dir, readOnly.Env = readOnlyWorkspace, nativeCandidateEnvironment(home, path, nil)
	readOnlyOutput, err := readOnly.Output()
	if err != nil {
		t.Fatalf("read-only generic run: %v", err)
	}
	if err := json.Unmarshal(bytes.TrimSpace(readOnlyOutput), &observation); err != nil {
		t.Fatal(err)
	}
	if observation.WorkspaceWrite {
		t.Fatal("read-only generic command wrote to workspace")
	}
	assertNoSessions(t, home)

	nonzero := exec.Command(binary, "run", "--profile", "generic-readwrite", "--", helper, "--acs-generic-command-helper", "--exit-23")
	nonzero.Dir, nonzero.Env = workspace, nativeCandidateEnvironment(home, path, nil)
	if err := nonzero.Run(); !exitStatusIs(err, 23) {
		t.Fatalf("generic nonzero exit = %v, want 23", err)
	}

	signalCommand := exec.Command(binary, "run", "--profile", "generic-readwrite", "--", helper, "--acs-generic-command-helper", "--wait-signal")
	signalCommand.Dir, signalCommand.Env = workspace, nativeCandidateEnvironment(home, path, nil)
	if err := signalCommand.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitForFakeDevinMarker(filepath.Join(workspace, "generic-signal-ready"), 2*time.Second) {
		t.Fatal("generic signal helper did not become ready")
	}
	if err := signalCommand.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	if err := waitForGenericCommand(signalCommand, 5*time.Second); !exitStatusIs(err, 42) {
		t.Fatalf("generic forwarded signal exit = %v, want 42", err)
	}

	descendantPID := filepath.Join(workspace, "generic-descendant.pid")
	descendantContext, cancelDescendant := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelDescendant()
	descendant := exec.CommandContext(descendantContext, binary, "run", "--profile", "generic-readwrite", "--", helper,
		"--acs-generic-command-helper", "--descendant-parent", descendantPID)
	descendant.Dir, descendant.Env = workspace, nativeCandidateEnvironment(home, path, nil)
	if output, err := descendant.CombinedOutput(); err != nil {
		t.Fatalf("generic descendant run: %v; output=%s", err, output)
	}
	pIDBytes, err := os.ReadFile(descendantPID)
	if err != nil {
		t.Fatal(err)
	}
	pID, err := strconv.Atoi(string(pIDBytes))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !errors.Is(syscall.Kill(pID, 0), syscall.ESRCH) {
		time.Sleep(10 * time.Millisecond)
	}
	if err := syscall.Kill(pID, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("generic descendant %d survived settlement: %v", pID, err)
	}

	ptyCommand := exec.Command(binary, "run", "--profile", "generic-readwrite", "--", helper, "--acs-generic-command-helper", "--pty-resize")
	ptyCommand.Dir, ptyCommand.Env = workspace, nativeCandidateEnvironment(home, path, nil)
	terminal, err := pty.Start(ptyCommand)
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	capture := &safeCapture{}
	copyDone := make(chan struct{})
	go func() {
		defer close(copyDone)
		buffer := make([]byte, 4096)
		for {
			count, readErr := terminal.Read(buffer)
			if count > 0 {
				capture.Write(buffer[:count])
			}
			if readErr != nil {
				return
			}
		}
	}()
	waitForOutput(t, capture, "generic-pty-ready")
	if err := pty.Setsize(terminal, &pty.Winsize{Rows: 31, Cols: 97}); err != nil {
		t.Fatal(err)
	}
	if err := ptyCommand.Process.Signal(syscall.SIGWINCH); err != nil {
		t.Fatal(err)
	}
	if err := waitForGenericCommand(ptyCommand, 5*time.Second); err != nil {
		t.Fatalf("generic PTY run: %v; output=%s", err, capture.String())
	}
	_ = terminal.Close()
	select {
	case <-copyDone:
	case <-time.After(time.Second):
		t.Fatal("generic PTY output did not settle")
	}
	if !strings.Contains(capture.String(), "generic-pty-size:97:31") {
		t.Fatalf("generic resize was not forwarded: %s", capture.String())
	}
	assertNoSessions(t, home)
}

func exitStatusIs(err error, status int) bool {
	exitError, ok := err.(*exec.ExitError)
	return ok && exitError.ExitCode() == status
}

func waitForGenericCommand(command *exec.Cmd, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = command.Process.Kill()
		<-done
		return errors.New("generic command did not exit before the acceptance timeout")
	}
}

// TestPromotedArtifactSharedTargetConformance exercises the common Profile
// contract through the exact installed ACS candidate. Target execution and
// credential-bearing Codex observations remain in their dedicated gates.
func TestPromotedArtifactSharedTargetConformance(t *testing.T) {
	binary := promotedBinary(t)
	home, path := prepareRuntimeHome(t)
	writeSkillBundle(t, home, "unselected")
	for name, contents := range map[string]string{"delivery": "# delivery\n", "unselected": "# unselected\n"} {
		sharedRoot := filepath.Join(home, ".agents", "skills", name)
		if err := os.MkdirAll(sharedRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(sharedRoot, "SKILL.md"), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	workspace := realTemporaryDirectory(t)
	for _, relative := range []string{".agents/skills/project-agent", ".devin/skills/project-devin"} {
		root := filepath.Join(workspace, filepath.FromSlash(relative))
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "SKILL.md"), []byte("# project local\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	globalAuth := filepath.Join(home, ".codex", "auth.json")
	if err := os.MkdirAll(filepath.Dir(globalAuth), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(globalAuth, []byte("global-auth-sentinel\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tools := realTemporaryDirectory(t)
	installPromotedArtifactFakeDevin(t, tools)
	unrelated := realTemporaryDirectory(t)
	unrelatedSecret := filepath.Join(unrelated, "unrelated-secret")
	unrelatedWrite := filepath.Join(unrelated, "unrelated-write")
	if err := os.WriteFile(unrelatedSecret, []byte("must remain unavailable\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertExternalWriteFixtureIsUnrelated(t, unrelatedWrite, workspace, home)

	for _, access := range []string{"read-only", "read-write"} {
		name := "shared-" + strings.ReplaceAll(access, "-", "")
		writeSharedTargetProfile(t, home, name, access)
		outputs := map[string]string{}
		for _, target := range []string{"devin", "codex"} {
			arguments := []string{target, "--profile", name, "--dry-run"}
			if target == "codex" && access == "read-write" {
				arguments = append(arguments, "--auth", "override")
			}
			command := exec.Command(binary, arguments...)
			command.Env = nativeCandidateEnvironment(home, path, nil)
			command.Dir = workspace
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("installed candidate %s shared contract: %v; output=%s", target, err, output)
			}
			outputs[target] = string(output)
			for _, marker := range []string{
				"identity: devin-config:review",
				"identity: shared-agents:delivery",
				"access: " + access,
				filepath.Join("<session>", "home", ".acs", "common", "v1", "skills", "devin-config", "review"),
				filepath.Join("<session>", "home", ".acs", "common", "v1", "skills", "shared-agents", "delivery"),
			} {
				if !strings.Contains(outputs[target], marker) {
					t.Fatalf("%s shared dry-run omitted %q: %s", target, marker, output)
				}
			}
			if strings.Contains(outputs[target], "unselected") {
				t.Fatalf("%s shared dry-run included an unselected global Skill: %s", target, output)
			}
			passiveBoundary := "No Session was created"
			if target == "codex" {
				passiveBoundary = "No identity lock, executable probe, Session, or process was created."
			}
			if !strings.Contains(outputs[target], passiveBoundary) {
				t.Fatalf("%s dry-run omitted passive boundary %q: %s", target, passiveBoundary, output)
			}
			explainArguments := []string{"explain", target, "--profile", name, "--json"}
			if target == "codex" && access == "read-write" {
				explainArguments = append(explainArguments, "--auth", "override")
			}
			explain := exec.Command(binary, explainArguments...)
			explain.Env, explain.Dir = nativeCandidateEnvironment(home, path, nil), workspace
			explanationOutput, err := explain.CombinedOutput()
			if err != nil {
				t.Fatalf("installed candidate %s explanation: %v; output=%s", target, err, explanationOutput)
			}
			privateReferenceLeaked := target == "codex" && (bytes.Contains(explanationOutput, []byte(`"work"`)) || bytes.Contains(explanationOutput, []byte("override")))
			if bytes.Contains(explanationOutput, []byte("unselected")) || bytes.Contains(explanationOutput, []byte(workspace)) || privateReferenceLeaked {
				t.Fatalf("%s explanation exposed unselected/private binding: %s", target, explanationOutput)
			}
			var explanation struct {
				Plan struct {
					Requested   []nativeExplanationFact `json:"requested"`
					TargetAdded []nativeExplanationFact `json:"targetAdded"`
				} `json:"plan"`
			}
			if err := json.Unmarshal(explanationOutput, &explanation); err != nil {
				t.Fatalf("decode %s explanation: %v; output=%s", target, err, explanationOutput)
			}
			workspaceFact, found := nativeExplanationFactByID(explanation.Plan.Requested, "common.workspace")
			if !found || workspaceFact.Value.Access != access {
				t.Fatalf("%s explanation workspace = %#v, want %s", target, workspaceFact, access)
			}
			for _, id := range []string{"skills.selected.devin-config:review", "skills.selected.shared-agents:delivery"} {
				if !nativeExplanationHasFact(explanation.Plan.Requested, id) {
					t.Fatalf("%s explanation omitted exact selected identity %s", target, id)
				}
			}
			if target == "devin" && !nativeExplanationHasFact(explanation.Plan.TargetAdded, "devin.project-skills") {
				t.Fatalf("Devin explanation omitted project inheritance: %s", explanationOutput)
			}
			assertNoSessions(t, home)
		}
		for _, marker := range []string{
			filepath.Join("<session>", "home", ".config", "devin", "skills", "review"),
			filepath.Join("<session>", "home", ".agents", "skills", "delivery"),
			filepath.Join(workspace, ".agents", "skills", "project-agent"),
			filepath.Join(workspace, ".devin", "skills", "project-devin"),
		} {
			if !strings.Contains(outputs["devin"], marker) {
				t.Fatalf("Devin shared dry-run omitted projection or project-local boundary %q", marker)
			}
		}
		codexReference := "work"
		if access == "read-write" {
			codexReference = "override"
		}
		for _, marker := range []string{
			filepath.Join("<session>", "home", ".codex", "skills", "devin-config", "review"),
			filepath.Join("<session>", "home", ".codex", "skills", "shared-agents", "delivery"),
			"reference: " + codexReference,
		} {
			if !strings.Contains(outputs["codex"], marker) {
				t.Fatalf("Codex shared dry-run omitted projection or opaque identity %q", marker)
			}
		}
		for _, project := range []string{"project-agent", "project-devin"} {
			if strings.Contains(outputs["codex"], project) {
				t.Fatalf("Codex represented project-local Skill %q as ACS-managed material", project)
			}
		}
		profileBytes, err := os.ReadFile(filepath.Join(home, ".acs", "profiles", name+".json"))
		if err != nil || !bytes.Contains(profileBytes, []byte(`"authRef":"work"`)) || bytes.Contains(profileBytes, []byte("override")) {
			t.Fatalf("Codex dry-run override changed the stored opaque reference: %q, %v", profileBytes, err)
		}

		writeFakeDevinConfiguration(t, workspace, fakeDevinConfiguration{
			Mode: "shared-target-conformance", HostSecret: unrelatedSecret,
			ExternalWritePath: unrelatedWrite,
			ProjectAgentPath:  filepath.Join(workspace, ".agents", "skills", "project-agent", "SKILL.md"),
			ProjectDevinPath:  filepath.Join(workspace, ".devin", "skills", "project-devin", "SKILL.md"),
		})
		command := exec.Command(binary, "devin", "--profile", name)
		command.Env = nativeCandidateEnvironment(home, tools+string(os.PathListSeparator)+path, nil)
		command.Dir = workspace
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("installed candidate Devin %s attached fixture: %v; output=%s", access, err, output)
		}
		var result fakeDevinResult
		if err := json.Unmarshal(bytes.TrimSpace(output), &result); err != nil {
			t.Fatalf("contained Devin fixture result is invalid: %v; output=%s", err, output)
		}
		for label, observed := range map[string]bool{
			"both preflights":             result.PreflightSkills && result.PreflightAuthentication,
			"selected common bytes":       result.SelectedCommonSkills,
			"selected Devin projections":  result.SelectedProjectedSkills,
			"unselected global exclusion": result.UnselectedGlobalAbsent,
			"project .agents read":        result.ProjectAgentReadable,
			"project .devin read":         result.ProjectDevinReadable,
			"private Session write":       result.SessionWritable,
		} {
			if !observed {
				t.Fatalf("Devin %s fixture did not prove %s: %#v", access, label, result)
			}
		}
		wantWorkspaceWrite := access == "read-write"
		if result.WorkspaceWritable != wantWorkspaceWrite {
			t.Fatalf("Devin %s workspace write = %v, want %v", access, result.WorkspaceWritable, wantWorkspaceWrite)
		}
		if result.HostFileReadable || result.ExternalWriteSucceeded {
			t.Fatalf("Devin %s fixture reached unrelated host state: %#v", access, result)
		}
		assertMarkerAbsent(t, unrelatedWrite, "shared Devin fixture wrote unrelated host path")
		assertNoSessions(t, home)
	}

	legacy := exec.Command(binary, "codex", "--profile", "reviews", "--auth", "work", "--dry-run")
	legacy.Env, legacy.Dir = nativeCandidateEnvironment(home, path, nil), workspace
	if output, err := legacy.CombinedOutput(); err == nil || !strings.Contains(string(output), "unsupported schema version 1") {
		t.Fatalf("installed Codex reinterpreted legacy Devin Profile: err=%v output=%s", err, output)
	}
	contents, err := os.ReadFile(globalAuth)
	if err != nil || string(contents) != "global-auth-sentinel\n" {
		t.Fatalf("dry-run accessed or changed global Codex auth: %q, %v", contents, err)
	}
	assertNoSessions(t, home)
}

func TestSharedTargetFixtureDoesNotInventPreflightEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		skills bool
		auth   bool
	}{
		{name: "neither Session marker"},
		{name: "skills only", skills: true},
		{name: "auth only", auth: true},
		{name: "both", skills: true, auth: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			workspace := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
			if test.skills {
				writeFakeDevinMarker(filepath.Join(home, fakeDevinSkillsProbeMarker))
			}
			if test.auth {
				writeFakeDevinMarker(filepath.Join(home, fakeDevinAuthProbeMarker))
			}

			result := observeFakeDevinSharedTargetConformance(fakeDevinConfiguration{}, workspace)
			if result.PreflightSkills != test.skills {
				t.Fatalf("skills preflight observation = %v, want %v", result.PreflightSkills, test.skills)
			}
			if result.PreflightAuthentication != test.auth {
				t.Fatalf("authentication preflight observation = %v, want %v", result.PreflightAuthentication, test.auth)
			}
		})
	}
}

func assertPromotedArtifactV3WorkspaceModes(t *testing.T) {
	binary := promotedBinary(t)
	home, path := prepareRuntimeHome(t)
	writeVersionThreeProfile(t, home, "readonly", "read-only")
	writeVersionThreeProfile(t, home, "coding", "read-write")
	outsideDirectory := realTemporaryDirectory(t)
	outside := filepath.Join(outsideDirectory, "unrelated-write")
	outsideSecret := filepath.Join(outsideDirectory, "unrelated-secret")
	if err := os.WriteFile(outsideSecret, []byte("must remain outside grants\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		profile  string
		writable bool
	}{{"readonly", false}, {"coding", true}} {
		workspace := realTemporaryDirectory(t)
		commands := "set -u\n" +
			"test \"$(cat \"$HOME/.acs/common/v1/skills/devin-config/review/SKILL.md\")\" != \"\" || exit 61\n" +
			"test ! -e \"$HOME/.config/devin/skills/review/SKILL.md\" || exit 62\n" +
			"printf session > \"$HOME/session-write\" || exit 63\n" +
			"if printf workspace > ./workspace-write 2>/dev/null; then print -r -- workspace-written; else print -r -- workspace-denied; fi\n" +
			"if printf outside > " + strconv.Quote(outside) + " 2>/dev/null; then exit 64; fi\n" +
			"if cat " + strconv.Quote(outsideSecret) + " >/dev/null 2>&1; then exit 65; fi\n" +
			"print -r -- v3-common-ok\nexit 0\n"
		command := exec.Command(binary, "sandbox", "--profile", test.profile)
		command.Env, command.Dir, command.Stdin = nativeCandidateEnvironment(home, path, nil), workspace, strings.NewReader(commands)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("installed v3 %s shell: %v; output=%s", test.profile, err, output)
		}
		if !strings.Contains(string(output), "v3-common-ok") {
			t.Fatalf("v3 common material was not consumed: %s", output)
		}
		_, workspaceErr := os.Stat(filepath.Join(workspace, "workspace-write"))
		if (workspaceErr == nil) != test.writable {
			t.Fatalf("profile %s workspace state=%v, writable=%v; output=%s", test.profile, workspaceErr, test.writable, output)
		}
		assertMarkerAbsent(t, outside, "v3 shell wrote unrelated host path")
		assertNoSessions(t, home)
	}
}

func assertPromotedArtifactSandboxShell(t *testing.T) {
	binary := promotedBinary(t)
	home, path := prepareRuntimeHome(t)
	workspace := realTemporaryDirectory(t)
	outside := realTemporaryDirectory(t)
	outFile := filepath.Join(outside, "outside-secret")
	if err := os.WriteFile(outFile, []byte("private\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dryRun := exec.Command(binary, "sandbox", "--profile", "reviews", "--dry-run")
	dryRun.Env = nativeCandidateEnvironment(home, path, nil)
	dryRun.Dir = workspace
	dryOutput, err := dryRun.CombinedOutput()
	if err != nil {
		t.Fatalf("installed candidate sandbox dry run failed: %v", err)
	}
	for _, marker := range []string{
		`Dry run for Profile "reviews"`,
		"selected native backend: Seatbelt",
		"No Session was created and no sandbox shell was started.",
	} {
		if !strings.Contains(string(dryOutput), marker) {
			t.Fatalf("sandbox dry run omitted %q: %s", marker, dryOutput)
		}
	}
	assertNoSessions(t, home)

	commands := "set -eu\n" +
		"test -f \"$HOME/.config/devin/skills/review/SKILL.md\"\n" +
		"test ! -e \"$HOME/.local/share/devin/credentials.toml\"\n" +
		"printf allowed > ./sandbox-workspace-proof\n" +
		"if cat " + strconv.Quote(outFile) + " >/dev/null 2>&1; then exit 71; fi\n" +
		"sleep 30 &\n" +
		"print -r -- $! > ./sandbox-descendant.pid\n" +
		"print -r -- sandbox-shell-ok\n" +
		"exit 0\n"
	command := exec.Command(binary, "sandbox", "--profile", "reviews")
	command.Env = nativeCandidateEnvironment(home, path, nil)
	command.Dir = workspace
	command.Stdin = strings.NewReader(commands)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("installed candidate sandbox shell failed: %v; output=%s", err, output)
	}
	if !strings.Contains(string(output), "sandbox-shell-ok") {
		t.Fatalf("sandbox shell output = %q", output)
	}
	assertMarkerExists(t, filepath.Join(workspace, "sandbox-workspace-proof"))
	pIDBytes, err := os.ReadFile(filepath.Join(workspace, "sandbox-descendant.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pID, err := strconv.Atoi(strings.TrimSpace(string(pIDBytes)))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if errors.Is(syscall.Kill(pID, 0), syscall.ESRCH) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := syscall.Kill(pID, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("sandbox shell descendant %d survived completion: %v", pID, err)
	}
	assertNoSessions(t, home)
}

func assertPromotedArtifactNativeReadiness(t *testing.T) {
	binary := promotedBinary(t)
	home, path := prepareRuntimeHome(t)
	workspace := realTemporaryDirectory(t)
	command := exec.Command(binary, "devin", "--profile", "reviews", "--dry-run")
	command.Env = nativeCandidateEnvironment(home, path, nil)
	command.Dir = workspace
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatal("installed candidate did not report native readiness")
	}
	for _, marker := range []string{
		"required sandbox mode: native",
		"supported platform: supported",
		"backend readiness: ready",
		"ACS will not start Devin without the required sandbox.",
	} {
		if !strings.Contains(string(output), marker) {
			t.Fatalf("native readiness omitted required observation %q", marker)
		}
	}
	if strings.Contains(string(output), privateEnvironmentValue) || containsControlCharacter(string(output)) {
		t.Fatal("native readiness exposed unsafe host detail")
	}
	assertNoSessions(t, home)
}

func assertPromotedArtifactNativeContainment(t *testing.T) {
	binary := promotedBinary(t)
	home, path := prepareRuntimeHome(t)
	// Exercise the installed candidate's v3 common copy followed by its real
	// Devin projection; the fake target observes the projected managed path.
	writeVersionThreeProfile(t, home, "reviews", "read-write")
	fixtureRoot := realTemporaryDirectory(t)
	workspace := filepath.Join(fixtureRoot, "workspace")
	tools := filepath.Join(fixtureRoot, "tools")
	externalRoot := realTemporaryDirectory(t)
	t.Cleanup(func() {
		if err := os.RemoveAll(externalRoot); err != nil {
			t.Error("did not remove the external write fixture")
		}
	})
	for _, directory := range []string{workspace, tools} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = releaseFakeDevinDescendant(workspace) })
	installPromotedArtifactFakeDevin(t, tools)

	hostSecret := filepath.Join(fixtureRoot, "host-secret")
	if err := os.WriteFile(hostSecret, []byte("native-host-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hostSecret, filepath.Join(workspace, "host-secret-link")); err != nil {
		t.Fatal(err)
	}
	socketDirectory, err := os.MkdirTemp("/tmp", "acs-native-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDirectory) })
	hostSocket := filepath.Join(socketDirectory, "host.sock")
	unixListener, err := net.Listen("unix", hostSocket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unixListener.Close() })
	ipListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ipListener.Close() })
	ipAccepted := make(chan struct{}, 1)
	go func() {
		connection, acceptErr := ipListener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
			ipAccepted <- struct{}{}
		}
	}()

	config := fakeDevinConfiguration{
		Mode:                "containment",
		HostSecret:          hostSecret,
		HostSocket:          hostSocket,
		OutboundAddress:     ipListener.Addr().String(),
		EnvironmentSentinel: privateEnvironmentValue,
		DescriptorSentinel:  privateDescriptorValue,
		ExternalWritePath:   filepath.Join(externalRoot, "unrelated-write"),
	}
	assertExternalWriteFixtureIsUnrelated(t, config.ExternalWritePath, workspace, home)
	writeFakeDevinConfiguration(t, workspace, config)

	descriptor, err := os.Open(hostSecret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = descriptor.Close() })
	command := exec.Command(binary, "devin", "--profile", "reviews")
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, tools+string(os.PathListSeparator)+path, map[string]string{
		"ACS_NATIVE_CANDIDATE_SECRET": privateEnvironmentValue,
	})
	command.ExtraFiles = []*os.File{descriptor}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		t.Fatal("installed candidate failed the native containment fixture")
	}
	if output.Len() != 0 {
		t.Fatal("native containment fixture produced target output")
	}

	result := readFakeDevinResult(t, workspace)
	if !result.PreflightSkills || !result.PreflightAuthentication {
		t.Fatal("candidate did not run both preflight probes in the contained Session")
	}
	for name, actual := range map[string]bool{
		"workspace write":     result.WorkspaceWritable,
		"Session write":       result.SessionWritable,
		"Session temporary":   result.TemporaryWritable,
		"allowed environment": result.AllowedEnvironment,
		"outbound IP":         result.OutboundIP,
		"local IP bind":       result.LocalIPBind,
		"descendant start":    result.DescendantStarted,
	} {
		if !actual {
			t.Fatalf("native containment did not preserve %s", name)
		}
	}
	for name, actual := range map[string]bool{
		"host file":            result.HostFileReadable,
		"symlink escape":       result.SymlinkEscapeReadable,
		"secret environment":   result.BlockedEnvironmentVisible,
		"inherited descriptor": result.DescriptorLeaked,
		"host Unix socket":     result.HostSocketReachable,
		"local Unix bind":      result.LocalUnixBind,
		"unrelated host write": result.ExternalWriteSucceeded,
	} {
		if actual {
			t.Fatalf("native containment exposed %s", name)
		}
	}
	select {
	case <-ipAccepted:
	case <-time.After(5 * time.Second):
		t.Fatal("native containment did not permit outbound IP")
	}
	assertMarkerExists(t, filepath.Join(workspace, "workspace-write"))
	assertMarkerAbsent(t, config.ExternalWritePath, "native containment wrote outside its allowed roots")
	assertDescendantStopsAfterCandidateReturn(t, workspace)
	assertNoSessions(t, home)
}

func assertPromotedArtifactNativePreflightFailureIsSafe(t *testing.T) {
	binary := promotedBinary(t)
	home, path := prepareRuntimeHome(t)
	fixtureRoot := realTemporaryDirectory(t)
	workspace := filepath.Join(fixtureRoot, "workspace")
	tools := filepath.Join(fixtureRoot, "tools")
	for _, directory := range []string{workspace, tools} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	installPromotedArtifactFakeDevin(t, tools)
	privatePath := filepath.Join(fixtureRoot, "private-account")
	writeFakeDevinConfiguration(t, workspace, fakeDevinConfiguration{
		Mode:          "authentication-failure",
		PrivatePath:   privatePath,
		PrivateOutput: "credential=never-log\x1b[31m",
	})

	command := exec.Command(binary, "devin", "--profile", "reviews")
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, tools+string(os.PathListSeparator)+path, nil)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("candidate accepted a failed authentication preflight")
	}
	assertSafeCandidateFailure(t, output, "authentication_preflight_failed", privatePath, "credential=never-log")
	if _, err := os.Stat(filepath.Join(workspace, "interactive-started")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("authentication failure started the interactive target")
	}
	assertNoSessions(t, home)
}

func assertPromotedArtifactMissingBackendFailsClosed(t *testing.T) {
	binary := promotedBinary(t)
	home, path := prepareRuntimeHome(t)
	fixtureRoot := realTemporaryDirectory(t)
	workspace := filepath.Join(fixtureRoot, "workspace")
	tools := filepath.Join(fixtureRoot, "tools")
	for _, directory := range []string{workspace, tools} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFakeDevin(t, filepath.Join(tools, "devin"), "#!/bin/sh\ntouch ./interactive-started\n")

	command := promotedArtifactMissingBackendCommand(t, binary, home, tools+string(os.PathListSeparator)+path, workspace)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("candidate accepted a missing required backend")
	}
	assertSafeCandidateFailure(t, output, "backend_unavailable", fixtureRoot)
	for _, marker := range []string{
		"preflight-skills",
		"preflight-authentication",
		"interactive-started",
		"descendant-ready",
		"descendant-acknowledged",
		"descendant-survived",
		fakeDevinResultName,
	} {
		if _, err := os.Stat(filepath.Join(workspace, marker)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("missing required backend started a target marker")
		}
	}
	assertNoSessions(t, home)
}

type fakeDevinConfiguration struct {
	Mode                string `json:"mode"`
	HostSecret          string `json:"hostSecret,omitempty"`
	HostSocket          string `json:"hostSocket,omitempty"`
	OutboundAddress     string `json:"outboundAddress,omitempty"`
	EnvironmentSentinel string `json:"environmentSentinel,omitempty"`
	DescriptorSentinel  string `json:"descriptorSentinel,omitempty"`
	ExternalWritePath   string `json:"externalWritePath,omitempty"`
	PrivatePath         string `json:"privatePath,omitempty"`
	PrivateOutput       string `json:"privateOutput,omitempty"`
	ProjectAgentPath    string `json:"projectAgentPath,omitempty"`
	ProjectDevinPath    string `json:"projectDevinPath,omitempty"`
}

type fakeDevinResult struct {
	PreflightSkills           bool `json:"preflightSkills"`
	PreflightAuthentication   bool `json:"preflightAuthentication"`
	WorkspaceWritable         bool `json:"workspaceWritable"`
	SessionWritable           bool `json:"sessionWritable"`
	TemporaryWritable         bool `json:"temporaryWritable"`
	HostFileReadable          bool `json:"hostFileReadable"`
	SymlinkEscapeReadable     bool `json:"symlinkEscapeReadable"`
	AllowedEnvironment        bool `json:"allowedEnvironment"`
	BlockedEnvironmentVisible bool `json:"blockedEnvironmentVisible"`
	DescriptorLeaked          bool `json:"descriptorLeaked"`
	HostSocketReachable       bool `json:"hostSocketReachable"`
	OutboundIP                bool `json:"outboundIP"`
	LocalIPBind               bool `json:"localIPBind"`
	LocalUnixBind             bool `json:"localUnixBind"`
	ExternalWriteSucceeded    bool `json:"externalWriteSucceeded"`
	DescendantStarted         bool `json:"descendantStarted"`
	SelectedCommonSkills      bool `json:"selectedCommonSkills"`
	SelectedProjectedSkills   bool `json:"selectedProjectedSkills"`
	UnselectedGlobalAbsent    bool `json:"unselectedGlobalAbsent"`
	ProjectAgentReadable      bool `json:"projectAgentReadable"`
	ProjectDevinReadable      bool `json:"projectDevinReadable"`
}

func installPromotedArtifactFakeDevin(t *testing.T, tools string) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(binary, filepath.Join(tools, "devin")); err != nil {
		t.Fatal(err)
	}
}

func writeFakeDevinConfiguration(t *testing.T, workspace string, configuration fakeDevinConfiguration) {
	t.Helper()
	contents, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, fakeDevinConfigurationName), contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFakeDevinConfiguration() (fakeDevinConfiguration, error) {
	contents, err := os.ReadFile(filepath.Join(mustGetwd(), fakeDevinConfigurationName))
	if err != nil {
		return fakeDevinConfiguration{}, err
	}
	var configuration fakeDevinConfiguration
	if err := json.Unmarshal(contents, &configuration); err != nil {
		return fakeDevinConfiguration{}, err
	}
	return configuration, nil
}

func readFakeDevinResult(t *testing.T, workspace string) fakeDevinResult {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(workspace, fakeDevinResultName))
	if err != nil {
		t.Fatal("contained fake Devin did not record its result")
	}
	var result fakeDevinResult
	if err := json.Unmarshal(contents, &result); err != nil {
		t.Fatal("contained fake Devin wrote an invalid result")
	}
	return result
}

func runPromotedArtifactFakeDevin(arguments []string) bool {
	if len(arguments) == 1 && arguments[0] == "--acs-native-candidate-descendant" {
		runFakeDevinDescendant()
		return true
	}
	if len(arguments) == 3 && arguments[0] == "skills" && arguments[1] == "list" && arguments[2] == "--json" {
		runFakeDevinSkills()
		return true
	}
	if len(arguments) == 2 && arguments[0] == "auth" && arguments[1] == "status" {
		runFakeDevinAuthentication()
		return true
	}
	if len(arguments) == 2 && arguments[0] == "--respect-workspace-trust" && arguments[1] == "false" {
		runFakeDevinInteractive()
		return true
	}
	return false
}

func runFakeDevinSkills() {
	workspace := mustGetwd()
	configuration, _ := readFakeDevinConfiguration()
	if configuration.Mode == "shared-target-conformance" {
		writeFakeDevinMarker(filepath.Join(os.Getenv("HOME"), fakeDevinSkillsProbeMarker))
	} else {
		writeFakeDevinMarker(filepath.Join(workspace, "preflight-skills"))
	}
	base := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "devin", "skills", "review")
	catalog := []map[string]string{{"name": "review", "provider": "Devin", "base_dir": base}}
	if configuration.Mode == "shared-target-conformance" {
		catalog = append(catalog, map[string]string{"name": "delivery", "provider": "Agents", "base_dir": filepath.Join(os.Getenv("HOME"), ".agents", "skills", "delivery")})
	}
	_ = json.NewEncoder(os.Stdout).Encode(catalog)
	return
}

func runFakeDevinAuthentication() {
	configuration, err := readFakeDevinConfiguration()
	if err != nil {
		os.Exit(71)
	}
	if configuration.Mode == "authentication-failure" {
		_, _ = io.WriteString(os.Stderr, configuration.PrivateOutput)
		os.Exit(66)
	}
	credential := filepath.Join(os.Getenv("XDG_DATA_HOME"), "devin", "credentials.toml")
	if _, err := os.Stat(credential); err != nil {
		os.Exit(65)
	}
	if configuration.Mode == "shared-target-conformance" {
		writeFakeDevinMarker(filepath.Join(os.Getenv("HOME"), fakeDevinAuthProbeMarker))
	} else {
		writeFakeDevinMarker(filepath.Join(mustGetwd(), "preflight-authentication"))
	}
	_, _ = io.WriteString(os.Stdout, "Logged in (fixture).\n")
}

func runFakeDevinInteractive() {
	configuration, err := readFakeDevinConfiguration()
	if err != nil {
		os.Exit(71)
	}
	workspace := mustGetwd()
	if configuration.Mode == "signal" || configuration.Mode == "resize" {
		runFakeDevinTerminalFixture(configuration.Mode, workspace)
		return
	}
	if configuration.Mode == "shared-target-conformance" {
		runFakeDevinSharedTargetConformance(configuration, workspace)
		return
	}
	result := fakeDevinResult{
		PreflightSkills:           fakeDevinMarkerExists(filepath.Join(workspace, "preflight-skills")),
		PreflightAuthentication:   fakeDevinMarkerExists(filepath.Join(workspace, "preflight-authentication")),
		WorkspaceWritable:         writeFakeDevinMarker(filepath.Join(workspace, "workspace-write")),
		SessionWritable:           writeFakeDevinMarker(filepath.Join(os.Getenv("HOME"), "session-write")),
		TemporaryWritable:         writeFakeDevinMarker(filepath.Join(os.Getenv("TMPDIR"), "temporary-write")),
		HostFileReadable:          fakeDevinCanRead(configuration.HostSecret),
		SymlinkEscapeReadable:     fakeDevinCanRead(filepath.Join(workspace, "host-secret-link")),
		AllowedEnvironment:        fakeDevinAllowedEnvironment(),
		BlockedEnvironmentVisible: os.Getenv("ACS_NATIVE_CANDIDATE_SECRET") == configuration.EnvironmentSentinel,
		DescriptorLeaked:          fakeDevinDescriptorContains(configuration.DescriptorSentinel),
		HostSocketReachable:       fakeDevinCanDial("unix", configuration.HostSocket),
		OutboundIP:                fakeDevinCanDial("tcp", configuration.OutboundAddress),
		LocalIPBind:               fakeDevinCanBind("tcp4", "127.0.0.1:0"),
		LocalUnixBind:             fakeDevinCanBind("unix", filepath.Join(os.Getenv("HOME"), "denied-bind.sock")),
		ExternalWriteSucceeded:    writeFakeDevinMarker(configuration.ExternalWritePath),
	}
	result.DescendantStarted = startFakeDevinDescendant()
	writeFakeDevinMarker(filepath.Join(workspace, "interactive-started"))
	contents, err := json.Marshal(result)
	if err != nil {
		os.Exit(72)
	}
	if err := os.WriteFile(filepath.Join(workspace, fakeDevinResultName), contents, 0o600); err != nil {
		os.Exit(73)
	}
}

func runFakeDevinSharedTargetConformance(configuration fakeDevinConfiguration, workspace string) {
	result := observeFakeDevinSharedTargetConformance(configuration, workspace)
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(77)
	}
}

func observeFakeDevinSharedTargetConformance(configuration fakeDevinConfiguration, workspace string) fakeDevinResult {
	home := os.Getenv("HOME")
	return fakeDevinResult{
		PreflightSkills:         fakeDevinMarkerExists(filepath.Join(home, fakeDevinSkillsProbeMarker)),
		PreflightAuthentication: fakeDevinMarkerExists(filepath.Join(home, fakeDevinAuthProbeMarker)),
		SelectedCommonSkills: fakeDevinContentsEqual(filepath.Join(home, ".acs", "common", "v1", "skills", "devin-config", "review", "SKILL.md"), "# review\n") &&
			fakeDevinContentsEqual(filepath.Join(home, ".acs", "common", "v1", "skills", "shared-agents", "delivery", "SKILL.md"), "# delivery\n"),
		SelectedProjectedSkills: fakeDevinContentsEqual(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "devin", "skills", "review", "SKILL.md"), "# review\n") &&
			fakeDevinContentsEqual(filepath.Join(home, ".agents", "skills", "delivery", "SKILL.md"), "# delivery\n"),
		UnselectedGlobalAbsent: !fakeDevinPathExists(filepath.Join(home, ".acs", "common", "v1", "skills", "devin-config", "unselected")) &&
			!fakeDevinPathExists(filepath.Join(home, ".acs", "common", "v1", "skills", "shared-agents", "unselected")) &&
			!fakeDevinPathExists(filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "devin", "skills", "unselected")) &&
			!fakeDevinPathExists(filepath.Join(home, ".agents", "skills", "unselected")),
		ProjectAgentReadable:   fakeDevinCanRead(configuration.ProjectAgentPath),
		ProjectDevinReadable:   fakeDevinCanRead(configuration.ProjectDevinPath),
		WorkspaceWritable:      writeFakeDevinMarker(filepath.Join(workspace, "shared-workspace-write")),
		SessionWritable:        writeFakeDevinMarker(filepath.Join(home, "shared-session-write")),
		HostFileReadable:       fakeDevinCanRead(configuration.HostSecret),
		ExternalWriteSucceeded: writeFakeDevinMarker(configuration.ExternalWritePath),
	}
}

func fakeDevinContentsEqual(path, want string) bool {
	contents, err := os.ReadFile(path)
	return err == nil && string(contents) == want
}

func fakeDevinPathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func runFakeDevinTerminalFixture(mode, workspace string) {
	ready := filepath.Join(workspace, "terminal-ready")
	if !writeFakeDevinMarker(ready) {
		os.Exit(74)
	}
	signals := make(chan os.Signal, 1)
	if mode == "signal" {
		signal.Notify(signals, syscall.SIGTERM)
		defer signal.Stop(signals)
		<-signals
		_ = os.WriteFile(filepath.Join(workspace, "signal-record"), []byte("SIGTERM\n"), 0o600)
		os.Exit(42)
	}
	signal.Notify(signals, syscall.SIGWINCH)
	defer signal.Stop(signals)
	<-signals
	width, height, err := term.GetSize(os.Stdin.Fd())
	if err != nil {
		os.Exit(75)
	}
	_ = os.WriteFile(filepath.Join(workspace, "resize-record"), []byte(strconv.Itoa(height)+" "+strconv.Itoa(width)+"\n"), 0o600)
}

func runFakeDevinDescendant() {
	workspace := mustGetwd()
	if !writeFakeDevinMarker(filepath.Join(workspace, "descendant-ready")) {
		os.Exit(76)
	}
	for !fakeDevinMarkerExists(filepath.Join(workspace, "descendant-release")) {
		time.Sleep(10 * time.Millisecond)
	}
	if !writeFakeDevinMarker(filepath.Join(workspace, "descendant-acknowledged")) {
		return
	}
	_ = writeFakeDevinMarker(filepath.Join(workspace, "descendant-survived"))
}

func startFakeDevinDescendant() bool {
	command := exec.Command(os.Args[0], "--acs-native-candidate-descendant")
	command.Dir = mustGetwd()
	command.Env = os.Environ()
	if err := command.Start(); err != nil {
		return false
	}
	return waitForFakeDevinMarker(filepath.Join(mustGetwd(), "descendant-ready"), 2*time.Second)
}

func waitForFakeDevinMarker(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fakeDevinMarkerExists(path) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fakeDevinMarkerExists(path)
}

func fakeDevinAllowedEnvironment() bool {
	home := os.Getenv("HOME")
	return home != "" &&
		os.Getenv("XDG_CONFIG_HOME") == filepath.Join(home, ".config") &&
		os.Getenv("XDG_DATA_HOME") == filepath.Join(home, ".local", "share") &&
		os.Getenv("XDG_CACHE_HOME") == filepath.Join(home, ".cache") &&
		os.Getenv("XDG_STATE_HOME") == filepath.Join(home, ".local", "state") &&
		strings.HasPrefix(os.Getenv("TMPDIR"), filepath.Dir(home)+string(filepath.Separator)) &&
		os.Getenv("TERM") == "xterm-256color"
}

func fakeDevinCanRead(path string) bool {
	if path == "" {
		return false
	}
	contents, err := os.ReadFile(path)
	return err == nil && len(contents) > 0
}

func fakeDevinDescriptorContains(want string) bool {
	if want == "" {
		return false
	}
	file := os.NewFile(uintptr(3), "candidate-host-descriptor")
	if file == nil {
		return false
	}
	contents, err := io.ReadAll(io.LimitReader(file, 512))
	return err == nil && strings.Contains(string(contents), want)
}

func fakeDevinCanDial(network, address string) bool {
	if address == "" {
		return false
	}
	connection, err := net.DialTimeout(network, address, 2*time.Second)
	if err != nil {
		return false
	}
	return connection.Close() == nil
}

func fakeDevinCanBind(network, address string) bool {
	listener, err := net.Listen(network, address)
	if err != nil {
		return false
	}
	return listener.Close() == nil
}

func writeFakeDevinMarker(path string) bool {
	return path != "" && os.WriteFile(path, []byte("ok\n"), 0o600) == nil
}

func releaseFakeDevinDescendant(workspace string) error {
	return os.WriteFile(filepath.Join(workspace, "descendant-release"), []byte("release\n"), 0o600)
}

func fakeDevinMarkerExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func mustGetwd() string {
	directory, err := os.Getwd()
	if err != nil {
		os.Exit(70)
	}
	return directory
}

func nativeCandidateEnvironment(home, path string, overrides map[string]string) []string {
	values := map[string]string{
		"HOME":     home,
		"PATH":     path,
		"TERM":     "xterm-256color",
		"NO_COLOR": "1",
	}
	for key, value := range overrides {
		values[key] = value
	}
	environment := make([]string, 0, len(os.Environ())+len(values))
	for _, entry := range os.Environ() {
		key, _, found := strings.Cut(entry, "=")
		if found {
			if _, overridden := values[key]; overridden {
				continue
			}
		}
		environment = append(environment, entry)
	}
	for _, key := range []string{"HOME", "PATH", "TERM", "NO_COLOR", "ACS_NATIVE_CANDIDATE_SECRET", "ACS_GENERIC_HOST_SECRET"} {
		if value, ok := values[key]; ok {
			environment = append(environment, key+"="+value)
		}
	}
	return environment
}

func requireEnvironmentEntry(t *testing.T, environment []string, want string) {
	t.Helper()
	for _, entry := range environment {
		if entry == want {
			return
		}
	}
	t.Fatalf("parent environment does not contain %q", want)
}

func assertSafeCandidateFailure(t *testing.T, output []byte, category string, forbidden ...string) {
	t.Helper()
	text := string(output)
	if !strings.Contains(text, category) {
		t.Fatalf("candidate failure did not report the stable %s category", category)
	}
	if containsControlCharacter(text) {
		t.Fatal("candidate failure included terminal control characters")
	}
	for _, value := range forbidden {
		if value != "" && strings.Contains(text, value) {
			t.Fatal("candidate failure exposed private fixture detail")
		}
	}
}

func containsControlCharacter(value string) bool {
	for _, character := range value {
		if character < 0x20 && character != '\n' && character != '\r' && character != '\t' {
			return true
		}
	}
	return false
}

func assertMarkerExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatal("contained target did not create its allowed marker")
	}
}

func assertMarkerAbsent(t *testing.T, path, message string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(message)
	}
}

func assertDescendantStopsAfterCandidateReturn(t *testing.T, workspace string) {
	t.Helper()
	if err := releaseFakeDevinDescendant(workspace); err != nil {
		t.Fatal("could not release descendant fixture")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if fakeDevinMarkerExists(filepath.Join(workspace, "descendant-survived")) {
			t.Fatal("native containment did not clean a descendant before Session removal")
		}
		if fakeDevinMarkerExists(filepath.Join(workspace, "descendant-acknowledged")) {
			t.Fatal("native containment left a descendant alive after candidate return")
		}
		time.Sleep(10 * time.Millisecond)
	}
	assertMarkerAbsent(t, filepath.Join(workspace, "descendant-survived"), "native containment did not clean a descendant before Session removal")
	assertMarkerAbsent(t, filepath.Join(workspace, "descendant-acknowledged"), "native containment left a descendant alive after candidate return")
}

func assertExternalWriteFixtureIsUnrelated(t *testing.T, path, workspace, home string) {
	t.Helper()
	for _, allowed := range []string{workspace, filepath.Join(home, ".acs", "sessions")} {
		relative, err := filepath.Rel(allowed, path)
		if err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			t.Fatal("external write fixture is inside an allowed sandbox root")
		}
	}
}
