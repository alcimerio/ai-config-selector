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
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/charmbracelet/x/term"
	"github.com/creack/pty"
	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
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
	t.Run("Devin preflight and target generations are fresh while retained", assertPromotedArtifactDevinGenerations)
	t.Run("preflight failure is categorized without target details", assertPromotedArtifactNativePreflightFailureIsSafe)
	t.Run("missing backend OR invalid policy cannot start a marker", assertPromotedArtifactMissingBackendFailsClosed)
}

func assertPromotedArtifactDevinGenerations(t *testing.T) {
	binary := promotedBinary(t)
	home, path := prepareRuntimeHome(t)
	root := realTemporaryDirectory(t)
	workspace, tools := filepath.Join(root, "workspace"), filepath.Join(root, "tools")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(tools, 0o700); err != nil {
		t.Fatal(err)
	}
	writeVersionThreeProfile(t, home, "generation", "read-write")
	installPromotedArtifactFakeDevin(t, tools)
	writeFakeDevinConfiguration(t, workspace, fakeDevinConfiguration{Mode: "session-generations"})
	before := promotedSessionSnapshot(t, binary, home, path)
	command := exec.Command(binary, "devin", "--profile", "generation")
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, tools+string(os.PathListSeparator)+path, nil)
	var output synchronizedNativeCapture
	command.Stdout, command.Stderr = &output, &output
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := startNativeCommand(command)
	t.Cleanup(func() {
		for _, phase := range []string{"skills", "authentication", "interactive"} {
			_ = writeFakeDevinMarker(filepath.Join(workspace, ".acs-phase-"+phase+"-release"))
		}
		settleNativeCommand(command, done)
	})
	var previous struct {
		ID, RootName, Challenge string
		Generation              uint64
	}
	for index, phase := range []string{"skills", "authentication", "interactive"} {
		ready := filepath.Join(workspace, ".acs-phase-"+phase+"-ready")
		if !waitForFakeDevinMarker(ready, 10*time.Second) {
			t.Fatalf("%s phase did not become ready", phase)
		}
		cap := readLiveGenerationCapability(t, home)
		phaseHome, err := os.ReadFile(ready)
		if err != nil || filepath.Clean(string(phaseHome)) != filepath.Join(home, ".acs", "sessions", cap.RootName, "home") {
			t.Fatalf("%s phase HOME is not bound to its private capability root", phase)
		}
		if index > 0 && (cap.ID != previous.ID || cap.RootName != previous.RootName || cap.Generation <= previous.Generation || cap.Challenge == previous.Challenge) {
			t.Fatalf("%s capability identity or generation freshness check failed", phase)
		}
		sessionRoot := filepath.Join(home, ".acs", "sessions", cap.RootName)
		if _, err := os.Lstat(filepath.Join(sessionRoot, ".acs-cleanup-proof-v1")); !os.IsNotExist(err) {
			t.Fatalf("%s live process retained cleanup proof: %v", phase, err)
		}
		recoveryContext, cancelRecovery := context.WithTimeout(context.Background(), 5*time.Second)
		recover := exec.CommandContext(recoveryContext, binary, "session", "recover", cap.ID, "--json")
		recover.Env = nativeCandidateEnvironment(home, path, nil)
		recoveryOutput, recoveryErr := recover.Output()
		cancelRecovery()
		var recovery struct {
			Outcome string `json:"outcome"`
		}
		if recoveryErr == nil || json.Unmarshal(recoveryOutput, &recovery) != nil || (recovery.Outcome != "active" && recovery.Outcome != "busy") {
			t.Fatalf("live %s recovery did not report active or busy: %v", phase, recoveryErr)
		}
		if info, err := os.Stat(sessionRoot); err != nil || !info.IsDir() {
			t.Fatalf("live %s Session was removed during recovery refusal", phase)
		}
		previous = cap
		if !writeFakeDevinMarker(filepath.Join(workspace, ".acs-phase-"+phase+"-release")) {
			t.Fatal("release phase")
		}
	}
	if err := waitNativeCommand(done, 15*time.Second); err != nil {
		t.Fatalf("generation candidate: %v output=%s", err, output.String())
	}
	assertNoSessions(t, home)
	assertNewRemovedPromotedSessions(t, binary, home, path, before, "devin")
}

func readLiveGenerationCapability(t *testing.T, home string) struct {
	ID, RootName, Challenge string
	Generation              uint64
} {
	t.Helper()
	entries, err := filepath.Glob(filepath.Join(home, ".acs", "session-operations-v1", "capabilities", "*.json"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("live capability entries=%v err=%v", entries, err)
	}
	var cap struct {
		ID, RootName, Challenge string
		Generation              uint64
	}
	contents, err := os.ReadFile(entries[0])
	if err != nil || json.Unmarshal(contents, &cap) != nil || cap.ID == "" || cap.Generation == 0 || cap.Challenge == "" {
		t.Fatalf("read live capability: %v", err)
	}
	return cap
}

func assertPromotedArtifactEffectiveExplanation(t *testing.T) {
	binary := promotedBinary(t)
	home, path := prepareRuntimeHome(t)
	sharedSkill := filepath.Join(home, ".agents", "skills", "delivery")
	if err := os.MkdirAll(sharedSkill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sharedSkill, "SKILL.md"), []byte("# delivery\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeSharedTargetProfile(t, home, "explanation", "read-write")
	workspace := realTemporaryDirectory(t)
	for _, directory := range []string{
		filepath.Join(home, ".acs", "locks", "codex-auth"),
		filepath.Join(home, ".acs", "quarantine", "codex-auth"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "state-sentinel"), []byte("unchanged\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
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
		{name: "codex", recipe: "codex", explain: []string{"explain", "codex", "--profile", "explanation", "--auth", explanationStoredAuthRef, "--json"}, execute: []string{"codex", "--profile", "explanation", "--auth", explanationStoredAuthRef, "--dry-run"}},
		{name: "run", recipe: "command", explain: []string{"explain", "run", "--profile", "explanation", "--json", "--", helper, "--acs-generic-command-helper", "--tripwire", filepath.Join(workspace, "expected-digest-run-target")}, execute: []string{"run", "--profile", "explanation", "--dry-run", "--", helper, "--acs-generic-command-helper", "--tripwire", filepath.Join(workspace, "expected-digest-run-target")}},
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
			for _, id := range []string{"runtime.devices", "runtime.environment", "runtime.environment.fixed-path", "runtime.environment.synthetic", "runtime.mach-services", "runtime.metadata", "runtime.network", "runtime.session", "runtime.sysctls"} {
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
			for _, id := range []string{"skills.selected.devin-config:review", "skills.selected.shared-agents:delivery"} {
				if !nativeExplanationHasFact(result.Plan.Requested, id) {
					t.Fatalf("requested facts omitted exact selected identity %s: %s", id, output)
				}
			}
			if bytes.Contains(output, []byte("unselected")) {
				t.Fatalf("explanation rendered an unselected bundle: %s", output)
			}
			selectedOverlay, hasSelectedOverlay := nativeExplanationFactByID(result.Plan.Requested, "target.overlay")
			switch test.name {
			case "devin", "codex":
				if !hasSelectedOverlay || selectedOverlay.Value.Mode != test.name {
					t.Fatalf("selected overlay fact for %s is incomplete: %#v", test.name, selectedOverlay)
				}
			default:
				if hasSelectedOverlay {
					t.Fatalf("common intent %s selected a target overlay: %#v", test.name, selectedOverlay)
				}
			}
			for _, inactive := range []string{"devin", "codex"} {
				factID := "overlay.inactive." + inactive
				shouldBeInactive := test.name != inactive
				if nativeExplanationHasFact(result.Plan.Unsupported, factID) != shouldBeInactive {
					t.Fatalf("inactive overlay presentation %s for %s is incorrect: %s", factID, test.name, output)
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
			if !nativeExplanationHasFact(result.Plan.TargetAdded, "runtime.session-destinations") {
				t.Fatalf("target-added facts omitted runtime.session-destinations: %s", output)
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
			if got := facts["runtime.network"].Mode; got != "local-ip-socket-bind-no-listen-coarse-outbound-ip-macos-dns" {
				t.Fatalf("network declaration = %q", got)
			}
			if got := facts["runtime.sysctls"].Names; !reflect.DeepEqual(got, []string{"hw.ncpu", "hw.pagesize", "hw.pagesize_compat"}) {
				t.Fatalf("sysctl declaration = %q", got)
			}
			if got := facts["runtime.mach-services"].Names; !reflect.DeepEqual(got, []string{"com.apple.SecurityServer", "com.apple.trustd.agent"}) {
				t.Fatalf("Mach-service declaration = %q", got)
			}
			linked := append(append([]string(nil), test.execute...), "--expect-authority-digest", result.Plan.Digest)
			// The run grammar requires the expectation before the literal boundary.
			if test.name == "run" {
				linked = []string{"run", "--profile", "explanation", "--dry-run", "--expect-authority-digest", result.Plan.Digest, "--", helper, "--acs-generic-command-helper", "--tripwire", filepath.Join(workspace, "expected-digest-run-target")}
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
				mismatchArguments = append(mismatchArguments, "--auth", explanationStoredAuthRef)
			case "run":
				mismatchArguments = append(mismatchArguments, "--", helper, "--acs-generic-command-helper", "--tripwire", filepath.Join(workspace, "expected-digest-run-target"))
			}
			beforeHome, beforeWorkspace := snapshotInspectionHome(t, home), snapshotInspectionHome(t, workspace)
			mismatchCommand := exec.Command(binary, mismatchArguments...)
			mismatchCommand.Dir, mismatchCommand.Env = workspace, nativeCandidateEnvironment(home, path, nil)
			mismatchOutput, mismatchErr := mismatchCommand.CombinedOutput()
			if mismatchErr == nil || !bytes.Contains(mismatchOutput, []byte("authority_plan_changed")) {
				t.Fatalf("mismatch did not fail at semantic guard: err=%v output=%s", mismatchErr, mismatchOutput)
			}
			if after := snapshotInspectionHome(t, home); !reflect.DeepEqual(after, beforeHome) {
				t.Fatalf("%s digest mismatch changed durable Profile/auth/lock/quarantine/home state: before=%#v after=%#v", test.name, beforeHome, after)
			}
			if after := snapshotInspectionHome(t, workspace); !reflect.DeepEqual(after, beforeWorkspace) {
				t.Fatalf("%s digest mismatch invoked a workspace-visible target/preflight or changed workspace state: before=%#v after=%#v", test.name, beforeWorkspace, after)
			}
			for _, marker := range []string{"preflight-skills", "preflight-authentication", "interactive-started", "expected-digest-run-target"} {
				if _, err := os.Stat(filepath.Join(workspace, marker)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("%s digest mismatch reached target/provider tripwire %q: %v", test.name, marker, err)
				}
			}
			assertNoSessions(t, home)
		})
	}
	for _, test := range tests {
		arguments := append([]string(nil), test.explain...)
		insertAt := len(arguments)
		for index, argument := range arguments {
			if argument == "--" {
				insertAt = index
				break
			}
		}
		arguments = append(arguments, "")
		copy(arguments[insertAt+1:], arguments[insertAt:])
		arguments[insertAt] = "--check-native-readiness"
		beforeHome, beforeWorkspace := snapshotInspectionHome(t, home), snapshotInspectionHome(t, workspace)
		readiness := exec.Command(binary, arguments...)
		readiness.Dir, readiness.Env = workspace, nativeCandidateEnvironment(home, path, nil)
		output, err := readiness.CombinedOutput()
		if err != nil || !bytes.Contains(output, []byte(`"id":"native.backend","status":"pass","code":"backend_ready"`)) || !bytes.Contains(output, []byte(`"id":"native.platform","status":"pass","code":"supported_platform"`)) || !bytes.Contains(output, []byte(`"id":"runtime.enforcement","status":"unchecked"`)) {
			t.Fatalf("bounded native readiness for %s: %v; output=%s", test.name, err, output)
		}
		if after := snapshotInspectionHome(t, home); !reflect.DeepEqual(after, beforeHome) {
			t.Fatalf("bounded native readiness for %s changed durable home state: before=%#v after=%#v", test.name, beforeHome, after)
		}
		if after := snapshotInspectionHome(t, workspace); !reflect.DeepEqual(after, beforeWorkspace) {
			t.Fatalf("bounded native readiness for %s changed workspace state: before=%#v after=%#v", test.name, beforeWorkspace, after)
		}
		assertNoSessions(t, home)
	}
	writeVersionTwoProfile(t, home, "reviews-v2")
	assertPromotedArtifactLegacyExplanations(t, binary, home, path, workspace, helper)
	assertPromotedArtifactInactiveOverlayExplanations(t, binary, home, path, workspace)
	assertPromotedArtifactExplanationFailuresArePlanless(t, binary, home, path, workspace)
	assertPromotedArtifactRunDigestMeaning(t, binary, home, path, workspace, helper)
	assertPromotedArtifactCodexAuthDigestMeaning(t, binary, home, path, workspace)
	assertPromotedArtifactV3ExplanationWorkspaceModes(t, binary, home, path, workspace, helper)
}

func assertPromotedArtifactV3ExplanationWorkspaceModes(t *testing.T, binary, home, path, workspace, helper string) {
	t.Helper()
	writeSharedTargetProfile(t, home, "explanation-readonly", "read-only")
	type modeResult struct {
		access, digest string
	}
	byIntent := map[string][]modeResult{}
	for _, profileName := range []string{"explanation-readonly", "explanation"} {
		for _, test := range []struct {
			name      string
			arguments []string
		}{
			{name: "sandbox", arguments: []string{"explain", "sandbox", "--profile", profileName, "--json"}},
			{name: "devin", arguments: []string{"explain", "devin", "--profile", profileName, "--json"}},
			{name: "codex", arguments: []string{"explain", "codex", "--profile", profileName, "--json"}},
			{name: "run", arguments: []string{"explain", "run", "--profile", profileName, "--json", "--", helper}},
		} {
			command := exec.Command(binary, test.arguments...)
			command.Dir, command.Env = workspace, nativeCandidateEnvironment(home, path, nil)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("v3 %s %s explanation: %v; output=%s", profileName, test.name, err, output)
			}
			var result struct {
				Plan struct {
					Digest    string                  `json:"authorityDigest"`
					Requested []nativeExplanationFact `json:"requested"`
				} `json:"plan"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("decode v3 mode explanation: %v; output=%s", err, output)
			}
			workspaceFact, found := nativeExplanationFactByID(result.Plan.Requested, "common.workspace")
			if !found || workspaceFact.Value.Access == "" || workspaceFact.Reason != "stored_v3_intent" {
				t.Fatalf("v3 workspace authority is incomplete: %#v output=%s", workspaceFact, output)
			}
			byIntent[test.name] = append(byIntent[test.name], modeResult{access: workspaceFact.Value.Access, digest: result.Plan.Digest})
		}
	}
	for intent, results := range byIntent {
		if len(results) != 2 || results[0].access != "read-only" || results[1].access != "read-write" || results[0].digest == results[1].digest {
			t.Fatalf("v3 %s workspace declaration/digest matrix = %#v", intent, results)
		}
	}
}

func assertPromotedArtifactRunDigestMeaning(t *testing.T, binary, home, path, workspace, helper string) {
	t.Helper()
	workspaceHelper := filepath.Join(workspace, "candidate-helper")
	contents, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workspaceHelper, contents, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := func(arguments ...string) string {
		invocation := []string{"explain", "run", "--profile", "explanation", "--json", "--"}
		invocation = append(invocation, arguments...)
		command := exec.Command(binary, invocation...)
		command.Dir, command.Env = workspace, nativeCandidateEnvironment(home, path, nil)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("run digest explanation: %v; output=%s", err, output)
		}
		for _, private := range arguments[1:] {
			if private != "" && bytes.Contains(output, []byte(private)) {
				t.Fatalf("run explanation exposed literal argument value %q: %s", private, output)
			}
		}
		var result struct {
			Plan struct {
				Digest string `json:"authorityDigest"`
			} `json:"plan"`
		}
		if err := json.Unmarshal(output, &result); err != nil || result.Plan.Digest == "" {
			t.Fatalf("decode run digest: %v; output=%s", err, output)
		}
		return result.Plan.Digest
	}
	first := digest(helper, "PRIVATE-ARGV-ONE")
	second := digest(helper, "PRIVATE-ARGV-TWO")
	changedCount := digest(helper, "PRIVATE-ARGV-ONE", "PRIVATE-ARGV-TWO")
	changedForm := digest("./candidate-helper", "PRIVATE-ARGV-ONE")
	if first != second {
		t.Fatal("literal argv values changed semantic authority digest")
	}
	if first == changedCount || first == changedForm {
		t.Fatal("literal argument count or validated executable form was absent from semantic authority digest")
	}
}

func assertPromotedArtifactCodexAuthDigestMeaning(t *testing.T, binary, home, path, workspace string) {
	t.Helper()
	writeNativeExplanationProfile(t, home, "auth-first", `"codex":{"version":1,"authRef":"`+explanationFirstAuthRef+`"}`)
	writeNativeExplanationProfile(t, home, "auth-second", `"codex":{"version":1,"authRef":"`+explanationSecondAuthRef+`"}`)
	explain := func(profileName string, override ...string) (string, []nativeExplanationFact) {
		arguments := []string{"explain", "codex", "--profile", profileName, "--json"}
		if len(override) != 0 {
			arguments = append(arguments, "--auth", override[0])
		}
		command := exec.Command(binary, arguments...)
		command.Dir, command.Env = workspace, nativeCandidateEnvironment(home, path, nil)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("Codex auth explanation: %v; output=%s", err, output)
		}
		for _, private := range []string{explanationFirstAuthRef, explanationSecondAuthRef, explanationRunAuthRef} {
			if bytes.Contains(output, []byte(private)) {
				t.Fatalf("Codex explanation exposed auth reference %q: %s", private, output)
			}
		}
		var result struct {
			Plan struct {
				Digest    string                  `json:"authorityDigest"`
				Requested []nativeExplanationFact `json:"requested"`
			} `json:"plan"`
		}
		if err := json.Unmarshal(output, &result); err != nil {
			t.Fatalf("decode Codex auth explanation: %v; output=%s", err, output)
		}
		return result.Plan.Digest, result.Plan.Requested
	}
	first, firstFacts := explain("auth-first")
	second, _ := explain("auth-second")
	override, overrideFacts := explain("auth-first", explanationRunAuthRef)
	if first != second {
		t.Fatal("opaque Codex auth reference value changed semantic authority digest")
	}
	if first == override {
		t.Fatal("overlay versus one-run auth binding origin was absent from semantic authority digest")
	}
	if fact, found := nativeExplanationFactByID(firstFacts, "codex.authentication"); !found || fact.Reason != "overlay" {
		t.Fatalf("overlay auth binding origin missing: %#v", firstFacts)
	}
	if fact, found := nativeExplanationFactByID(overrideFacts, "codex.authentication"); !found || fact.Reason != "one_run_override" {
		t.Fatalf("one-run auth binding origin missing: %#v", overrideFacts)
	}
}

func assertPromotedArtifactLegacyExplanations(t *testing.T, binary, home, path, workspace, helper string) {
	t.Helper()
	for _, profileName := range []string{"reviews", "reviews-v2"} {
		for _, invocation := range [][]string{
			{"explain", "sandbox", "--profile", profileName, "--json"},
			{"explain", "devin", "--profile", profileName, "--json"},
			{"explain", "run", "--profile", profileName, "--json", "--", helper},
		} {
			command := exec.Command(binary, invocation...)
			command.Dir, command.Env = workspace, nativeCandidateEnvironment(home, path, nil)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("legacy %s %q: %v; output=%s", profileName, invocation, err, output)
			}
			var result struct {
				Profile struct{ Compatibility string } `json:"profile"`
				Plan    struct {
					Requested   []nativeExplanationFact `json:"requested"`
					TargetAdded []nativeExplanationFact `json:"targetAdded"`
				} `json:"plan"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("decode legacy explanation: %v; output=%s", err, output)
			}
			workspaceFact, found := nativeExplanationFactByID(result.Plan.Requested, "common.workspace")
			if result.Profile.Compatibility != "legacy" || !found || workspaceFact.Value.Access != "read-write" || workspaceFact.Reason != "legacy_compatibility_default" {
				t.Fatalf("legacy compatibility authority is incomplete: %#v output=%s", result, output)
			}
			if !nativeExplanationHasFact(result.Plan.TargetAdded, "skills.target-projection") {
				t.Fatalf("legacy target placement missing: %s", output)
			}
			assertNoSessions(t, home)
		}
		codex := exec.Command(binary, "explain", "codex", "--profile", profileName, "--auth", explanationLegacyAuthRef, "--json")
		codex.Dir, codex.Env = workspace, nativeCandidateEnvironment(home, path, nil)
		output, err := codex.CombinedOutput()
		if err == nil || !bytes.Contains(output, []byte(`"plan":null`)) || !bytes.Contains(output, []byte(`"code":"profile_load_failed"`)) || bytes.Contains(output, []byte(explanationLegacyAuthRef)) || bytes.Contains(output, []byte(home)) {
			t.Fatalf("legacy Codex failure is unsafe or reinterpreted: err=%v output=%s", err, output)
		}
		assertNoSessions(t, home)
	}
}

func assertPromotedArtifactInactiveOverlayExplanations(t *testing.T, binary, home, path, workspace string) {
	t.Helper()
	profiles := []struct {
		name, overlays string
	}{
		{name: "inactive-none", overlays: `"devin":{"version":1}`},
		{name: "inactive-known", overlays: `"devin":{"version":1},"codex":{"version":1,"authRef":"` + explanationInactiveAuthRef + `"}`},
		{name: "inactive-unknown-a", overlays: `"devin":{"version":1},"codex":{"version":1,"authRef":"` + explanationInactiveAuthRef + `"},"PRIVATE-OVERLAY-B":{"version":41,"payload":"PRIVATE-PAYLOAD-B"},"PRIVATE-OVERLAY-A":{"version":99,"payload":"PRIVATE-PAYLOAD-A"}`},
		{name: "inactive-unknown-b", overlays: `"PRIVATE-OVERLAY-A":{"version":99,"payload":"PRIVATE-PAYLOAD-A"},"PRIVATE-OVERLAY-B":{"version":41,"payload":"PRIVATE-PAYLOAD-B"},"codex":{"version":1,"authRef":"` + explanationInactiveAuthRef + `"},"devin":{"version":1}`},
	}
	type decoded struct {
		Plan struct {
			Digest      string                  `json:"authorityDigest"`
			Unsupported []nativeExplanationFact `json:"unsupported"`
		} `json:"plan"`
		Limitations []struct {
			Code, Detail string
		} `json:"limitations"`
	}
	results := make(map[string]decoded, len(profiles))
	for _, candidate := range profiles {
		writeNativeExplanationProfile(t, home, candidate.name, candidate.overlays)
		command := exec.Command(binary, "explain", "devin", "--profile", candidate.name, "--json")
		command.Dir, command.Env = workspace, nativeCandidateEnvironment(home, path, nil)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("inactive overlay explanation %s: %v; output=%s", candidate.name, err, output)
		}
		for _, private := range []string{explanationInactiveAuthRef, "PRIVATE-OVERLAY-A", "PRIVATE-OVERLAY-B", "PRIVATE-PAYLOAD-A", "PRIVATE-PAYLOAD-B"} {
			if bytes.Contains(output, []byte(private)) {
				t.Fatalf("inactive overlay explanation exposed %q: %s", private, output)
			}
		}
		var result decoded
		if err := json.Unmarshal(output, &result); err != nil {
			t.Fatalf("decode inactive overlay explanation: %v; output=%s", err, output)
		}
		results[candidate.name] = result
		assertNoSessions(t, home)
	}
	baseline := results["inactive-none"].Plan.Digest
	for name, result := range results {
		if result.Plan.Digest != baseline {
			t.Fatalf("inactive overlay %s changed semantic digest: %s != %s", name, result.Plan.Digest, baseline)
		}
	}
	if !nativeExplanationHasFact(results["inactive-known"].Plan.Unsupported, "overlay.inactive.codex") {
		t.Fatalf("known inactive overlay is not reported: %#v", results["inactive-known"].Plan.Unsupported)
	}
	first, second := results["inactive-unknown-a"].Limitations, results["inactive-unknown-b"].Limitations
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("unknown inactive overlay order changed presentation: first=%#v second=%#v", first, second)
	}
	unknownCount := 0
	for _, limitation := range first {
		if limitation.Code == "inactive_overlay_unknown" {
			unknownCount++
			if limitation.Detail == "" {
				t.Fatalf("unknown inactive overlay limitation omitted detail: %#v", limitation)
			}
		}
	}
	if unknownCount != 2 {
		t.Fatalf("unknown inactive limitations = %d, want one per overlay: %#v", unknownCount, first)
	}
	for _, fact := range results["inactive-unknown-a"].Plan.Unsupported {
		if strings.HasPrefix(fact.ID, "overlay.inactive.unknown-") {
			t.Fatalf("unknown inactive overlay fabricated a plan fact: %#v", fact)
		}
	}
}

func writeNativeExplanationProfile(t *testing.T, home, name, overlays string) {
	t.Helper()
	directory := filepath.Join(home, ".acs", "profiles")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	contents := fmt.Sprintf(`{"version":3,"name":%q,"common":{"skills":{"version":1,"selection":[{"source":"devin-config","relativePath":"review"}]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{%s}}`, name, overlays)
	if err := os.WriteFile(filepath.Join(directory, name+".json"), []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertPromotedArtifactExplanationFailuresArePlanless(t *testing.T, binary, home, path, workspace string) {
	t.Helper()
	for _, test := range []struct {
		name, selection, overlays, code string
	}{
		{name: "selected-overlay-missing", selection: `[{"source":"devin-config","relativePath":"review"}]`, overlays: `"codex":{"version":1}`, code: "profile_resolution_failed"},
		{name: "selected-overlay-unsupported", selection: `[{"source":"devin-config","relativePath":"review"}]`, overlays: `"devin":{"version":9,"PRIVATE-PAYLOAD":true}`, code: "profile_resolution_failed"},
		{name: "selected-overlay-malformed", selection: `[{"source":"devin-config","relativePath":"review"}]`, overlays: `"devin":[]`, code: "profile_load_failed"},
		{name: "selected-skill-missing", selection: `[{"source":"shared-agents","relativePath":"PRIVATE-MISSING-SKILL"}]`, overlays: `"devin":{"version":1}`, code: "profile_resolution_failed"},
	} {
		directory := filepath.Join(home, ".acs", "profiles")
		contents := fmt.Sprintf(`{"version":3,"name":%q,"common":{"skills":{"version":1,"selection":%s},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{%s}}`, test.name, test.selection, test.overlays)
		if err := os.WriteFile(filepath.Join(directory, test.name+".json"), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command(binary, "explain", "devin", "--profile", test.name, "--json")
		command.Dir, command.Env = workspace, nativeCandidateEnvironment(home, path, nil)
		beforeHome, beforeWorkspace := snapshotInspectionHome(t, home), snapshotInspectionHome(t, workspace)
		output, err := command.CombinedOutput()
		if err == nil || !bytes.Contains(output, []byte(`"plan":null`)) || !bytes.Contains(output, []byte(`"code":"`+test.code+`"`)) {
			t.Fatalf("unsafe explanation failure %s: err=%v output=%s", test.name, err, output)
		}
		for _, private := range []string{home, "PRIVATE-PAYLOAD", "PRIVATE-MISSING-SKILL"} {
			if bytes.Contains(output, []byte(private)) {
				t.Fatalf("explanation failure %s exposed %q: %s", test.name, private, output)
			}
		}
		if after := snapshotInspectionHome(t, home); !reflect.DeepEqual(after, beforeHome) {
			t.Fatalf("explanation failure %s changed durable home state: before=%#v after=%#v", test.name, beforeHome, after)
		}
		if after := snapshotInspectionHome(t, workspace); !reflect.DeepEqual(after, beforeWorkspace) {
			t.Fatalf("explanation failure %s changed workspace state: before=%#v after=%#v", test.name, beforeWorkspace, after)
		}
		assertNoSessions(t, home)
	}
}

type nativeExplanationFact struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
	Source struct {
		ID      string `json:"id"`
		Version int    `json:"version"`
	} `json:"source"`
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

type privateCapabilityObservation struct {
	CurrentReadable        bool `json:"currentReadable"`
	OtherReadable          bool `json:"otherReadable"`
	EnvironmentLeak        bool `json:"environmentLeak"`
	CurrentDescriptorLeak  bool `json:"currentDescriptorLeak"`
	InjectedDescriptorLeak bool `json:"injectedDescriptorLeak"`
}

type privateCapabilityProbe struct {
	Current       string `json:"current"`
	Other         string `json:"other"`
	CurrentDevice uint64 `json:"currentDevice"`
	CurrentInode  uint64 `json:"currentInode"`
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
		case "--tripwire":
			if len(arguments) != 3 || !writeFakeDevinMarker(arguments[2]) {
				os.Exit(91)
			}
			return true
		case "--private-capability-live", "--private-capability-hold":
			if len(arguments) != 4 {
				os.Exit(90)
			}
			if !writeFakeDevinMarker(arguments[2]) {
				os.Exit(89)
			}
			for !fakeDevinMarkerExists(arguments[3]) {
				time.Sleep(10 * time.Millisecond)
			}
			if arguments[1] == "--private-capability-hold" {
				return true
			}
			contents, err := os.ReadFile(filepath.Join(mustGetwd(), ".acs-native-private-capability-probe.json"))
			if err != nil {
				os.Exit(88)
			}
			var probe privateCapabilityProbe
			if json.Unmarshal(contents, &probe) != nil || probe.Current == "" || probe.Other == "" || probe.CurrentDevice == 0 || probe.CurrentInode == 0 {
				os.Exit(87)
			}
			current, currentErr := os.ReadFile(probe.Current)
			other, otherErr := os.ReadFile(probe.Other)
			observation := privateCapabilityObservation{
				CurrentReadable:        currentErr == nil && len(current) != 0,
				OtherReadable:          otherErr == nil && len(other) != 0,
				EnvironmentLeak:        os.Getenv("ACS_SESSION_PRIVATE_CHALLENGE") != "",
				InjectedDescriptorLeak: fakeDevinDescriptorContains(privateDescriptorValue),
			}
			for descriptor := 3; descriptor < 64; descriptor++ {
				if nativeDescriptorMatches(descriptor, probe.CurrentDevice, probe.CurrentInode) {
					observation.CurrentDescriptorLeak = true
				}
			}
			encoded, _ := json.Marshal(observation)
			if os.WriteFile(filepath.Join(mustGetwd(), ".acs-native-private-capability-result.json"), encoded, 0o600) != nil {
				os.Exit(86)
			}
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

func TestNativeDescriptorIdentityDetectorPositiveControl(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "descriptor-identity")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	device, inode := nativeFileIdentity(t, file.Name())
	if !nativeDescriptorMatches(int(file.Fd()), device, inode) {
		t.Fatal("descriptor identity detector missed an intentionally open descriptor")
	}
}

func nativeDescriptorMatches(descriptor int, device, inode uint64) bool {
	var stat unix.Stat_t
	return unix.Fstat(descriptor, &stat) == nil && uint64(stat.Dev) == device && stat.Ino == inode
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
	declarations := map[string]map[string]nativeExplanationFact{}
	for access, profileName := range map[string]string{"read-write": "generic-readwrite", "read-only": "generic-readonly"} {
		explain := exec.Command(binary, "explain", "run", "--profile", profileName, "--json", "--", helper,
			"--acs-generic-command-helper", externalSecret, externalWrite)
		explain.Dir, explain.Env = workspace, nativeCandidateEnvironment(home, path, map[string]string{"ACS_GENERIC_HOST_SECRET": "hidden"})
		output, err := explain.CombinedOutput()
		if err != nil {
			t.Fatalf("generic %s explanation: %v; output=%s", access, err, output)
		}
		var result struct {
			Plan struct {
				Requested   []nativeExplanationFact `json:"requested"`
				TargetAdded []nativeExplanationFact `json:"targetAdded"`
				Effective   []nativeExplanationFact `json:"effective"`
			} `json:"plan"`
		}
		if err := json.Unmarshal(output, &result); err != nil {
			t.Fatalf("decode generic %s explanation: %v; output=%s", access, err, output)
		}
		facts := map[string]nativeExplanationFact{}
		for _, list := range [][]nativeExplanationFact{result.Plan.Requested, result.Plan.TargetAdded, result.Plan.Effective} {
			for _, fact := range list {
				facts[fact.ID] = fact
			}
		}
		if workspaceFact, found := facts["common.workspace"]; !found || workspaceFact.Value.Access != access {
			t.Fatalf("generic %s explanation workspace fact = %#v", access, workspaceFact)
		}
		for _, id := range []string{"run.command", "run.literal-argv", "runtime.environment", "runtime.environment.fixed-path", "runtime.environment.synthetic", "runtime.process", "runtime.session", "runtime.terminal", "runtime.devices", "workspace.read"} {
			if _, found := facts[id]; !found {
				t.Fatalf("generic %s explanation omitted declaration %s", access, id)
			}
		}
		declarations[access] = facts
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

	beforeGenericSessions := promotedSessionSnapshot(t, binary, home, path)
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
	assertGenericObservationMatchesDeclaration(t, "read-write", declarations["read-write"], observation)
	if stderr.String() != "generic-stderr-ok\n" {
		t.Fatalf("stderr = %q", stderr.String())
	}
	assertMarkerExists(t, filepath.Join(workspace, "generic-workspace-write"))
	assertNoSessions(t, home)
	assertNewRemovedPromotedSessions(t, binary, home, path, beforeGenericSessions, "command")

	assertLiveTrackedCapabilityIsolation(t, binary, helper, home, path, workspace)
	privateRoot := filepath.Join(home, ".acs", "session-operations-v1")
	alias := filepath.Join(realTemporaryDirectory(t), "private-workspace-alias")
	if err := os.Symlink(privateRoot, alias); err != nil {
		t.Fatal(err)
	}
	aliasTripwire := filepath.Join(workspace, "private-alias-target-started")
	aliasCommand := exec.Command(binary, "run", "--profile", "generic-readwrite", "--", helper,
		"--acs-generic-command-helper", "--tripwire", aliasTripwire)
	aliasCommand.Dir, aliasCommand.Env = alias, nativeCandidateEnvironment(home, path, nil)
	aliasOutput, err := aliasCommand.CombinedOutput()
	if err == nil {
		t.Fatal("candidate accepted a workspace alias to private Session capabilities")
	}
	assertSafeCandidateFailure(t, aliasOutput, "unsafe_path", privateDescriptorValue, "other-session-private-challenge")
	assertMarkerAbsent(t, aliasTripwire, "target started from a private capability workspace alias")
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
	assertGenericObservationMatchesDeclaration(t, "read-only", declarations["read-only"], observation)
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

// assertLiveTrackedCapabilityIsolation observes the candidate-created private
// records while two actual contained commands remain live.  The target receives
// only host-selected path names, never a capability challenge or record bytes.
func assertLiveTrackedCapabilityIsolation(t *testing.T, binary, helper, home, path, workspace string) {
	t.Helper()
	capabilities := filepath.Join(home, ".acs", "session-operations-v1", "capabilities")
	currentReady, currentRelease := filepath.Join(workspace, ".acs-native-current-ready"), filepath.Join(workspace, ".acs-native-current-release")
	otherReady, otherRelease := filepath.Join(workspace, ".acs-native-other-ready"), filepath.Join(workspace, ".acs-native-other-release")
	injectedPath := filepath.Join(workspace, ".acs-native-injected-descriptor")
	if err := os.WriteFile(injectedPath, []byte(privateDescriptorValue), 0o600); err != nil {
		t.Fatal(err)
	}
	injected, err := os.Open(injectedPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = injected.Close() })
	current := exec.Command(binary, "run", "--profile", "generic-readwrite", "--", helper, "--acs-generic-command-helper", "--private-capability-live", currentReady, currentRelease)
	current.Dir, current.Env = workspace, nativeCandidateEnvironment(home, path, map[string]string{"ACS_SESSION_PRIVATE_CHALLENGE": "must-not-reach-target"})
	current.ExtraFiles = []*os.File{injected}
	var currentOutput synchronizedNativeCapture
	current.Stdout, current.Stderr = &currentOutput, &currentOutput
	if err := current.Start(); err != nil {
		t.Fatal(err)
	}
	currentDone := startNativeCommand(current)
	t.Cleanup(func() {
		_ = writeFakeDevinMarker(currentRelease)
		settleNativeCommand(current, currentDone)
	})
	if !waitForFakeDevinMarker(currentReady, 10*time.Second) {
		t.Fatal("live current Session target did not become ready")
	}
	currentCapability := onlyNativeCapability(t, capabilities)

	other := exec.Command(binary, "run", "--profile", "generic-readwrite", "--", helper, "--acs-generic-command-helper", "--private-capability-hold", otherReady, otherRelease)
	other.Dir, other.Env = workspace, nativeCandidateEnvironment(home, path, nil)
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	otherDone := startNativeCommand(other)
	t.Cleanup(func() {
		_ = writeFakeDevinMarker(otherRelease)
		settleNativeCommand(other, otherDone)
	})
	if !waitForFakeDevinMarker(otherReady, 10*time.Second) {
		t.Fatal("live other Session target did not become ready")
	}
	otherCapability := otherNativeCapability(t, capabilities, currentCapability)
	currentDevice, currentInode := nativeFileIdentity(t, currentCapability)
	probe, err := json.Marshal(privateCapabilityProbe{Current: currentCapability, Other: otherCapability, CurrentDevice: currentDevice, CurrentInode: currentInode})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, ".acs-native-private-capability-probe.json"), probe, 0o600); err != nil {
		t.Fatal(err)
	}
	if !writeFakeDevinMarker(currentRelease) {
		t.Fatal("release current capability witness")
	}
	if err := waitNativeCommand(currentDone, 10*time.Second); err != nil {
		t.Fatalf("live current capability witness: %v; output=%s", err, currentOutput.String())
	}
	result, err := os.ReadFile(filepath.Join(workspace, ".acs-native-private-capability-result.json"))
	if err != nil {
		t.Fatal("read live capability observation")
	}
	var observation privateCapabilityObservation
	if err := json.Unmarshal(result, &observation); err != nil {
		t.Fatal("decode live capability observation")
	}
	if observation.CurrentReadable || observation.OtherReadable || observation.EnvironmentLeak || observation.CurrentDescriptorLeak || observation.InjectedDescriptorLeak {
		t.Fatalf("contained target received current or cross-Session private authority: %+v", observation)
	}
	if !writeFakeDevinMarker(otherRelease) {
		t.Fatal("release other capability witness")
	}
	if err := waitNativeCommand(otherDone, 10*time.Second); err != nil {
		t.Fatalf("live other capability witness: %v", err)
	}
	assertNoSessions(t, home)
}

type synchronizedNativeCapture struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (capture *synchronizedNativeCapture) Write(contents []byte) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.b.Write(contents)
}

func (capture *synchronizedNativeCapture) String() string {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return capture.b.String()
}

type nativeCommandDone struct {
	done chan struct{}
	err  error
}

func startNativeCommand(command *exec.Cmd) *nativeCommandDone {
	result := &nativeCommandDone{done: make(chan struct{})}
	go func() {
		result.err = command.Wait()
		close(result.done)
	}()
	return result
}

func waitNativeCommand(result *nativeCommandDone, timeout time.Duration) error {
	select {
	case <-result.done:
		return result.err
	case <-time.After(timeout):
		return fmt.Errorf("did not settle within %s", timeout)
	}
}

func settleNativeCommand(command *exec.Cmd, result *nativeCommandDone) {
	select {
	case <-result.done:
		return
	case <-time.After(2 * time.Second):
		_ = command.Process.Kill()
		select {
		case <-result.done:
		case <-time.After(2 * time.Second):
		}
	}
}

func nativeFileIdentity(t *testing.T, path string) (uint64, uint64) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat host-observed private capability: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Dev == 0 || stat.Ino == 0 {
		t.Fatalf("host private capability has no stable file identity: %#v", info.Sys())
	}
	return uint64(stat.Dev), stat.Ino
}

func onlyNativeCapability(t *testing.T, directory string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		entries, _ := filepath.Glob(filepath.Join(directory, "*.json"))
		if len(entries) == 1 {
			return entries[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("candidate did not publish exactly one current private capability in %s", directory)
	return ""
}

func otherNativeCapability(t *testing.T, directory, current string) string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		entries, _ := filepath.Glob(filepath.Join(directory, "*.json"))
		for _, entry := range entries {
			if entry != current {
				return entry
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("candidate did not publish a second current private capability in %s", directory)
	return ""
}

type promotedPublicSession struct {
	ID       string `json:"id"`
	State    string `json:"state"`
	Target   string `json:"target"`
	Revision uint64 `json:"revision"`
}

func promotedSessionSnapshot(t *testing.T, binary, home, path string) map[string]promotedPublicSession {
	t.Helper()
	command := exec.Command(binary, "session", "list", "--json")
	command.Env = nativeCandidateEnvironment(home, path, nil)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("candidate session list: %v; output=%s", err, output)
	}
	var result struct {
		Sessions []promotedPublicSession `json:"sessions"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode candidate session list: %v; output=%s", err, output)
	}
	snapshot := make(map[string]promotedPublicSession, len(result.Sessions))
	for _, item := range result.Sessions {
		snapshot[item.ID] = item
	}
	return snapshot
}

func assertNewRemovedPromotedSessions(t *testing.T, binary, home, path string, before map[string]promotedPublicSession, target string) {
	t.Helper()
	after := promotedSessionSnapshot(t, binary, home, path)
	found := 0
	for id, item := range after {
		if _, existed := before[id]; existed {
			continue
		}
		found++
		if item.State != "removed" || item.Target != target || item.Revision == 0 {
			t.Fatalf("candidate lifecycle row = %+v", item)
		}
		inspect := exec.Command(binary, "session", "inspect", id, "--json")
		inspect.Env = nativeCandidateEnvironment(home, path, nil)
		output, err := inspect.Output()
		if err != nil {
			t.Fatalf("candidate session inspect: %v; output=%s", err, output)
		}
		text := string(output)
		if !strings.Contains(text, `"state":"removed"`) || strings.Contains(text, "rootToken") || strings.Contains(text, "challenge") || strings.Contains(text, "session-") {
			t.Fatalf("candidate session inspect was not sanitized: %s", output)
		}
	}
	if found == 0 {
		t.Fatal("candidate contained operation published no durable Session lifecycle row")
	}
}

func assertGenericObservationMatchesDeclaration(t *testing.T, access string, facts map[string]nativeExplanationFact, observation genericHelperObservation) {
	t.Helper()
	_, declaresWrite := facts["workspace.write"]
	wantWrite := access == "read-write"
	if declaresWrite != wantWrite || observation.WorkspaceWrite != wantWrite {
		t.Fatalf("generic %s declaration/observation workspace write = (%v, %v), want %v", access, declaresWrite, observation.WorkspaceWrite, wantWrite)
	}
	if !observation.SafePath || !observation.HostSecretGone || !observation.HomeIsSynthetic {
		t.Fatalf("generic %s environment observation did not corroborate fixed-path/synthetic/environment declarations: %#v", access, observation)
	}
	if observation.ExternalRead || observation.ExternalWrite {
		t.Fatalf("generic %s behavior exceeded declared workspace/Session authority: %#v", access, observation)
	}
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
		devinRequested, devinTargetAdded, devinEffective := map[string]nativeExplanationFact{}, map[string]nativeExplanationFact{}, map[string]nativeExplanationFact{}
		for _, target := range []string{"devin", "codex"} {
			arguments := []string{target, "--profile", name, "--dry-run"}
			if target == "codex" && access == "read-write" {
				arguments = append(arguments, "--auth", explanationOverrideAuthRef)
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
				explainArguments = append(explainArguments, "--auth", explanationOverrideAuthRef)
			}
			explain := exec.Command(binary, explainArguments...)
			explain.Env, explain.Dir = nativeCandidateEnvironment(home, path, nil), workspace
			explanationOutput, err := explain.CombinedOutput()
			if err != nil {
				t.Fatalf("installed candidate %s explanation: %v; output=%s", target, err, explanationOutput)
			}
			privateReferenceLeaked := target == "codex" && (bytes.Contains(explanationOutput, []byte(explanationStoredAuthRef)) || bytes.Contains(explanationOutput, []byte(explanationOverrideAuthRef)))
			if bytes.Contains(explanationOutput, []byte("unselected")) || bytes.Contains(explanationOutput, []byte(workspace)) || privateReferenceLeaked {
				t.Fatalf("%s explanation exposed unselected/private binding: %s", target, explanationOutput)
			}
			var explanation struct {
				Plan struct {
					Requested   []nativeExplanationFact `json:"requested"`
					TargetAdded []nativeExplanationFact `json:"targetAdded"`
					Effective   []nativeExplanationFact `json:"effective"`
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
			if target == "devin" {
				for _, fact := range explanation.Plan.Requested {
					devinRequested[fact.ID] = fact
				}
				for _, fact := range explanation.Plan.TargetAdded {
					devinTargetAdded[fact.ID] = fact
				}
				for _, fact := range explanation.Plan.Effective {
					devinEffective[fact.ID] = fact
				}
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
		codexReference := explanationStoredAuthRef
		if access == "read-write" {
			codexReference = explanationOverrideAuthRef
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
		if err != nil || !bytes.Contains(profileBytes, []byte(`"authRef":"`+explanationStoredAuthRef+`"`)) || bytes.Contains(profileBytes, []byte("override")) {
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
		if workspaceFact, found := devinRequested["common.workspace"]; !found || workspaceFact.Value.Access != access {
			t.Fatalf("Devin behavioral result lacks matching declared workspace authority: %#v", workspaceFact)
		}
		for _, id := range []string{"devin.preflight.skills", "devin.preflight.authentication", "devin.credentials", "devin.project-skills", "skills.projection.devin-config:review", "skills.projection.shared-agents:delivery"} {
			if _, found := devinTargetAdded[id]; !found {
				t.Fatalf("Devin behavioral result lacks matching target declaration %s", id)
			}
		}
		for _, id := range []string{"runtime.session", "skills.common.devin-config:review", "skills.common.shared-agents:delivery", "workspace.read"} {
			if _, found := devinEffective[id]; !found {
				t.Fatalf("Devin behavioral result lacks matching effective declaration %s", id)
			}
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
		_, declaresWorkspaceWrite := devinEffective["workspace.write"]
		if declaresWorkspaceWrite != wantWorkspaceWrite {
			t.Fatalf("Devin declared workspace write=%v, want %v", declaresWorkspaceWrite, wantWorkspaceWrite)
		}
		if result.WorkspaceWritable != wantWorkspaceWrite {
			t.Fatalf("Devin %s workspace write = %v, want %v", access, result.WorkspaceWritable, wantWorkspaceWrite)
		}
		if result.HostFileReadable || result.ExternalWriteSucceeded {
			t.Fatalf("Devin %s fixture reached unrelated host state: %#v", access, result)
		}
		assertMarkerAbsent(t, unrelatedWrite, "shared Devin fixture wrote unrelated host path")
		assertNoSessions(t, home)
	}

	legacy := exec.Command(binary, "codex", "--profile", "reviews", "--auth", explanationStoredAuthRef, "--dry-run")
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
		explain := exec.Command(binary, "explain", "sandbox", "--profile", test.profile, "--json")
		explain.Env, explain.Dir = nativeCandidateEnvironment(home, path, nil), workspace
		explanationOutput, err := explain.CombinedOutput()
		if err != nil {
			t.Fatalf("installed v3 %s explanation: %v; output=%s", test.profile, err, explanationOutput)
		}
		var explanation struct {
			Plan struct {
				Requested []nativeExplanationFact `json:"requested"`
				Effective []nativeExplanationFact `json:"effective"`
			} `json:"plan"`
		}
		if err := json.Unmarshal(explanationOutput, &explanation); err != nil {
			t.Fatalf("decode v3 %s explanation: %v; output=%s", test.profile, err, explanationOutput)
		}
		workspaceFact, found := nativeExplanationFactByID(explanation.Plan.Requested, "common.workspace")
		wantAccess := "read-only"
		if test.writable {
			wantAccess = "read-write"
		}
		if !found || workspaceFact.Value.Access != wantAccess || nativeExplanationHasFact(explanation.Plan.Effective, "workspace.write") != test.writable || !nativeExplanationHasFact(explanation.Plan.Effective, "runtime.session") {
			t.Fatalf("v3 %s declared authority does not match expected behavioral case: %#v", test.profile, explanation.Plan)
		}
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
	beforeShellSessions := promotedSessionSnapshot(t, binary, home, path)
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
	assertNewRemovedPromotedSessions(t, binary, home, path, beforeShellSessions, "shell")
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
	explain := exec.Command(binary, "explain", "devin", "--profile", "reviews", "--json")
	explain.Dir, explain.Env = workspace, nativeCandidateEnvironment(home, tools+string(os.PathListSeparator)+path, map[string]string{
		"ACS_NATIVE_CANDIDATE_SECRET": privateEnvironmentValue,
	})
	explanationOutput, err := explain.CombinedOutput()
	if err != nil {
		t.Fatalf("native containment explanation: %v; output=%s", err, explanationOutput)
	}
	var explanation struct {
		Plan struct {
			Requested []nativeExplanationFact `json:"requested"`
			Effective []nativeExplanationFact `json:"effective"`
		} `json:"plan"`
	}
	if err := json.Unmarshal(explanationOutput, &explanation); err != nil {
		t.Fatalf("decode native containment explanation: %v; output=%s", err, explanationOutput)
	}
	workspaceFact, found := nativeExplanationFactByID(explanation.Plan.Requested, "common.workspace")
	if !found || workspaceFact.Value.Access != "read-write" {
		t.Fatalf("native containment explanation workspace fact = %#v", workspaceFact)
	}
	declared := map[string]nativeExplanationFact{}
	for _, fact := range explanation.Plan.Effective {
		declared[fact.ID] = fact
	}
	for _, id := range []string{"runtime.environment", "runtime.environment.fixed-path", "runtime.environment.synthetic", "runtime.devices", "runtime.mach-services", "runtime.network", "runtime.process", "runtime.session", "runtime.sysctls", "runtime.terminal", "workspace.read", "workspace.write"} {
		if _, found := declared[id]; !found {
			t.Fatalf("native containment behavior lacks matching effective declaration %s", id)
		}
	}
	if declared["runtime.network"].Value.Mode != "local-ip-socket-bind-no-listen-coarse-outbound-ip-macos-dns" {
		t.Fatalf("native containment network declaration = %#v", declared["runtime.network"])
	}
	if got := declared["runtime.sysctls"].Value.Names; !reflect.DeepEqual(got, []string{"hw.ncpu", "hw.pagesize", "hw.pagesize_compat"}) {
		t.Fatalf("native containment sysctl declaration = %q", got)
	}
	if got := declared["runtime.mach-services"].Value.Names; !reflect.DeepEqual(got, []string{"com.apple.SecurityServer", "com.apple.trustd.agent"}) {
		t.Fatalf("native containment Mach-service declaration = %q", got)
	}

	descriptor, err := os.Open(hostSecret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = descriptor.Close() })
	beforeDevinSessions := promotedSessionSnapshot(t, binary, home, path)
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
		"workspace write":      result.WorkspaceWritable,
		"Session write":        result.SessionWritable,
		"Session temporary":    result.TemporaryWritable,
		"allowed environment":  result.AllowedEnvironment,
		"outbound IP":          result.OutboundIP,
		"local IP bind":        result.LocalIPBind,
		"descendant start":     result.DescendantStarted,
		"registered sysctls":   result.RegisteredSysctls,
		"system trust read":    result.SystemTrustSettings,
		"local trust evaluate": result.LocalSystemTrust,
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
		"unregistered sysctl":  !result.UnregisteredSysctlDenied,
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
	assertNewRemovedPromotedSessions(t, binary, home, path, beforeDevinSessions, "devin")
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
	RegisteredSysctls         bool `json:"registeredSysctls"`
	UnregisteredSysctlDenied  bool `json:"unregisteredSysctlDenied"`
	SystemTrustSettings       bool `json:"systemTrustSettings"`
	LocalSystemTrust          bool `json:"localSystemTrust"`
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
	holdFakeDevinGenerationPhase(configuration, "skills", workspace)
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
	holdFakeDevinGenerationPhase(configuration, "authentication", mustGetwd())
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
	holdFakeDevinGenerationPhase(configuration, "interactive", workspace)
	if configuration.Mode == "session-generations" {
		return
	}
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
		RegisteredSysctls:         fakeDevinRegisteredSysctls(),
		UnregisteredSysctlDenied:  fakeDevinUnregisteredSysctlDenied(),
		SystemTrustSettings:       fakeDevinCopySystemTrustSettings() == nil,
		LocalSystemTrust:          fakeDevinEvaluateLocalSystemTrust() == nil,
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

func holdFakeDevinGenerationPhase(configuration fakeDevinConfiguration, phase, workspace string) {
	if configuration.Mode != "session-generations" {
		return
	}
	ready := filepath.Join(workspace, ".acs-phase-"+phase+"-ready")
	release := filepath.Join(workspace, ".acs-phase-"+phase+"-release")
	if os.WriteFile(ready+".pending", []byte(os.Getenv("HOME")), 0o600) != nil || os.Rename(ready+".pending", ready) != nil {
		os.Exit(70)
	}
	deadline := time.Now().Add(20 * time.Second)
	for !fakeDevinMarkerExists(release) {
		if time.Now().After(deadline) {
			os.Exit(69)
		}
		time.Sleep(10 * time.Millisecond)
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

func fakeDevinRegisteredSysctls() bool {
	for _, name := range []string{"hw.ncpu", "hw.pagesize", "hw.pagesize_compat"} {
		if _, err := unix.SysctlUint32(name); err != nil {
			return false
		}
	}
	return true
}

func fakeDevinUnregisteredSysctlDenied() bool {
	_, err := unix.Sysctl("kern.hostname")
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

func fakeDevinCopySystemTrustSettings() error {
	security, err := purego.Dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return err
	}
	defer func() { _ = purego.Dlclose(security) }()
	coreFoundation, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return err
	}
	defer func() { _ = purego.Dlclose(coreFoundation) }()
	var copyCertificates func(uint32, *unsafe.Pointer) int32
	var arrayCount func(unsafe.Pointer) int
	var release func(unsafe.Pointer)
	purego.RegisterLibFunc(&copyCertificates, security, "SecTrustSettingsCopyCertificates")
	purego.RegisterLibFunc(&arrayCount, coreFoundation, "CFArrayGetCount")
	purego.RegisterLibFunc(&release, coreFoundation, "CFRelease")
	var certificates unsafe.Pointer
	status := copyCertificates(2, &certificates)
	if certificates != nil {
		defer release(certificates)
	}
	if status != 0 || certificates == nil || arrayCount(certificates) <= 0 {
		return errors.New("system trust settings unavailable")
	}
	return nil
}

func fakeDevinEvaluateLocalSystemTrust() error {
	security, err := purego.Dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return err
	}
	defer func() { _ = purego.Dlclose(security) }()
	coreFoundation, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return err
	}
	defer func() { _ = purego.Dlclose(coreFoundation) }()
	var copyCertificates func(uint32, *unsafe.Pointer) int32
	var arrayCount func(unsafe.Pointer) int
	var arrayValueAtIndex func(unsafe.Pointer, int) unsafe.Pointer
	var createBasicX509 func() unsafe.Pointer
	var createTrust func(unsafe.Pointer, unsafe.Pointer, *unsafe.Pointer) int32
	var setNetworkFetchAllowed func(unsafe.Pointer, uint8) int32
	var evaluateTrust func(unsafe.Pointer, *unsafe.Pointer) bool
	var release func(unsafe.Pointer)
	purego.RegisterLibFunc(&copyCertificates, security, "SecTrustSettingsCopyCertificates")
	purego.RegisterLibFunc(&arrayCount, coreFoundation, "CFArrayGetCount")
	purego.RegisterLibFunc(&arrayValueAtIndex, coreFoundation, "CFArrayGetValueAtIndex")
	purego.RegisterLibFunc(&createBasicX509, security, "SecPolicyCreateBasicX509")
	purego.RegisterLibFunc(&createTrust, security, "SecTrustCreateWithCertificates")
	purego.RegisterLibFunc(&setNetworkFetchAllowed, security, "SecTrustSetNetworkFetchAllowed")
	purego.RegisterLibFunc(&evaluateTrust, security, "SecTrustEvaluateWithError")
	purego.RegisterLibFunc(&release, coreFoundation, "CFRelease")
	var certificates unsafe.Pointer
	if status := copyCertificates(2, &certificates); status != 0 || certificates == nil {
		return errors.New("system trust certificates unavailable")
	}
	defer release(certificates)
	if arrayCount(certificates) <= 0 {
		return errors.New("system trust certificates empty")
	}
	certificate := arrayValueAtIndex(certificates, 0)
	policy := createBasicX509()
	if certificate == nil || policy == nil {
		return errors.New("local trust inputs unavailable")
	}
	defer release(policy)
	var trust unsafe.Pointer
	if status := createTrust(certificate, policy, &trust); status != 0 || trust == nil {
		return errors.New("local trust creation unavailable")
	}
	defer release(trust)
	if setNetworkFetchAllowed(trust, 0) != 0 {
		return errors.New("local trust network control unavailable")
	}
	var evaluationError unsafe.Pointer
	trusted := evaluateTrust(trust, &evaluationError)
	if evaluationError != nil {
		defer release(evaluationError)
	}
	if !trusted {
		return errors.New("local system trust unavailable")
	}
	return nil
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
	var family int
	var socketAddress unix.Sockaddr
	switch network {
	case "tcp4":
		family = unix.AF_INET
		socketAddress = &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}
	case "unix":
		family = unix.AF_UNIX
		socketAddress = &unix.SockaddrUnix{Name: address}
	default:
		return false
	}
	descriptor, err := unix.Socket(family, unix.SOCK_STREAM, 0)
	if err != nil {
		return false
	}
	unix.CloseOnExec(descriptor)
	bindErr := unix.Bind(descriptor, socketAddress)
	closeErr := unix.Close(descriptor)
	if family == unix.AF_UNIX && bindErr == nil {
		_ = os.Remove(address)
	}
	return bindErr == nil && closeErr == nil
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
	for _, key := range []string{"HOME", "PATH", "TERM", "NO_COLOR", "ACS_NATIVE_CANDIDATE_SECRET", "ACS_GENERIC_HOST_SECRET", "ACS_SESSION_PRIVATE_CHALLENGE"} {
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
