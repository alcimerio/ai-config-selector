//go:build darwin

package launch

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/creack/pty"
	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

func TestSeatbeltPolicyIsDefaultDenyAndUsesParametersForValidatedPaths(t *testing.T) {
	request := validatedProcessRequest{
		workspace:        `/private/tmp/workspace-\"quoted`,
		sessionDirectory: "/private/tmp/session\nprivate",
		executable:       "/private/tmp/bin/devin",
		runtimeInputs:    []string{"/private/tmp/runtime/input.pem"},
	}
	policy, definitions, err := buildSeatbeltPolicy(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"(version 1)", "(deny default)", `(param "WORKSPACE")`,
		`(param "SESSION")`, `(param "EXECUTABLE")`, `(param "RUNTIME_0")`,
		`(remote ip)`, `(literal "/private/var/run/mDNSResponder")`,
		`(literal "/var")`,
		`(literal "/private/var/select/sh")`,
		`(literal "/dev/tty")`, `(target same-sandbox)`,
		"(allow mach-lookup\n  (global-name \"com.apple.SecurityServer\"))",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("policy omits %q", want)
		}
	}
	for _, forbidden := range []string{
		request.workspace, request.sessionDirectory, request.executable,
		request.runtimeInputs[0], "(allow file-read*)\n",
		"(allow sysctl-read)\n", "(allow iokit", "(allow network*)",
	} {
		if strings.Contains(policy, forbidden) {
			t.Errorf("policy contains forbidden text %q", forbidden)
		}
	}
	if got := strings.Count(policy, "(allow mach-lookup"); got != 1 {
		t.Fatalf("Mach lookup rule count = %d, want only com.apple.SecurityServer", got)
	}
	if got := strings.Count(policy, "(global-name"); got != 1 {
		t.Fatalf("Mach service count = %d, want only com.apple.SecurityServer", got)
	}
	wantDefinitions := []string{
		"-DWORKSPACE=" + request.workspace,
		"-DSESSION=" + request.sessionDirectory,
		"-DEXECUTABLE=" + request.executable,
		"-DRUNTIME_0=" + request.runtimeInputs[0],
	}
	if strings.Join(definitions, "\n") != strings.Join(wantDefinitions, "\n") {
		t.Fatalf("definitions = %#v, want %#v", definitions, wantDefinitions)
	}
}

func TestSeatbeltCheckRejectsUnsafeSystemExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox-exec")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	backend := newSeatbeltBackend(path)
	err := backend.check(context.Background())
	if err == nil {
		t.Fatal("unsafe backend accepted")
	}
	assertSandboxCategory(t, err, SandboxBackendUnavailable)
	if strings.Contains(err.Error(), path) {
		t.Fatalf("backend error leaked path: %v", err)
	}
}

func TestSeatbeltRejectsInvalidGeneratedPolicyBeforeAttachingTargetStreams(t *testing.T) {
	for _, test := range []struct {
		name        string
		policy      string
		definitions []string
	}{
		{name: "policy", policy: `(version 1) (REJECTED_POLICY_TOKEN default)`},
		{
			name:        "definition",
			policy:      `(version 1) (deny default)`,
			definitions: []string{"-DREJECTED_DEFINITION_TOKEN"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := seatbeltTestRequest(t)
			marker := filepath.Join(request.workspace, "target-started")
			request.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", "mark", marker}
			var output bytes.Buffer
			var errorOutput bytes.Buffer
			request.terminal = Terminal{Output: &output, ErrorOutput: &errorOutput}
			backend := newSeatbeltBackend(seatbeltExecutable)
			backend.policy = func(validatedProcessRequest) (string, []string, error) {
				return test.policy, test.definitions, nil
			}

			process, err := backend.prepare(context.Background(), request)
			if err == nil {
				t.Fatal("invalid generated policy unexpectedly prepared a target")
			}
			if process != nil {
				t.Fatal("invalid generated policy returned a target process")
			}
			assertSandboxCategory(t, err, SandboxSetupFailed)
			for _, leaked := range []string{
				"REJECTED_POLICY_TOKEN", "REJECTED_DEFINITION_TOKEN", "sandbox-exec",
			} {
				if strings.Contains(err.Error(), leaked) || strings.Contains(output.String(), leaked) ||
					strings.Contains(errorOutput.String(), leaked) {
					t.Fatalf("rejected backend diagnostic %q leaked: error=%q stdout=%q stderr=%q", leaked, err, output.String(), errorOutput.String())
				}
			}
			if output.Len() != 0 || errorOutput.Len() != 0 {
				t.Fatalf("policy validation reached target streams: stdout=%q stderr=%q", output.String(), errorOutput.String())
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("target marker exists after invalid policy: %v", err)
			}
		})
	}
}

func TestSeatbeltCleansDescendantAfterProcessGroupAndSessionEscape(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	result := filepath.Join(request.workspace, "setsid-result")
	marker := filepath.Join(request.workspace, "escaped-descendant-survived")
	request.arguments = []string{
		"-test.run=TestSeatbeltHelperProcess", "--", "process-group-escape-parent", result, marker,
	}
	process, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatalf("top-level target failed: %v", err)
	}
	resultContents, err := os.ReadFile(result)
	if err != nil {
		t.Fatalf("read descendant setsid result: %v", err)
	}
	if got := strings.TrimSpace(string(resultContents)); got != "escaped" {
		t.Fatalf("descendant setsid result = %q, want a real process-group escape", got)
	}
	if err := os.RemoveAll(request.sessionDirectory); err != nil {
		t.Fatalf("remove settled Session: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("descendant survived CleanupDone after process-group escape attempt: %v", err)
	}
}

func TestSeatbeltResolvesHostnameThroughMDNSSocketAlias(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	request.arguments = []string{
		"-test.run=TestSeatbeltHelperProcess", "--", "resolve-hostname", "example.com",
	}
	var output bytes.Buffer
	request.terminal = Terminal{Output: &output, ErrorOutput: &output}
	process, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatalf("hostname lookup failed: %v; output=%q", err, output.String())
	}
	if got := strings.TrimSpace(output.String()); got != "resolved" {
		t.Fatalf("hostname lookup output = %q", got)
	}
}

func TestSeatbeltReadsSystemTrustSettingsThroughSecurityServer(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	request.arguments = []string{
		"-test.run=TestSeatbeltHelperProcess", "--", "copy-system-trust-settings",
	}
	var output bytes.Buffer
	request.terminal = Terminal{Output: &output, ErrorOutput: &output}
	process, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatalf("trust-settings read failed: %v; output=%q", err, output.String())
	}
}

func TestSeatbeltRejectsMalformedMissingAndSpoofedCleanupProof(t *testing.T) {
	challenge := bytes.Repeat([]byte{0x5a}, seatbeltChallengeSize)
	validWrongChallenge, err := json.Marshal(seatbeltCleanupProof{
		Magic: seatbeltProofMagic, Version: seatbeltProofVersion,
		Challenge:       strings.Repeat("00", seatbeltChallengeSize),
		ZeroLiveTargets: true, NoTargetStarted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		command  *exec.Cmd
		response []byte
	}{
		{name: "missing"},
		{name: "malformed", response: []byte("not-json\n")},
		{name: "spoofed", response: append(validWrongChallenge, '\n')},
		{name: "raw-status-125", command: exec.Command("/bin/sh", "-c", "exit 125")},
	} {
		t.Run(test.name, func(t *testing.T) {
			parent, peer := seatbeltTestSocketPair(t)
			command := test.command
			if command == nil {
				command = exec.Command("/usr/bin/true")
			}
			process := newSeatbeltLifecycleTestProcess(command)
			process.supervised = true
			process.control = parent
			process.challenge = append([]byte(nil), challenge...)
			go func() {
				defer peer.Close()
				got := make([]byte, len(challenge))
				_, _ = io.ReadFull(peer, got)
				if len(test.response) > 0 {
					_, _ = peer.Write(test.response)
				}
			}()
			if err := process.Start(); err != nil {
				t.Fatal(err)
			}
			err := process.Wait()
			assertSandboxCategory(t, err, SandboxProcessWaitFailed)
			select {
			case <-process.CleanupDone():
				t.Fatal("untrusted proof released cleanup quarantine")
			default:
			}
		})
	}
}

func TestSeatbeltSupervisorProvesPreTargetStartFailure(t *testing.T) {
	control, peer := seatbeltTestSocketPair(t)
	supervisorFD, err := unix.Dup(int(peer.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	challenge := bytes.Repeat([]byte{0x6b}, seatbeltChallengeSize)
	result := make(chan int, 1)
	go func() {
		result <- runSeatbeltSupervisor(supervisorFD, filepath.Join(t.TempDir(), "missing-target"), nil)
	}()
	if _, err := control.Write(challenge); err != nil {
		t.Fatal(err)
	}
	proof, err := io.ReadAll(control)
	if err != nil {
		t.Fatal(err)
	}
	if status := <-result; status != 125 {
		t.Fatalf("pre-target supervisor status = %d, want 125", status)
	}
	if err := validateSeatbeltCleanupProof(proof, challenge); err != nil {
		t.Fatalf("pre-target proof = %q, want valid: %v", proof, err)
	}
	var decoded seatbeltCleanupProof
	if err := json.Unmarshal(proof, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.NoTargetStarted || decoded.TargetExited || decoded.TargetExitCode != 0 || decoded.TargetSignal != 0 {
		t.Fatalf("pre-target proof = %#v, want an explicit no-target result", decoded)
	}
	if err := matchSeatbeltProofStatus(proof, seatbeltTestExitStatus(t, 125)); err != nil {
		t.Fatalf("pre-target status match = %v, want success", err)
	}
}

func TestSeatbeltRejectsSpoofedPreTargetProof(t *testing.T) {
	challenge := bytes.Repeat([]byte{0x37}, seatbeltChallengeSize)
	for _, test := range []struct {
		name  string
		proof seatbeltCleanupProof
	}{
		{
			name: "target-status",
			proof: seatbeltCleanupProof{
				Magic: seatbeltProofMagic, Version: seatbeltProofVersion,
				Challenge: hex.EncodeToString(challenge), ZeroLiveTargets: true,
				NoTargetStarted: true, TargetExited: true,
			},
		},
		{
			name: "target-exit-code",
			proof: seatbeltCleanupProof{
				Magic: seatbeltProofMagic, Version: seatbeltProofVersion,
				Challenge: hex.EncodeToString(challenge), ZeroLiveTargets: true,
				NoTargetStarted: true, TargetExitCode: 125,
			},
		},
		{
			name: "wrong-challenge",
			proof: seatbeltCleanupProof{
				Magic: seatbeltProofMagic, Version: seatbeltProofVersion,
				Challenge: strings.Repeat("00", seatbeltChallengeSize), ZeroLiveTargets: true,
				NoTargetStarted: true,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			data, err := json.Marshal(test.proof)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateSeatbeltCleanupProof(data, challenge); err == nil {
				t.Fatalf("spoofed pre-target proof %q unexpectedly validated", data)
			}
		})
	}
	valid, err := json.Marshal(seatbeltCleanupProof{
		Magic: seatbeltProofMagic, Version: seatbeltProofVersion,
		Challenge: hex.EncodeToString(challenge), ZeroLiveTargets: true, NoTargetStarted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := matchSeatbeltProofStatus(valid, seatbeltTestExitStatus(t, 124)); err == nil {
		t.Fatal("pre-target proof accepted a supervisor status other than 125")
	}
}

func TestSeatbeltAuthenticatedPreTargetFailureReleasesSession(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	session, err := CreateSession(request.sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	request.sessionDirectory = session.RootDir
	request.sessionHome = filepath.Join(session.RootDir, "home")
	request.temporaryDirectory = filepath.Join(session.RootDir, "tmp")
	for _, directory := range []string{request.sessionHome, request.temporaryDirectory} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	request.environment, err = buildProcessEnvironment(request.sessionHome, request.temporaryDirectory, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.executable = filepath.Join(t.TempDir(), "missing-target")
	process, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := RetainSessionUntilProcessDone(process, session)
	if err != nil {
		t.Fatal(err)
	}
	if err := retained.Start(); err != nil {
		t.Fatal(err)
	}
	if err := session.Remove(); err != nil {
		t.Fatal(err)
	}
	waitErr := retained.Wait()
	if waitErr == nil {
		t.Fatal("trusted pre-target failure unexpectedly reported success")
	}
	var exitError *exec.ExitError
	if !errors.As(waitErr, &exitError) {
		t.Fatalf("pre-target Wait error = %v, want exit status 125", waitErr)
	}
	status, ok := exitError.Sys().(syscall.WaitStatus)
	if !ok || !status.Exited() || status.ExitStatus() != 125 {
		t.Fatalf("pre-target Wait status = %v, want exit 125", exitError.Sys())
	}
	select {
	case <-retained.(ProcessCleanup).CleanupDone():
	case <-time.After(time.Second):
		t.Fatal("trusted pre-target proof did not complete cleanup")
	}
	seatbeltRequireSessionRemoved(t, session.RootDir)
}

func TestSeatbeltControlWriteFailureReapsStartedSupervisorButKeepsSessionQuarantined(t *testing.T) {
	session, err := CreateSession(filepath.Join(t.TempDir(), "sessions"))
	if err != nil {
		t.Fatal(err)
	}
	parent, peer := seatbeltTestSocketPair(t)
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	process := newSeatbeltLifecycleTestProcess(exec.Command("/usr/bin/true"))
	process.supervised = true
	process.control = parent
	process.challenge = bytes.Repeat([]byte{0xc4}, seatbeltChallengeSize)
	retained, err := RetainSessionUntilProcessDone(process, session)
	if err != nil {
		t.Fatal(err)
	}
	startErr := retained.Start()
	assertSandboxCategory(t, startErr, SandboxProcessStartFailed)
	if err := session.Remove(); err != nil {
		t.Fatal(err)
	}
	reaped := make(chan struct{})
	go func() {
		process.awaitRetainedLeader()
		close(reaped)
	}()
	select {
	case <-reaped:
	case <-time.After(time.Second):
		t.Fatal("started supervisor was not reaped after control write failure")
	}
	if process.command.ProcessState == nil {
		t.Fatal("started supervisor lacks a reaped process state")
	}
	select {
	case <-retained.(ProcessCleanup).CleanupDone():
		t.Fatal("control write failure released the cleanup quarantine")
	default:
	}
	if _, err := os.Stat(session.RootDir); err != nil {
		t.Fatalf("quarantined control-write failure released Session: %v", err)
	}
}

func TestSeatbeltCleanupProofTimeoutFailsClosed(t *testing.T) {
	parent, peer := seatbeltTestSocketPair(t)
	process := newSeatbeltLifecycleTestProcess(exec.Command("/usr/bin/true"))
	process.supervised = true
	process.control = parent
	process.challenge = bytes.Repeat([]byte{0xa5}, seatbeltChallengeSize)
	timedOut := make(chan time.Time)
	close(timedOut)
	process.proofTimeout = func() <-chan time.Time { return timedOut }
	releasePeer := make(chan struct{})
	go func() {
		challenge := make([]byte, seatbeltChallengeSize)
		_, _ = io.ReadFull(peer, challenge)
		<-releasePeer
	}()
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	err := process.Wait()
	close(releasePeer)
	assertSandboxCategory(t, err, SandboxProcessWaitFailed)
	select {
	case <-process.CleanupDone():
		t.Fatal("cleanup proof timeout released quarantine")
	default:
	}
}

func TestSeatbeltEnumerationFailureAndNonconvergenceNeverProveCleanup(t *testing.T) {
	enumerationFailure := seatbeltTestEnumerator{allErr: errors.New("injected enumeration failure")}
	if err := settleSeatbeltInstance(enumerationFailure, newSeatbeltIdentityLedger(), os.Getpid(), 0, time.Now().Add(time.Second)); err == nil {
		t.Fatal("enumeration failure unexpectedly proved cleanup")
	}
	nonconverging := seatbeltTestEnumerator{}
	if err := settleSeatbeltInstance(nonconverging, newSeatbeltIdentityLedger(), os.Getpid(), 0, time.Now().Add(-time.Millisecond)); err == nil {
		t.Fatal("expired convergence deadline unexpectedly proved cleanup")
	}
}

func TestSeatbeltCredentialAmbiguityFailsClosed(t *testing.T) {
	pid := os.Getpid()
	info := seatbeltBSDInfo{
		PID: uint32(pid), UID: uint32(os.Geteuid() + 1), RUID: uint32(os.Geteuid() + 1),
		SVUID: uint32(os.Geteuid() + 1), GID: uint32(os.Getegid()),
		RGID: uint32(os.Getegid()), SVGID: uint32(os.Getegid()),
		StartSecond: 1, StartMicrosecond: 2,
	}
	enumerator := seatbeltTestEnumerator{pids: []int{pid}, infos: map[int]seatbeltBSDInfo{pid: info}}
	if err := recordSeatbeltTargets(enumerator, -1, newSeatbeltIdentityLedger()); err == nil {
		t.Fatal("changed target credentials unexpectedly remained eligible for cleanup proof")
	}
}

func TestSeatbeltTargetCannotInheritOrSpoofControlDescriptor(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	request.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", "check-extra-descriptors"}
	var output bytes.Buffer
	request.terminal = Terminal{Output: &output, ErrorOutput: &output}
	process, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatalf("descriptor probe failed: %v; output=%q", err, output.String())
	}
	if got := strings.TrimSpace(output.String()); got != "sealed" {
		t.Fatalf("descriptor probe = %q, want sealed", got)
	}
}

func TestSeatbeltHelperAttackKeepsCleanupQuarantined(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	session, err := CreateSession(request.sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	request.sessionDirectory = session.RootDir
	request.sessionHome = filepath.Join(session.RootDir, "home")
	request.temporaryDirectory = filepath.Join(session.RootDir, "tmp")
	for _, directory := range []string{request.sessionHome, request.temporaryDirectory} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	request.environment, err = buildProcessEnvironment(request.sessionHome, request.temporaryDirectory, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", "kill-supervisor"}
	process, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	retained, err := RetainSessionUntilProcessDone(process, session)
	if err != nil {
		t.Fatal(err)
	}
	if err := retained.Start(); err != nil {
		t.Fatal(err)
	}
	if err := session.Remove(); err != nil {
		t.Fatal(err)
	}
	if err := retained.Wait(); err == nil {
		t.Fatal("supervisor attack unexpectedly produced cleanup proof")
	}
	select {
	case <-retained.(ProcessCleanup).CleanupDone():
		t.Fatal("supervisor death released cleanup quarantine")
	default:
	}
	if _, err := os.Stat(session.RootDir); err != nil {
		t.Fatalf("quarantined Session was released after supervisor death: %v", err)
	}
}

func TestSeatbeltPreservesNormalAndSignalExitStatus(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	for _, test := range []struct {
		name        string
		mode        string
		exitCode    int
		deathSignal syscall.Signal
	}{
		{name: "exit", mode: "exit-code", exitCode: 37},
		{name: "signal", mode: "self-signal", deathSignal: syscall.SIGTERM},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := seatbeltTestRequest(t)
			request.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", test.mode}
			process, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if err := process.Start(); err != nil {
				t.Fatal(err)
			}
			waitErr := process.Wait()
			var exitError *exec.ExitError
			if !errors.As(waitErr, &exitError) {
				t.Fatalf("Wait error = %v, want exit status", waitErr)
			}
			status := exitError.Sys().(syscall.WaitStatus)
			if test.deathSignal != 0 && (!status.Signaled() || status.Signal() != test.deathSignal) {
				t.Fatalf("signal status = %v, want %v", status, test.deathSignal)
			}
			if test.deathSignal == 0 && (!status.Exited() || status.ExitStatus() != test.exitCode) {
				t.Fatalf("exit status = %v, want %d", status, test.exitCode)
			}
			select {
			case <-process.(ProcessCleanup).CleanupDone():
			default:
				t.Fatal("valid cleanup proof did not complete cleanup")
			}
		})
	}
}

func TestSeatbeltForwardsOnlyRequestedSignalToTarget(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	marker := filepath.Join(request.workspace, "signal-received")
	ready := filepath.Join(request.workspace, "signal-ready")
	request.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", "await-signal", marker, ready}
	process, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	seatbeltWaitForMarker(t, ready)
	if err := process.Signal(syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	if contents, err := os.ReadFile(marker); err != nil || string(contents) != "user defined signal 1" {
		t.Fatalf("forwarded signal marker = %q, %v", contents, err)
	}
}

func TestSeatbeltCancellationStillRequiresCleanupProof(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	ctx, cancel := context.WithCancel(context.Background())
	request := seatbeltTestRequest(t)
	request.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", "sleep"}
	process, err := newSeatbeltBackend(seatbeltExecutable).prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := process.Wait(); err == nil {
		t.Fatal("canceled target unexpectedly reported success")
	}
	select {
	case <-process.(ProcessCleanup).CleanupDone():
	case <-time.After(time.Second):
		t.Fatal("canceled target did not produce cleanup proof")
	}
}

func TestSeatbeltCleanupDoesNotCrossConcurrentIdenticalInstances(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	firstRequest := seatbeltTestRequest(t)
	secondRequest := seatbeltTestRequest(t)
	firstMarker := filepath.Join(firstRequest.workspace, "first-signal")
	secondMarker := filepath.Join(secondRequest.workspace, "second-signal")
	firstReady := filepath.Join(firstRequest.workspace, "first-signal-ready")
	secondReady := filepath.Join(secondRequest.workspace, "second-signal-ready")
	firstRequest.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", "await-signal", firstMarker, firstReady}
	secondRequest.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", "await-signal", secondMarker, secondReady}
	first, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), secondRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	if err := second.Start(); err != nil {
		t.Fatal(err)
	}
	seatbeltWaitForMarker(t, firstReady)
	seatbeltWaitForMarker(t, secondReady)
	if err := first.Signal(syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	if err := first.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(secondMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first cleanup affected the concurrent instance: %v", err)
	}
	if err := second.Signal(syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	if err := second.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestSeatbeltCleanupDoesNotSignalUnrelatedProcess(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	marker := filepath.Join(t.TempDir(), "outside-signal")
	ready := filepath.Join(t.TempDir(), "outside-signal-ready")
	unrelated := exec.Command(os.Args[0], "-test.run=TestSeatbeltHelperProcess", "--", "await-signal", marker, ready)
	unrelated.Env = os.Environ()
	if err := unrelated.Start(); err != nil {
		t.Fatal(err)
	}
	seatbeltWaitForMarker(t, ready)
	t.Cleanup(func() {
		_ = unrelated.Process.Kill()
		_ = unrelated.Wait()
	})

	request := seatbeltTestRequest(t)
	request.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", "exit-code-zero"}
	process, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := unrelated.Process.Signal(syscall.SIGUSR1); err != nil {
		t.Fatal(err)
	}
	if err := unrelated.Wait(); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(marker)
	if err != nil || string(contents) != syscall.SIGUSR1.String() {
		t.Fatalf("unrelated process marker = %q, %v", contents, err)
	}
}

func TestSeatbeltConvergesAcrossForkingAndZombieDescendants(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	for _, mode := range []string{"fork-churn-parent", "zombie-parent"} {
		t.Run(mode, func(t *testing.T) {
			request := seatbeltTestRequest(t)
			ready := filepath.Join(request.workspace, mode+"-ready")
			marker := filepath.Join(request.workspace, mode+"-survived")
			request.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", mode, ready, marker}
			process, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if err := process.Start(); err != nil {
				t.Fatal(err)
			}
			if err := process.Wait(); err != nil {
				t.Fatal(err)
			}
			time.Sleep(500 * time.Millisecond)
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("descendant survived converged cleanup: %v", err)
			}
		})
	}
}

func TestSeatbeltWaitSettlesOutlivingDescendantsBeforeSessionRemoval(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	root := filepath.Dir(filepath.Dir(request.workspace))
	secret := filepath.Join(root, "secret")
	if err := os.WriteFile(secret, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(request.workspace, "descendant-survived")
	request.arguments = []string{
		"-test.run=TestSeatbeltHelperProcess", "--", "outliving-parent", secret, marker,
	}
	process, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatalf("top-level target failed: %v", err)
	}
	if err := os.RemoveAll(request.sessionDirectory); err != nil {
		t.Fatalf("remove settled Session: %v", err)
	}
	time.Sleep(750 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("descendant wrote after Wait returned and Session was removed: %v", err)
	}
}

func TestSeatbeltCancellationReportsProcessGroupFailure(t *testing.T) {
	process := newSeatbeltLifecycleTestProcess(exec.Command("/bin/sleep", "30"))
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-process.command.Process.Pid, syscall.SIGKILL)
		_ = process.command.Wait()
	})
	process.killProcessGroup = func(processGroup int, signal syscall.Signal) error {
		if processGroup != process.command.Process.Pid || signal != syscall.SIGKILL {
			t.Fatalf("process-group signal = (%d, %v), want (%d, SIGKILL)", processGroup, signal, process.command.Process.Pid)
		}
		return syscall.EPERM
	}

	err := process.cancel()
	if !errors.Is(err, syscall.EPERM) {
		t.Fatalf("cancel error = %v, want EPERM", err)
	}
}

func TestSeatbeltWaitBoundsUnresolvedCancellationAndRestoresTerminal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	waitRelease := make(chan struct{})
	process := &seatbeltProcess{
		ctx: ctx, processGroup: 42, cleanupDone: make(chan struct{}),
		waitCommand: func() error {
			<-waitRelease
			return nil
		},
	}
	timeout := make(chan time.Time)
	close(timeout)
	process.cancellationTimeout = func() <-chan time.Time { return timeout }
	terminal, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	process.terminal = terminal
	process.foregroundGroup = syscall.Getpgrp()
	restored := false
	process.setForegroundProcessGroup = func(*os.File, int) error {
		restored = true
		return nil
	}
	quarantined := false
	process.cleanupQuarantine = func(got *seatbeltProcess) {
		if got != process {
			t.Fatalf("quarantined process = %p, want %p", got, process)
		}
		quarantined = true
	}

	waitErr := process.Wait()
	close(waitRelease)
	if !errors.Is(waitErr, context.Canceled) || !errors.Is(waitErr, context.DeadlineExceeded) {
		t.Fatalf("Wait error = %v, want canceled bounded wait", waitErr)
	}
	if !quarantined {
		t.Fatal("unresolved canceled leader was not transferred to quarantine")
	}
	if !restored {
		t.Fatal("bounded cancellation did not restore the foreground terminal")
	}
	select {
	case <-process.CleanupDone():
		t.Fatal("unresolved canceled leader incorrectly reported cleanup completion")
	default:
	}
}

func TestSeatbeltWaitBoundsPersistentPermissionFailureAndRestoresTerminal(t *testing.T) {
	process := newSeatbeltLifecycleTestProcess(exec.Command("/usr/bin/true"))
	terminal, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	process.terminal = terminal
	process.foregroundGroup = syscall.Getpgrp()
	const attempts = 3
	process.settlementAttempts = attempts
	var killCalls int
	process.killProcessGroup = func(int, syscall.Signal) error {
		killCalls++
		return syscall.EPERM
	}
	process.cleanupRetry = func() {}
	restored := false
	process.setForegroundProcessGroup = func(got *os.File, processGroup int) error {
		if got != terminal || processGroup != syscall.Getpgrp() {
			t.Fatalf("foreground restoration = (%p, %d), want (%p, %d)", got, processGroup, terminal, syscall.Getpgrp())
		}
		restored = true
		return nil
	}
	quarantined := false
	process.cleanupQuarantine = func(got *seatbeltProcess) {
		if got != process {
			t.Fatalf("quarantined process = %p, want %p", got, process)
		}
		quarantined = true
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}

	err = process.Wait()
	if !errors.Is(err, syscall.EPERM) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait error = %v, want EPERM and bounded-cleanup deadline", err)
	}
	if killCalls != attempts {
		t.Fatalf("process-group kill calls = %d, want %d", killCalls, attempts)
	}
	if !quarantined {
		t.Fatal("Wait did not quarantine the unresolved process group")
	}
	if !restored {
		t.Fatal("Wait did not restore the foreground terminal after cleanup failure")
	}
	select {
	case <-process.CleanupDone():
		t.Fatal("persistent EPERM incorrectly reported cleanup completion")
	default:
	}
}

func TestSeatbeltQuarantineCompletionPreservesSessionLease(t *testing.T) {
	session, err := CreateSession(filepath.Join(t.TempDir(), "sessions"))
	if err != nil {
		t.Fatal(err)
	}
	process := newSeatbeltLifecycleTestProcess(exec.Command("/usr/bin/true"))
	process.settlementAttempts = 1
	process.cleanupRetry = func() {}
	var cleanupAllowed atomic.Bool
	process.killProcessGroup = func(int, syscall.Signal) error {
		if cleanupAllowed.Load() {
			return syscall.ESRCH
		}
		return syscall.EPERM
	}
	retryEntered := make(chan struct{})
	retryRelease := make(chan struct{})
	var retryOnce sync.Once
	process.quarantineRetry = func() {
		retryOnce.Do(func() { close(retryEntered) })
		<-retryRelease
	}
	retained, err := RetainSessionUntilProcessDone(process, session)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := retained.(ProcessCleanup); !ok {
		t.Fatal("retained Seatbelt process does not expose ProcessCleanup")
	}
	if err := retained.Start(); err != nil {
		t.Fatal(err)
	}
	if err := session.Remove(); err != nil {
		t.Fatal(err)
	}
	waitErr := retained.Wait()
	if !errors.Is(waitErr, syscall.EPERM) || !errors.Is(waitErr, context.DeadlineExceeded) {
		t.Fatalf("Wait error = %v, want quarantined EPERM deadline", waitErr)
	}
	select {
	case <-retryEntered:
	case <-time.After(time.Second):
		t.Fatal("cleanup quarantine did not begin retrying")
	}
	if _, err := os.Stat(session.RootDir); err != nil {
		t.Fatalf("Session lease released before quarantined cleanup completed: %v", err)
	}

	cleanupAllowed.Store(true)
	close(retryRelease)
	select {
	case <-retained.(ProcessCleanup).CleanupDone():
	case <-time.After(time.Second):
		t.Fatal("eventually successful cleanup did not complete quarantine")
	}
	deadline := time.Now().Add(time.Second)
	for {
		_, statErr := os.Stat(session.RootDir)
		if errors.Is(statErr, os.ErrNotExist) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Session remained after cleanup completion: %v", statErr)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSeatbeltStartFailureRestoresForegroundTerminal(t *testing.T) {
	process := newSeatbeltLifecycleTestProcess(exec.Command(filepath.Join(t.TempDir(), "missing")))
	terminal, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.Close()
	process.terminal = terminal
	process.foregroundGroup = syscall.Getpgrp()
	restored := false
	process.setForegroundProcessGroup = func(*os.File, int) error {
		restored = true
		return nil
	}

	if err := process.Start(); err == nil {
		t.Fatal("missing executable unexpectedly started")
	}
	if !restored {
		t.Fatal("Start failure did not restore the foreground terminal")
	}
	select {
	case <-process.CleanupDone():
	default:
		t.Fatal("Start failure did not complete cleanup")
	}
}

func TestSeatbeltContainsFilesystemNetworkEnvironmentAndDescendants(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	root := filepath.Dir(filepath.Dir(request.workspace))
	hostHome := filepath.Join(root, "home")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(hostHome, "secret")
	if err := os.WriteFile(secret, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	readable := filepath.Join(request.workspace, "readable")
	if err := os.WriteFile(readable, []byte("workspace"), 0o600); err != nil {
		t.Fatal(err)
	}
	sessionReadable := filepath.Join(request.sessionDirectory, "readable")
	if err := os.WriteFile(sessionReadable, []byte("session"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeInput := filepath.Join(root, "runtime.pem")
	if err := os.WriteFile(runtimeInput, []byte("runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	request.runtimeInputs = []string{runtimeInput}
	readEscape := filepath.Join(request.workspace, "read-escape")
	writeEscape := filepath.Join(request.workspace, "write-escape")
	if err := os.Symlink(secret, readEscape); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, writeEscape); err != nil {
		t.Fatal(err)
	}

	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go acceptSeatbeltTestConnection(tcp)
	unixPath := filepath.Join(hostHome, "agent.sock")
	unixListener, err := net.Listen("unix", unixPath)
	if err != nil {
		t.Fatal(err)
	}
	defer unixListener.Close()
	go acceptSeatbeltTestConnection(unixListener)

	request.arguments = []string{
		"-test.run=TestSeatbeltHelperProcess", "--", "containment",
		request.workspace, request.sessionDirectory, secret, outside,
		readable, sessionReadable, runtimeInput, readEscape, writeEscape,
		tcp.Addr().String(), unixPath,
		"/private/var/run/mDNSResponder",
	}
	var output bytes.Buffer
	request.terminal = Terminal{Output: &output, ErrorOutput: &output}
	backend := newSeatbeltBackend(seatbeltExecutable)
	process, err := backend.prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatalf("contained helper failed: %v; output=%q", err, output.String())
	}
	if got := strings.TrimSpace(output.String()); got != "contained" {
		t.Fatalf("contained helper output = %q", got)
	}
}

func TestSeatbeltPreservesRawTerminalDescriptors(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	request.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", "raw-terminal"}
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	settings, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TIOCGETA)
	if err != nil {
		t.Fatal(err)
	}
	settings.Lflag &^= unix.ICANON | unix.ECHO
	if err := unix.IoctlSetTermios(int(terminal.Fd()), unix.TIOCSETA, settings); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	request.terminal = Terminal{Input: terminal, Output: &output, ErrorOutput: &output}
	process, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(output.String()); got != "raw" {
		t.Fatalf("raw terminal output = %q", got)
	}
}

func TestSeatbeltPreservesTerminalResize(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	request.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", "terminal-size"}
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	if err := pty.Setsize(master, &pty.Winsize{Rows: 43, Cols: 117}); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	request.terminal = Terminal{Input: terminal, Output: &output, ErrorOutput: &output}
	process, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(output.String()); got != "43x117" {
		t.Fatalf("terminal size = %q, want 43x117", got)
	}
}

func TestSeatbeltHelperProcess(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		return
	}
	arguments := os.Args[separator+1:]
	switch arguments[0] {
	case "mark":
		if err := os.WriteFile(arguments[1], []byte("started"), 0o600); err != nil {
			os.Exit(71)
		}
		os.Exit(0)
	case "containment":
		runSeatbeltContainmentHelper(arguments[1:])
	case "grandchild":
		if _, err := os.ReadFile(arguments[1]); !isSeatbeltPermission(err) {
			os.Exit(72)
		}
		os.Exit(0)
	case "child":
		if _, err := os.ReadFile(arguments[1]); !isSeatbeltPermission(err) {
			os.Exit(84)
		}
		grandchild := exec.Command(os.Args[0], "-test.run=TestSeatbeltHelperProcess", "--", "grandchild", arguments[1])
		grandchild.Env = os.Environ()
		if err := grandchild.Run(); err != nil {
			os.Exit(85)
		}
		os.Exit(0)
	case "raw-terminal":
		settings, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TIOCGETA)
		if err != nil || settings.Lflag&unix.ICANON != 0 || settings.Lflag&unix.ECHO != 0 {
			os.Exit(83)
		}
		fmt.Fprintln(os.Stdout, "raw")
		os.Exit(0)
	case "terminal-size":
		size, err := pty.GetsizeFull(os.Stdin)
		if err != nil {
			os.Exit(110)
		}
		fmt.Fprintf(os.Stdout, "%dx%d\n", size.Rows, size.Cols)
		os.Exit(0)
	case "outliving-parent":
		child := exec.Command(os.Args[0], "-test.run=TestSeatbeltHelperProcess", "--", "delayed-descendant", arguments[1], arguments[2])
		child.Env = os.Environ()
		child.Stdin = nil
		child.Stdout = nil
		child.Stderr = nil
		if err := child.Start(); err != nil {
			os.Exit(87)
		}
		os.Exit(0)
	case "process-group-escape-parent":
		child := exec.Command(os.Args[0], "-test.run=TestSeatbeltHelperProcess", "--", "process-group-escape-child", arguments[1], arguments[2])
		child.Env = os.Environ()
		child.Stdin = nil
		child.Stdout = nil
		child.Stderr = nil
		if err := child.Start(); err != nil {
			os.Exit(90)
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			if _, err := os.Stat(arguments[1]); err == nil {
				os.Exit(0)
			}
			if time.Now().After(deadline) {
				os.Exit(91)
			}
			time.Sleep(time.Millisecond)
		}
	case "process-group-escape-child":
		result := "escaped"
		if _, err := unix.Setsid(); err != nil {
			if !isSeatbeltPermission(err) {
				os.Exit(92)
			}
			result = "denied"
		}
		if err := os.WriteFile(arguments[1], []byte(result), 0o600); err != nil {
			os.Exit(93)
		}
		time.Sleep(300 * time.Millisecond)
		if err := os.WriteFile(arguments[2], []byte("alive"), 0o600); err != nil {
			os.Exit(94)
		}
		os.Exit(0)
	case "resolve-hostname":
		addresses, err := net.DefaultResolver.LookupHost(context.Background(), arguments[1])
		if err != nil || len(addresses) == 0 {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(95)
		}
		fmt.Fprintln(os.Stdout, "resolved")
		os.Exit(0)
	case "copy-system-trust-settings":
		if err := seatbeltCopySystemTrustSettings(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(111)
		}
		os.Exit(0)
	case "check-extra-descriptors":
		for fd := 3; fd < 64; fd++ {
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
				fmt.Fprintf(os.Stdout, "leaked-fd-%d\n", fd)
				os.Exit(96)
			}
		}
		fmt.Fprintln(os.Stdout, "sealed")
		os.Exit(0)
	case "kill-supervisor":
		if err := syscall.Kill(os.Getppid(), syscall.SIGKILL); err != nil {
			os.Exit(97)
		}
		time.Sleep(20 * time.Millisecond)
		os.Exit(0)
	case "exit-code":
		os.Exit(37)
	case "exit-code-zero":
		os.Exit(0)
	case "self-signal":
		signal.Reset(syscall.SIGTERM)
		if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
			os.Exit(98)
		}
		time.Sleep(time.Second)
		os.Exit(99)
	case "await-signal":
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGUSR1)
		if len(arguments) > 2 {
			if err := os.WriteFile(arguments[2], []byte("ready"), 0o600); err != nil {
				os.Exit(100)
			}
		}
		received := <-signals
		signal.Stop(signals)
		if err := os.WriteFile(arguments[1], []byte(received.String()), 0o600); err != nil {
			os.Exit(101)
		}
		os.Exit(0)
	case "sleep":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	case "fork-churn-parent":
		child := exec.Command(os.Args[0], "-test.run=TestSeatbeltHelperProcess", "--", "fork-churn-child", arguments[1], arguments[2])
		child.Env = os.Environ()
		child.Stdin, child.Stdout, child.Stderr = nil, nil, nil
		if err := child.Start(); err != nil {
			os.Exit(101)
		}
		waitForSeatbeltHelperMarker(arguments[1], 102)
		os.Exit(0)
	case "fork-churn-child":
		if err := os.WriteFile(arguments[1], []byte("ready"), 0o600); err != nil {
			os.Exit(103)
		}
		deadline := time.Now().Add(350 * time.Millisecond)
		for time.Now().Before(deadline) {
			child := exec.Command("/usr/bin/true")
			child.Env = os.Environ()
			_ = child.Run()
		}
		if err := os.WriteFile(arguments[2], []byte("alive"), 0o600); err != nil {
			os.Exit(104)
		}
		os.Exit(0)
	case "zombie-parent":
		child := exec.Command(os.Args[0], "-test.run=TestSeatbeltHelperProcess", "--", "zombie-holder", arguments[1], arguments[2])
		child.Env = os.Environ()
		child.Stdin, child.Stdout, child.Stderr = nil, nil, nil
		if err := child.Start(); err != nil {
			os.Exit(105)
		}
		waitForSeatbeltHelperMarker(arguments[1], 106)
		os.Exit(0)
	case "zombie-holder":
		zombie := exec.Command(os.Args[0], "-test.run=TestSeatbeltHelperProcess", "--", "exit-code-zero")
		zombie.Env = os.Environ()
		zombie.Stdin, zombie.Stdout, zombie.Stderr = nil, nil, nil
		if err := zombie.Start(); err != nil {
			os.Exit(107)
		}
		time.Sleep(40 * time.Millisecond)
		if err := os.WriteFile(arguments[1], []byte("ready"), 0o600); err != nil {
			os.Exit(108)
		}
		time.Sleep(350 * time.Millisecond)
		if err := os.WriteFile(arguments[2], []byte("alive"), 0o600); err != nil {
			os.Exit(109)
		}
		os.Exit(0)
	case "delayed-descendant":
		time.Sleep(400 * time.Millisecond)
		_, readErr := os.ReadFile(arguments[1])
		if !isSeatbeltPermission(readErr) {
			os.Exit(88)
		}
		if err := os.WriteFile(arguments[2], []byte("alive"), 0o600); err != nil {
			os.Exit(89)
		}
		os.Exit(0)
	}
}

func runSeatbeltContainmentHelper(arguments []string) {
	if len(arguments) != 12 {
		os.Exit(73)
	}
	workspace, session, secret, outside := arguments[0], arguments[1], arguments[2], arguments[3]
	readEscape, writeEscape := arguments[7], arguments[8]
	for _, readable := range []string{arguments[4], arguments[5], arguments[6]} {
		if _, err := os.ReadFile(readable); err != nil {
			os.Exit(74)
		}
	}
	for _, path := range []string{filepath.Join(workspace, "created"), filepath.Join(session, "created")} {
		if err := os.WriteFile(path, []byte("allowed"), 0o600); err != nil {
			os.Exit(75)
		}
	}
	for _, path := range []string{secret, readEscape} {
		if _, err := os.ReadFile(path); !isSeatbeltPermission(err) {
			os.Exit(76)
		}
	}
	for _, path := range []string{filepath.Join(outside, "created"), filepath.Join(writeEscape, "created")} {
		if err := os.WriteFile(path, []byte("denied"), 0o600); !isSeatbeltPermission(err) {
			os.Exit(77)
		}
	}
	if os.Getenv("AWS_SECRET_ACCESS_KEY") != "" || os.Getenv("SSH_AUTH_SOCK") != "" {
		os.Exit(78)
	}
	tcp, err := net.DialTimeout("tcp4", arguments[9], 2*time.Second)
	if err != nil {
		os.Exit(79)
	}
	_ = tcp.Close()
	unixConnection, err := net.DialTimeout("unix", arguments[10], 300*time.Millisecond)
	if err == nil {
		_ = unixConnection.Close()
		os.Exit(80)
	}
	if !isSeatbeltPermission(err) {
		os.Exit(86)
	}
	resolver, err := net.DialTimeout("unix", arguments[11], 300*time.Millisecond)
	if err != nil {
		os.Exit(82)
	}
	_ = resolver.Close()
	child := exec.Command(os.Args[0], "-test.run=TestSeatbeltHelperProcess", "--", "child", secret)
	child.Env = os.Environ()
	if err := child.Run(); err != nil {
		os.Exit(81)
	}
	fmt.Fprintln(os.Stdout, "contained")
	os.Exit(0)
}

func isSeatbeltPermission(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

func seatbeltCopySystemTrustSettings() error {
	security, err := purego.Dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return err
	}
	coreFoundation, err := purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_LOCAL)
	if err != nil {
		return err
	}
	var copyCertificates func(uint32, *unsafe.Pointer) int32
	var arrayCount func(unsafe.Pointer) int
	var release func(unsafe.Pointer)
	purego.RegisterLibFunc(&copyCertificates, security, "SecTrustSettingsCopyCertificates")
	purego.RegisterLibFunc(&arrayCount, coreFoundation, "CFArrayGetCount")
	purego.RegisterLibFunc(&release, coreFoundation, "CFRelease")
	var certificates unsafe.Pointer
	status := copyCertificates(2, &certificates) // kSecTrustSettingsDomainSystem
	if certificates != nil {
		defer release(certificates)
	}
	if status != 0 || certificates == nil {
		return fmt.Errorf("copy system trust settings: status=%d certificates=%t", status, certificates != nil)
	}
	if count := arrayCount(certificates); count <= 0 {
		return errors.New("copy system trust settings: no certificates")
	}
	return nil
}

func acceptSeatbeltTestConnection(listener net.Listener) {
	connection, err := listener.Accept()
	if err == nil {
		_ = connection.Close()
	}
}

func waitForSeatbeltHelperMarker(path string, exitCode int) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			os.Exit(exitCode)
		}
		time.Sleep(time.Millisecond)
	}
}

func seatbeltWaitForMarker(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for Seatbelt helper marker %q", path)
		}
		time.Sleep(time.Millisecond)
	}
}

func seatbeltTestExitStatus(t *testing.T, status int) error {
	t.Helper()
	command := exec.Command("/bin/sh", "-c", fmt.Sprintf("exit %d", status))
	err := command.Run()
	if err == nil {
		t.Fatalf("exit %d command unexpectedly succeeded", status)
	}
	return err
}

func seatbeltRequireSessionRemoved(t *testing.T, root string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		_, err := os.Stat(root)
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Session remained after authenticated cleanup: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
}

func seatbeltTestRequest(t *testing.T) validatedProcessRequest {
	t.Helper()
	root, err := os.MkdirTemp("/private/tmp", "acs-seatbelt-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	workspace := filepath.Join(root, "home", "workspace")
	session := filepath.Join(root, "sessions", "session-one")
	home := filepath.Join(session, "home")
	temporary := filepath.Join(session, "tmp")
	for _, directory := range []string{workspace, home, temporary} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := buildProcessEnvironment(home, temporary, []string{
		"TERM=xterm-256color", "AWS_SECRET_ACCESS_KEY=private", "SSH_AUTH_SOCK=/private/agent.sock",
	})
	if err != nil {
		t.Fatal(err)
	}
	return validatedProcessRequest{
		workspace: workspace, sessionsDirectory: filepath.Dir(session), sessionDirectory: session,
		sessionHome: home, temporaryDirectory: temporary, executable: executable,
		environment: environment,
	}
}

func newSeatbeltLifecycleTestProcess(command *exec.Cmd) *seatbeltProcess {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	process := &seatbeltProcess{command: command, cleanupDone: make(chan struct{})}
	return process
}

func seatbeltTestSocketPair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	descriptors, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	parent := os.NewFile(uintptr(descriptors[0]), "seatbelt-test-parent")
	peer := os.NewFile(uintptr(descriptors[1]), "seatbelt-test-peer")
	t.Cleanup(func() {
		_ = parent.Close()
		_ = peer.Close()
	})
	return parent, peer
}

type seatbeltTestEnumerator struct {
	allErr error
	pids   []int
	infos  map[int]seatbeltBSDInfo
}

func (enumerator seatbeltTestEnumerator) allPIDs() ([]int, error) {
	return enumerator.pids, enumerator.allErr
}

func (enumerator seatbeltTestEnumerator) info(pid int) (seatbeltBSDInfo, error) {
	if info, ok := enumerator.infos[pid]; ok {
		return info, nil
	}
	return seatbeltBSDInfo{}, errors.New("unexpected process inspection")
}
