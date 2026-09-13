//go:build darwin

package launch

import (
	"bufio"
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
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/alcimerio/ai-config-selector/internal/environmentresource"
	"github.com/creack/pty"
	"github.com/ebitengine/purego"
	"golang.org/x/sys/unix"
)

func TestSeatbeltWorkspaceWriteRuleFollowsResolvedAccess(t *testing.T) {
	base := validatedProcessRequest{workspace: "/private/tmp/workspace", sessionDirectory: "/private/tmp/session", executable: "/bin/zsh"}
	for _, test := range []struct {
		access WorkspaceAccess
		want   bool
	}{{WorkspaceAccessReadOnly, false}, {WorkspaceAccessReadWrite, true}} {
		request := base
		request.workspaceAccess = test.access
		policy, _, err := buildSeatbeltPolicy(request)
		if err != nil {
			t.Fatal(err)
		}
		start := strings.Index(policy, "; Writes are limited")
		end := strings.Index(policy[start:], "; Normal outbound")
		writeRules := policy[start : start+end]
		present := strings.Contains(writeRules, `(param "WORKSPACE")`)
		if present != test.want {
			t.Fatalf("access %q workspace write rule present=%v\n%s", test.access, present, writeRules)
		}
		if !strings.Contains(writeRules, `(param "SESSION")`) {
			t.Fatalf("access %q removed Session writes", test.access)
		}
	}
}

func TestSeatbeltPolicyIsDefaultDenyAndUsesParametersForValidatedPaths(t *testing.T) {
	request := validatedProcessRequest{
		workspace:                  `/private/tmp/workspace-\"quoted`,
		sessionDirectory:           "/private/tmp/session\nprivate",
		executable:                 "/private/tmp/bin/devin",
		runtimeInputs:              []string{"/private/tmp/runtime/input.pem"},
		runtimeProbePaths:          []string{"/private/etc/codex/requirements.toml"},
		runtimeProbeTraversalPaths: []string{"/etc"},
	}
	policy, definitions, err := buildSeatbeltPolicy(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"(version 1)", "(deny default)", `(param "WORKSPACE")`,
		`(param "SESSION")`, `(param "EXECUTABLE")`, `(param "RUNTIME_0")`,
		`(param "RUNTIME_PROBE_0")`,
		`(param "RUNTIME_PROBE_TRAVERSAL_0")`,
		`(param "EXECUTABLE_ANCESTOR_0")`, `(param "EXECUTABLE_ANCESTOR_1")`,
		`(param "EXECUTABLE_ANCESTOR_2")`, `(param "EXECUTABLE_ANCESTOR_3")`,
		`(param "SESSION_ANCESTOR_0")`, `(param "SESSION_ANCESTOR_1")`,
		`(param "SESSION_ANCESTOR_2")`,
		`(remote ip)`, `(literal "/private/var/run/mDNSResponder")`,
		`(literal "/var")`,
		`(literal "/private/var/select/sh")`,
		`(literal "/usr/share") (subpath "/usr/share/terminfo")`,
		`(literal "/dev/tty")`, `(target same-sandbox)`,
		"(allow file-read-metadata\n  (literal \"/dev/null\"))",
		"(allow mach-lookup\n  (global-name \"com.apple.SecurityServer\"))",
		"(allow mach-lookup\n  (global-name \"com.apple.trustd.agent\"))",
		"(allow file-read-metadata\n  (literal (param \"EXECUTABLE_ANCESTOR_0\"))\n  (literal (param \"EXECUTABLE_ANCESTOR_1\"))\n  (literal (param \"EXECUTABLE_ANCESTOR_2\"))\n  (literal (param \"EXECUTABLE_ANCESTOR_3\")))",
		"(allow file-read-metadata\n  (literal (param \"SESSION_ANCESTOR_0\"))\n  (literal (param \"SESSION_ANCESTOR_1\"))\n  (literal (param \"SESSION_ANCESTOR_2\")))",
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("policy omits %q", want)
		}
	}
	for _, forbidden := range []string{
		request.workspace, request.sessionDirectory, request.executable,
		request.runtimeInputs[0], "(allow file-read*)\n",
		request.runtimeProbePaths[0],
		request.runtimeProbeTraversalPaths[0],
		"(allow sysctl-read)\n", "(allow iokit", "(allow network*)",
		"(subpath (param \"EXECUTABLE_ANCESTOR_",
		"(subpath (param \"SESSION_ANCESTOR_",
		`(subpath "/usr/share")`,
		"com.apple.system.opendirectoryd.libinfo", "com.apple.SystemConfiguration.configd",
		"com.apple.notificationcenter", "com.apple.logd",
	} {
		if strings.Contains(policy, forbidden) {
			t.Errorf("policy contains forbidden text %q", forbidden)
		}
	}
	if got := strings.Count(policy, "(allow mach-lookup"); got != 2 {
		t.Fatalf("Mach lookup rule count = %d, want only SecurityServer and trustd.agent", got)
	}
	if got := strings.Count(policy, "(global-name"); got != 2 {
		t.Fatalf("Mach service count = %d, want only SecurityServer and trustd.agent", got)
	}
	wantDefinitions := []string{
		"-DWORKSPACE=" + request.workspace,
		"-DSESSION=" + request.sessionDirectory,
		"-DEXECUTABLE=" + request.executable,
		"-DEXECUTABLE_ANCESTOR_0=/private/tmp/bin",
		"-DEXECUTABLE_ANCESTOR_1=/private/tmp",
		"-DEXECUTABLE_ANCESTOR_2=/private",
		"-DEXECUTABLE_ANCESTOR_3=/",
		"-DSESSION_ANCESTOR_0=/private/tmp",
		"-DSESSION_ANCESTOR_1=/private",
		"-DSESSION_ANCESTOR_2=/",
		"-DRUNTIME_0=" + request.runtimeInputs[0],
		"-DRUNTIME_PROBE_0=" + request.runtimeProbePaths[0],
		"-DRUNTIME_PROBE_TRAVERSAL_0=" + request.runtimeProbeTraversalPaths[0],
	}
	if strings.Join(definitions, "\n") != strings.Join(wantDefinitions, "\n") {
		t.Fatalf("definitions = %#v, want %#v", definitions, wantDefinitions)
	}
	if strings.Contains(policy, `(subpath (param "RUNTIME_PROBE_0"))`) {
		t.Fatal("runtime probe path grants descendant reads")
	}
	if strings.Contains(policy, `(subpath (param "RUNTIME_PROBE_TRAVERSAL_0"))`) {
		t.Fatal("runtime probe traversal path grants descendant reads")
	}
}

func TestSeatbeltExecutableAncestors(t *testing.T) {
	for _, test := range []struct {
		name       string
		executable string
		want       []string
	}{
		{
			name:       "variable depth",
			executable: "/private/tmp/acs/nested/launch/target",
			want: []string{
				"/private/tmp/acs/nested/launch",
				"/private/tmp/acs/nested",
				"/private/tmp/acs",
				"/private/tmp",
				"/private",
				"/",
			},
		},
		{
			name:       "root executable",
			executable: "/target",
			want:       []string{"/"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := seatbeltPathAncestors(test.executable); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("seatbeltPathAncestors(%q) = %q, want %q", test.executable, got, test.want)
			}
		})
	}
}

func TestSeatbeltPolicyCompilesTypedProfilePathGrants(t *testing.T) {
	request := validatedProcessRequest{
		workspace: "/private/tmp/workspace", sessionDirectory: "/private/tmp/session", executable: "/usr/bin/true",
		filesystemGrants: []FilesystemGrant{
			{ID: "read-file", Access: PathAccessReadOnly, Type: PathTypeFile, path: "/Users/example/read.txt", effective: true},
			{ID: "write-file", Access: PathAccessReadWrite, Type: PathTypeFile, path: "/Users/example/write.txt", effective: true},
			{ID: "write-dir", Access: PathAccessReadWrite, Type: PathTypeDirectory, path: "/Users/example/cache", effective: true},
			{ID: "covered", Access: PathAccessReadOnly, Type: PathTypeDirectory, path: "/private/tmp/workspace/covered", effective: false},
		},
	}
	policy, definitions, err := buildSeatbeltPolicy(request)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(definitions, "\n")
	for _, want := range []string{"-DPROFILE_PATH_0=/Users/example/read.txt", "-DPROFILE_PATH_1=/Users/example/write.txt", "-DPROFILE_PATH_2=/Users/example/cache"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("definitions omit %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, "covered") {
		t.Fatalf("dominated grant compiled: %s", joined)
	}
	if !strings.Contains(policy, `(literal (param "PROFILE_PATH_0"))`) || strings.Contains(policy, `(subpath (param "PROFILE_PATH_0"))`) {
		t.Fatalf("exact read file boundary is wrong: %s", policy)
	}
	if !strings.Contains(policy, `(literal (param "PROFILE_PATH_1"))`) || strings.Contains(policy, `(subpath (param "PROFILE_PATH_1"))`) {
		t.Fatalf("exact writable file boundary is wrong: %s", policy)
	}
	if !strings.Contains(policy, `(literal (param "PROFILE_PATH_2")) (subpath (param "PROFILE_PATH_2"))`) {
		t.Fatalf("writable directory descendants are absent: %s", policy)
	}
}

func TestSeatbeltPolicyKeepsValidatedExecutableSymlinkTraversalNarrow(t *testing.T) {
	request := validatedProcessRequest{
		workspace: "/private/tmp/workspace", sessionDirectory: "/private/tmp/session", executable: "/usr/bin/true",
		executableGrants: []ExecutableGrant{{
			ID: "brew-tool", logicalPath: "/Users/example/homebrew/bin/tool", path: "/Users/example/cellar/tool/1.0/bin/tool",
		}},
	}
	policy, definitions, err := buildSeatbeltPolicy(request)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(definitions, "\n")
	for _, want := range []string{
		"-DPROFILE_EXECUTABLE_0=/Users/example/cellar/tool/1.0/bin/tool",
		"-DPROFILE_EXECUTABLE_0_LOGICAL=/Users/example/homebrew/bin/tool",
		"-DPROFILE_EXECUTABLE_0_LOGICAL_ANCESTOR_0=/Users/example/homebrew/bin",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("definitions omit %q: %s", want, joined)
		}
	}
	for _, parameter := range []string{"PROFILE_EXECUTABLE_0", "PROFILE_EXECUTABLE_0_LOGICAL"} {
		if !strings.Contains(policy, `(literal (param "`+parameter+`"))`) || strings.Contains(policy, `(subpath (param "`+parameter+`"))`) {
			t.Fatalf("executable %s visibility is not exact: %s", parameter, policy)
		}
	}
	if !strings.Contains(policy, `(literal (param "PROFILE_EXECUTABLE_0_LOGICAL_ANCESTOR_0"))`) || strings.Contains(policy, `(subpath (param "PROFILE_EXECUTABLE_0_LOGICAL_ANCESTOR_0"))`) {
		t.Fatalf("logical symlink ancestor metadata is not literal-only: %s", policy)
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

func TestSeatbeltCheckClassifiesARejectedCapabilityProbeWithoutItsOutput(t *testing.T) {
	backend := newSeatbeltBackend(seatbeltExecutable)
	backend.verify = func(context.Context, string) error {
		return errors.New("PRIVATE_SEATBELT_OUTPUT\n\x1b[31m")
	}
	err := backend.check(context.Background())
	assertSandboxCategory(t, err, SandboxVerificationFailed)
	for _, leaked := range []string{"PRIVATE_SEATBELT_OUTPUT", "\n", "\x1b"} {
		if strings.Contains(err.Error(), leaked) {
			t.Fatalf("Seatbelt verification failure leaked %q: %q", leaked, err)
		}
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
			assertSandboxCategory(t, err, SandboxPolicyRejected)
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

func TestSeatbeltPersistsAuthenticatedRecoveryProofAfterNativeCleanup(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	request.executable = "/usr/bin/true"
	request.recoveryProofChallenge = bytes.Repeat([]byte{0x8e}, RecoveryProofChallengeSize)
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
	if proven, err := VerifySessionCleanupProof(request.sessionDirectory, request.recoveryProofChallenge); err != nil || !proven {
		t.Fatalf("native recovery proof = (%v, %v)", proven, err)
	}
}

func TestSeatbeltClearsPreparedRecoveryProofBeforeTargetStarts(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	request.recoveryProofChallenge = bytes.Repeat([]byte{0x9d}, RecoveryProofChallengeSize)
	proofPath := filepath.Join(request.sessionDirectory, sessionCleanupProofFile)
	if err := PrepareSessionCleanupProof(request.sessionDirectory, request.recoveryProofChallenge); err != nil {
		t.Fatal(err)
	}
	request.arguments = []string{
		"-test.run=TestSeatbeltHelperProcess", "--", "proof-cleared", proofPath,
	}
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
	if proven, err := VerifySessionCleanupProof(request.sessionDirectory, request.recoveryProofChallenge); err != nil || !proven {
		t.Fatalf("settled recovery proof = (%v, %v)", proven, err)
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
	for _, test := range []struct {
		name, omitted string
	}{
		{name: "registered SecurityServer permits system trust settings"},
		{name: "omitting SecurityServer denies system trust settings", omitted: "com.apple.SecurityServer"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := seatbeltTestRequest(t)
			request.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", "copy-system-trust-settings"}
			var output bytes.Buffer
			request.terminal = Terminal{Output: &output, ErrorOutput: &output}
			backend := newSeatbeltBackend(seatbeltExecutable)
			if test.omitted != "" {
				backend.policy = func(request validatedProcessRequest) (string, []string, error) {
					policy, definitions, err := buildSeatbeltPolicy(request)
					if err != nil {
						return "", nil, err
					}
					rule := "(allow mach-lookup\n  (global-name \"" + test.omitted + "\"))"
					policy, err = seatbeltRemovePolicyTextExactlyOnce(policy, rule, "SecurityServer rule")
					return policy, definitions, err
				}
			}
			process, err := backend.prepare(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			if err := process.Start(); err != nil {
				t.Fatal(err)
			}
			err = process.Wait()
			if test.omitted == "" && err != nil {
				t.Fatalf("trust-settings read failed: %v; output=%q", err, output.String())
			}
			if test.omitted != "" && err == nil {
				t.Fatalf("trust-settings read succeeded without %s; output=%q", test.omitted, output.String())
			}
		})
	}
}

func TestSeatbeltExercisesRegisteredSysctlsAndLocalIPBind(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	request.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", "runtime-authority", request.sessionDirectory}
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
		t.Fatalf("registered sysctl/local-IP runtime authority failed: %v; output=%q", err, output.String())
	}
	if got := strings.TrimSpace(output.String()); got != "runtime-authority" {
		t.Fatalf("runtime authority output = %q", got)
	}
}

func TestSeatbeltProductionTLSRequiresOnlyExecutableMetadataAndTrustdAgent(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	t.Setenv(seatbeltParentCredentialSentinel, "parent-only")
	request, output := seatbeltProductionTLSRequest(t)

	tests := []struct {
		name    string
		omitted string
		want    string
	}{
		{
			name: "restored rules allow offline platform trust evaluation",
			want: "tls-ready",
		},
		{
			name:    "removing executable metadata blocks offline platform trust evaluation",
			omitted: "executable metadata",
			want:    "tls-policy-unavailable",
		},
		{
			name:    "removing trustd agent blocks offline platform trust evaluation",
			omitted: "trustd agent",
			want:    "local-system-trust-unavailable",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			output.Reset()
			err := seatbeltRunProductionTLS(seatbeltProductionTLSSandbox(t, test.omitted), request)
			if test.omitted == "" && err != nil {
				t.Fatalf("production platform trust evaluation failed: %v; output=%q", err, output.String())
			}
			if test.omitted != "" && err == nil {
				t.Fatalf("platform trust evaluation succeeded without %s; output=%q", test.omitted, output.String())
			}
			if got := output.String(); !strings.Contains(got, test.want) {
				t.Fatalf("platform trust evaluation output = %q, want semantic outcome %q", got, test.want)
			}
		})
	}
}

func TestSeatbeltProductionSessionPrefixRequiresOnlySessionMetadata(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request, output := seatbeltProductionTLSRequest(t)
	database := filepath.Join(request.SessionHome, ".codex", "state_5.sqlite")
	sibling := filepath.Join(request.SessionsDirectory, "sibling-secret")
	siblingWrite := filepath.Join(request.SessionsDirectory, "sibling-write")
	if err := os.WriteFile(sibling, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	request.Arguments = []string{
		"-test.run=TestSeatbeltHelperProcess", "--", "session-prefix-metadata",
		database, request.SessionsDirectory, sibling, siblingWrite,
	}

	for _, test := range []struct {
		name    string
		omitted string
		want    string
	}{
		{name: "restored Session metadata allows canonicalization without sibling access", want: "session-prefix-metadata"},
		{name: "removing Session metadata blocks canonicalization", omitted: "session metadata", want: "prefix-metadata-denied"},
	} {
		t.Run(test.name, func(t *testing.T) {
			output.Reset()
			err := seatbeltRunProductionTLS(seatbeltProductionTLSSandbox(t, test.omitted), request)
			if test.omitted == "" && err != nil {
				t.Fatalf("Session prefix validation failed: %v; output=%q", err, output.String())
			}
			if test.omitted != "" && err == nil {
				t.Fatalf("Session prefix validation succeeded without %s; output=%q", test.omitted, output.String())
			}
			if got := output.String(); !strings.Contains(got, test.want) {
				t.Fatalf("Session prefix validation output = %q, want semantic outcome %q", got, test.want)
			}
		})
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
			parent, peer := seatbeltTestDeadlineSocketPair(t)
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
				_, _ = seatbeltTestAcceptTargetStart(peer, challenge)
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

func TestSeatbeltSupervisorStartHandshake(t *testing.T) {
	control, peer := seatbeltTestDeadlineSocketPair(t)
	challenge := bytes.Repeat([]byte{0x2a}, seatbeltChallengeSize)
	process := &seatbeltProcess{control: control, challenge: challenge, startupDeadline: time.Second}
	result := make(chan error, 1)
	go func() {
		_, err := seatbeltTestAcceptTargetStart(peer, challenge)
		result <- err
	}()
	if err := process.startSupervisor(); err != nil {
		_ = control.Close()
		_ = peer.Close()
		select {
		case <-result:
		case <-time.After(time.Second):
		}
		t.Fatalf("start handshake: %T %v", err, err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		_ = control.Close()
		_ = peer.Close()
		t.Fatal("start handshake peer did not finish within its test bound")
	}
}

func TestSeatbeltSupervisorEnvironmentHandshakeAndBoundedStall(t *testing.T) {
	intent := environmentresource.Intent{ID: "token", Destination: "TOOL_TOKEN", Scope: "attached-process-tree", SourceKind: "secret-reference", Provider: "host-environment", Reference: "PRIVATE_SOURCE", Required: true, Classification: "secret"}
	lease, err := environmentresource.Resolve([]environmentresource.Intent{intent}, func(name string) (string, bool) {
		return "private-value", name == "PRIVATE_SOURCE"
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lease.Release)

	t.Run("frame then start", func(t *testing.T) {
		control, peer := net.Pipe()
		defer control.Close()
		defer peer.Close()
		challenge := bytes.Repeat([]byte{0x73}, seatbeltChallengeSize)
		process := &seatbeltProcess{control: control, challenge: challenge, environmentProjection: lease, startupDeadline: time.Second}
		result := make(chan error, 1)
		go func() {
			got := make([]byte, len(challenge))
			if _, err := io.ReadFull(peer, got); err != nil || !bytes.Equal(got, challenge) {
				result <- errors.New("invalid challenge")
				return
			}
			if _, err := peer.Write([]byte{seatbeltSupervisorReady}); err != nil {
				result <- err
				return
			}
			mode := []byte{0}
			if _, err := io.ReadFull(peer, mode); err != nil || mode[0] != seatbeltSupervisorEnvironmentFrame {
				result <- errors.New("missing environment frame mode")
				return
			}
			projection, err := environmentresource.ReadFrame(peer, []string{"HOME=/private/session/home"})
			if err != nil || !reflect.DeepEqual(projection, []string{"TOOL_TOKEN=private-value"}) {
				result <- errors.New("invalid environment projection")
				return
			}
			start := []byte{0}
			_, err = io.ReadFull(peer, start)
			if err == nil && start[0] != seatbeltSupervisorStart {
				err = errors.New("invalid start marker")
			}
			result <- err
		}()
		if err := process.startSupervisor(); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("ready then stalled reader", func(t *testing.T) {
		control, peer := net.Pipe()
		defer control.Close()
		defer peer.Close()
		process := &seatbeltProcess{control: control, challenge: bytes.Repeat([]byte{0x45}, seatbeltChallengeSize), environmentProjection: lease, startupDeadline: 25 * time.Millisecond}
		go func() {
			challenge := make([]byte, seatbeltChallengeSize)
			_, _ = io.ReadFull(peer, challenge)
			_, _ = peer.Write([]byte{seatbeltSupervisorReady})
		}()
		started := time.Now()
		if err := process.startSupervisor(); err == nil {
			t.Fatal("stalled environment transfer succeeded")
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("stalled transfer exceeded bound: %v", elapsed)
		}
	})
}

func TestSeatbeltSupervisorCancellationUnblocksStartupAndPreservesPostStartSignal(t *testing.T) {
	t.Run("startup", func(t *testing.T) {
		control, peer := net.Pipe()
		defer peer.Close()
		ready := make(chan struct{})
		killed := make(chan syscall.Signal, 1)
		process := &seatbeltProcess{control: control, challenge: bytes.Repeat([]byte{0x32}, seatbeltChallengeSize), processGroup: 731, supervised: true, startupDeadline: 5 * time.Second, killProcessGroup: func(_ int, signal syscall.Signal) error { killed <- signal; return nil }}
		go func() {
			challenge := make([]byte, seatbeltChallengeSize)
			_, _ = io.ReadFull(peer, challenge)
			_, _ = peer.Write([]byte{seatbeltSupervisorReady})
			close(ready)
		}()
		result := make(chan error, 1)
		go func() { result <- process.startSupervisor() }()
		select {
		case <-ready:
		case err := <-result:
			t.Fatalf("startup environment rendezvous ended before READY: %v", err)
		case <-time.After(time.Second):
			process.closeControl()
			select {
			case <-result:
			case <-time.After(time.Second):
			}
			t.Fatal("startup environment rendezvous did not reach READY within its test bound")
		}
		canceledAt := time.Now()
		cancelResult := make(chan error, 1)
		go func() { cancelResult <- process.cancel() }()
		select {
		case err := <-cancelResult:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			process.closeControl()
			select {
			case <-cancelResult:
			case <-time.After(time.Second):
			}
			t.Fatal("startup cancellation itself exceeded its test bound")
		}
		select {
		case err := <-result:
			if err == nil {
				t.Fatal("canceled startup returned success")
			}
			if elapsed := time.Since(canceledAt); elapsed > time.Second {
				t.Fatalf("canceled startup waited for deadline: %v", elapsed)
			}
		case <-time.After(time.Second):
			t.Fatal("cancellation did not unblock startup transfer")
		}
		select {
		case signal := <-killed:
			if signal != syscall.SIGKILL {
				t.Fatalf("startup cancellation signal = %v", signal)
			}
		case <-time.After(time.Second):
			t.Fatal("startup cancellation did not reach the retained process group")
		}
	})

	t.Run("post start", func(t *testing.T) {
		control, peer := net.Pipe()
		defer control.Close()
		defer peer.Close()
		process := &seatbeltProcess{control: control, processGroup: 811, supervised: true, killProcessGroup: func(int, syscall.Signal) error { t.Fatal("post-start cancellation bypassed supervisor"); return nil }}
		process.supervisorStarted.Store(true)
		packet := make(chan []byte, 1)
		go func() {
			value := make([]byte, 2)
			_, _ = io.ReadFull(peer, value)
			packet <- value
		}()
		cancelResult := make(chan error, 1)
		go func() { cancelResult <- process.cancel() }()
		select {
		case err := <-cancelResult:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			process.closeControl()
			select {
			case <-cancelResult:
			case <-time.After(time.Second):
			}
			t.Fatal("post-start cancellation itself exceeded its test bound")
		}
		select {
		case got := <-packet:
			if !bytes.Equal(got, []byte{'S', byte(syscall.SIGKILL)}) {
				t.Fatalf("post-start signal packet = %v", got)
			}
		case <-time.After(time.Second):
			process.closeControl()
			select {
			case <-packet:
			case <-time.After(time.Second):
			}
			t.Fatal("post-start cancellation emitted no supervisor signal packet within its test bound")
		}
	})
}

func TestSeatbeltWaitMapsAuthenticatedTargetStatusThroughProxy(t *testing.T) {
	for _, test := range []struct {
		name  string
		proof seatbeltCleanupProof
		check func(*testing.T, error)
	}{
		{
			name:  "exit",
			proof: seatbeltCleanupProof{TargetExited: true, TargetExitCode: 37},
			check: func(t *testing.T, err error) {
				t.Helper()
				var exitError *exec.ExitError
				if !errors.As(err, &exitError) {
					t.Fatalf("Wait error = %v, want exit status 37", err)
				}
				status := exitError.Sys().(syscall.WaitStatus)
				if !status.Exited() || status.ExitStatus() != 37 {
					t.Fatalf("Wait status = %v, want exit 37", status)
				}
			},
		},
		{
			name:  "signal",
			proof: seatbeltCleanupProof{TargetSignal: int(syscall.SIGTERM)},
			check: func(t *testing.T, err error) {
				t.Helper()
				var exitError *exec.ExitError
				if !errors.As(err, &exitError) {
					t.Fatalf("Wait error = %v, want SIGTERM", err)
				}
				status := exitError.Sys().(syscall.WaitStatus)
				if !status.Signaled() || status.Signal() != syscall.SIGTERM {
					t.Fatalf("Wait status = %v, want SIGTERM", status)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			proofControl, supervisorControl := seatbeltTestDeadlineSocketPair(t)
			statusControl, proxyStatus := seatbeltTestSocketPair(t)
			helperControl, helperPeer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = helperControl.Close()
				_ = helperPeer.Close()
			})
			challenge := bytes.Repeat([]byte{0x94}, seatbeltChallengeSize)
			// macOS 26 can collapse a signaled supervisor into sandbox-exec's
			// generic 125 status. The proxy must use the authenticated proof,
			// not this intentionally mismatched inner result.
			command := exec.Command(os.Args[0], seatbeltStatusProxyArgument, "--", "/bin/sh", "-c", "exit 125")
			command.Env = seatbeltStatusProxyEnvironment(os.Environ())
			command.ExtraFiles = []*os.File{proxyStatus, helperControl}
			process := &seatbeltProcess{
				command: command, supervised: true, control: proofControl,
				helperControl: helperControl, statusControl: statusControl, proxyStatus: proxyStatus,
				challenge: append([]byte(nil), challenge...), cleanupDone: make(chan struct{}),
			}
			go func() {
				got, _ := seatbeltTestAcceptTargetStart(supervisorControl, challenge)
				proof := test.proof
				proof.Magic = seatbeltProofMagic
				proof.Version = seatbeltProofVersion
				proof.Challenge = hex.EncodeToString(got)
				proof.ZeroLiveTargets = true
				encoded, _ := json.Marshal(proof)
				_, _ = supervisorControl.Write(encoded)
				_ = supervisorControl.Close()
			}()
			if err := process.Start(); err != nil {
				t.Fatal(err)
			}
			waitErr := process.Wait()
			test.check(t, waitErr)
			select {
			case <-process.CleanupDone():
			default:
				t.Fatal("authenticated proof did not complete cleanup")
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
	seatbeltTestStartTarget(t, control, challenge)
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

func TestSeatbeltSupervisorPersistsRecoveryProofBeforeParentAcknowledgement(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "home"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv(seatbeltRecoveryProofEnvironment, "1")
	control, peer := seatbeltTestSocketPair(t)
	supervisorFD, err := unix.Dup(int(peer.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	challenge := bytes.Repeat([]byte{0x7d}, RecoveryProofChallengeSize)
	result := make(chan int, 1)
	go func() {
		result <- runSeatbeltSupervisor(supervisorFD, filepath.Join(root, "missing-target"), nil)
	}()
	seatbeltTestStartTarget(t, control, challenge)
	if _, err := io.ReadAll(control); err != nil {
		t.Fatal(err)
	}
	if status := <-result; status != 125 {
		t.Fatalf("pre-target supervisor status = %d, want 125", status)
	}
	if proven, err := VerifySessionCleanupProof(root, challenge); err != nil || !proven {
		t.Fatalf("persisted recovery proof = (%v, %v)", proven, err)
	}
}

func TestSeatbeltSupervisorPersistsRecoveryProofAfterOwnerConnectionLoss(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "home"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv(seatbeltRecoveryProofEnvironment, "1")
	control, peer := seatbeltTestSocketPair(t)
	supervisorFD, err := unix.Dup(int(peer.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	challenge := bytes.Repeat([]byte{0x8f}, RecoveryProofChallengeSize)
	result := make(chan int, 1)
	go func() {
		result <- runSeatbeltSupervisor(supervisorFD, filepath.Join(root, "missing-target"), nil)
	}()
	seatbeltTestStartTarget(t, control, challenge)
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	if status := <-result; status != 125 {
		t.Fatalf("disconnected supervisor status = %d, want 125", status)
	}
	if proven, err := VerifySessionCleanupProof(root, challenge); err != nil || !proven {
		t.Fatalf("recovery proof after owner loss = (%v, %v)", proven, err)
	}
}

func TestSeatbeltSupervisorWaitsForStartAfterClearingPreparedProof(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "home"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv(seatbeltRecoveryProofEnvironment, "1")
	control, peer := seatbeltTestSocketPair(t)
	supervisorFD, err := unix.Dup(int(peer.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	challenge := bytes.Repeat([]byte{0x91}, RecoveryProofChallengeSize)
	if err := PrepareSessionCleanupProof(root, challenge); err != nil {
		t.Fatal(err)
	}
	result := make(chan int, 1)
	go func() {
		result <- runSeatbeltSupervisor(supervisorFD, filepath.Join(root, "missing-target"), nil)
	}()
	if _, err := control.Write(challenge); err != nil {
		t.Fatal(err)
	}
	ready := []byte{0}
	if _, err := io.ReadFull(control, ready); err != nil || ready[0] != seatbeltSupervisorReady {
		t.Fatalf("supervisor readiness = (%q, %v)", ready, err)
	}
	if proven, err := VerifySessionCleanupProof(root, challenge); err != nil || proven {
		t.Fatalf("prepared proof after readiness = (%v, %v)", proven, err)
	}
	select {
	case status := <-result:
		t.Fatalf("supervisor exited before start decision with %d", status)
	default:
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	if status := <-result; status != 125 {
		t.Fatalf("disconnected supervisor status = %d, want 125", status)
	}
	if proven, err := VerifySessionCleanupProof(root, challenge); err != nil || !proven {
		t.Fatalf("no-target proof after owner loss = (%v, %v)", proven, err)
	}
}

func TestSeatbeltRecoveryProofControlNeverReachesTargetEnvironment(t *testing.T) {
	proxy := seatbeltStatusProxyEnvironment([]string{
		"HOME=/private/tmp/session/home", seatbeltRecoveryProofEnvironment + "=1",
	})
	if !seatbeltRecoveryProofEnabled(proxy) {
		t.Fatal("status proxy lost recovery-proof control")
	}
	supervisor := seatbeltSupervisorEnvironment(proxy)
	if !seatbeltRecoveryProofEnabled(supervisor) {
		t.Fatal("supervisor lost recovery-proof control")
	}
	if seatbeltRecoveryProofEnabled(seatbeltTargetEnvironment(supervisor)) {
		t.Fatal("target inherited recovery-proof control")
	}
}

func TestSelectedEnvironmentPolicyValidationStage(t *testing.T) {
	request := seatbeltTestRequest(t)
	traceRoot, err := os.MkdirTemp("/private/tmp", "acs-selected-policy-stage-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(traceRoot) })
	trace := filepath.Join(traceRoot, "environment-transport")
	lease, err := environmentresource.Resolve([]environmentresource.Intent{{
		ID: "token", Destination: "PROFILE_SELECTED_TOKEN", Scope: "attached-process-tree", SourceKind: "secret-reference",
		Provider: "host-environment", Reference: "ACS_NATIVE_PROFILE_TOKEN", Required: true, Classification: "secret",
	}}, func(name string) (string, bool) { return "selected-test-value", name == "ACS_NATIVE_PROFILE_TOKEN" })
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	request.environmentProjection = lease
	targetMarker := filepath.Join(request.temporaryDirectory, "environment-transport-target")
	request.arguments = []string{"-test.run=^TestSeatbeltHelperProcess$", "--", "environment-transport-target", targetMarker}
	sandboxExecFixture := seatbeltEnvironmentSandboxExecFixture(t)
	backend := &seatbeltBackend{
		executable: sandboxExecFixture,
		policy: func(validatedProcessRequest) (string, []string, error) {
			return seatbeltEnvironmentTestPolicy(request, trace)
		},
	}
	fixtureContext, cancelFixture := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancelFixture()
	process, err := backend.prepare(fixtureContext, request)
	if err != nil {
		t.Fatal(err)
	}
	prepared, ok := process.(*seatbeltProcess)
	if !ok {
		t.Fatalf("prepared process type = %T", process)
	}
	t.Cleanup(func() { closeUnstartedSeatbeltFixture(t, prepared) })
	if prepared.command.Process != nil {
		t.Fatal("policy-validation stage unexpectedly started the final process")
	}
	contents, err := os.ReadFile(trace + "-validation")
	if err != nil || string(contents) != "true" {
		t.Fatalf("selected environment validation observation=%q err=%v", contents, err)
	}
	for _, stage := range []string{"proxy", "target"} {
		if _, err := os.Stat(trace + "-" + stage); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("selected environment policy stage unexpectedly reached %s: %v", stage, err)
		}
	}
	if _, err := os.Stat(targetMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("prepare-only selected environment unexpectedly started its target: %v", err)
	}
}

func TestSelectedEnvironmentSupervisorStartAndCancelStage(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	traceRoot, err := os.MkdirTemp("/private/tmp", "acs-selected-start-stage-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(traceRoot) })
	trace := filepath.Join(traceRoot, "environment-transport")
	lease, err := environmentresource.Resolve([]environmentresource.Intent{{
		ID: "token", Destination: "PROFILE_SELECTED_TOKEN", Scope: "attached-process-tree", SourceKind: "secret-reference",
		Provider: "host-environment", Reference: "ACS_NATIVE_PROFILE_TOKEN", Required: true, Classification: "secret",
	}}, func(name string) (string, bool) { return "selected-test-value", name == "ACS_NATIVE_PROFILE_TOKEN" })
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	request.environmentProjection = lease
	targetMarker := filepath.Join(request.temporaryDirectory, "environment-transport-target")
	request.arguments = []string{"-test.run=^TestSeatbeltHelperProcess$", "--", "environment-transport-blocked-target", targetMarker}
	sandboxExecFixture := seatbeltEnvironmentSandboxExecFixture(t)
	backend := &seatbeltBackend{
		executable: sandboxExecFixture,
		policy: func(validatedProcessRequest) (string, []string, error) {
			return seatbeltEnvironmentTestPolicy(request, trace)
		},
	}
	fixtureContext, cancelFixture := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancelFixture()
	process, err := backend.prepare(fixtureContext, request)
	if err != nil {
		t.Fatal(err)
	}
	prepared, ok := process.(*seatbeltProcess)
	if !ok {
		t.Fatalf("prepared process type = %T", process)
	}
	startResult := make(chan error, 1)
	go func() { startResult <- process.Start() }()
	select {
	case err := <-startResult:
		if err != nil {
			t.Fatalf("selected environment start-and-cancel start: %v; trace=%s", err, seatbeltEnvironmentTraceState(trace))
		}
	case <-time.After(4 * time.Second):
		cancelFixture()
		prepared.closeControl()
		prepared.closeStatusControl()
		select {
		case <-startResult:
		case <-time.After(time.Second):
		}
		t.Fatalf("selected environment start-and-cancel did not start; trace=%s", seatbeltEnvironmentTraceState(trace))
	}
	waitResult := make(chan error, 1)
	go func() { waitResult <- process.Wait() }()
	readyDeadline := time.Now().Add(2 * time.Second)
	for {
		contents, readErr := os.ReadFile(targetMarker)
		if readErr == nil && string(contents) == "true" {
			break
		}
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			cancelFixture()
			prepared.closeControl()
			prepared.closeStatusControl()
			select {
			case <-waitResult:
			case <-time.After(time.Second):
			}
			t.Fatalf("selected environment start-and-cancel target marker: %v", readErr)
		}
		select {
		case waitErr := <-waitResult:
			t.Fatalf("selected environment target exited before ready: %v; trace=%s", waitErr, seatbeltEnvironmentTraceState(trace))
		default:
		}
		if time.Now().After(readyDeadline) {
			cancelFixture()
			prepared.closeControl()
			prepared.closeStatusControl()
			select {
			case <-waitResult:
			case <-time.After(time.Second):
			}
			t.Fatalf("selected environment target did not become ready; trace=%s", seatbeltEnvironmentTraceState(trace))
		}
		time.Sleep(time.Millisecond)
	}
	signalResult := make(chan error, 1)
	go func() { signalResult <- process.Signal(syscall.SIGKILL) }()
	select {
	case err := <-signalResult:
		if err != nil {
			cancelFixture()
			prepared.closeControl()
			prepared.closeStatusControl()
			select {
			case <-waitResult:
			case <-time.After(time.Second):
			}
			t.Fatalf("selected environment target signal: %v; trace=%s", err, seatbeltEnvironmentTraceState(trace))
		}
	case <-time.After(time.Second):
		cancelFixture()
		prepared.closeControl()
		prepared.closeStatusControl()
		select {
		case <-signalResult:
		case <-time.After(time.Second):
		}
		t.Fatalf("selected environment target signal exceeded its test bound; trace=%s", seatbeltEnvironmentTraceState(trace))
	}
	select {
	case waitErr := <-waitResult:
		var exitError *exec.ExitError
		if !errors.As(waitErr, &exitError) {
			t.Fatalf("selected environment canceled Wait error = %v, want SIGKILL", waitErr)
		}
		status, ok := exitError.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatalf("selected environment canceled Wait status = %v, want SIGKILL", exitError.Sys())
		}
	case <-time.After(4 * time.Second):
		cancelFixture()
		prepared.closeControl()
		prepared.closeStatusControl()
		settled := false
		select {
		case <-waitResult:
			settled = true
		case <-time.After(time.Second):
		}
		t.Fatalf("selected environment canceled Wait exceeded its test bound; settled-after-control-close=%t; trace=%s", settled, seatbeltEnvironmentTraceState(trace))
	}
	select {
	case <-process.(ProcessCleanup).CleanupDone():
	default:
		t.Fatal("selected environment canceled target lacked authenticated cleanup completion")
	}
	for _, stage := range []string{"validation", "proxy"} {
		contents, err := os.ReadFile(trace + "-" + stage)
		if err != nil || string(contents) != "true" {
			t.Fatalf("selected environment start-and-cancel %s observation=%q err=%v", stage, contents, err)
		}
	}
	if contents, err := os.ReadFile(targetMarker); err != nil || string(contents) != "true" {
		t.Fatalf("selected environment start-and-cancel target observation=%q err=%v", contents, err)
	}
}

func TestSelectedEnvironmentStaysSeparateFromPolicyValidationAndStatusProxy(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	trace := filepath.Join(filepath.Dir(filepath.Dir(request.workspace)), "environment-transport")
	target := filepath.Join(request.temporaryDirectory, "environment-transport-target")
	denialReceipt := filepath.Join(request.temporaryDirectory, "outside-signal-denied")
	descendantReady := filepath.Join(request.temporaryDirectory, "environment-descendant.ready")
	descendantPIDPath := filepath.Join(request.temporaryDirectory, "environment-descendant.pid")
	lease, err := environmentresource.Resolve([]environmentresource.Intent{{
		ID: "token", Destination: "PROFILE_SELECTED_TOKEN", Scope: "attached-process-tree", SourceKind: "secret-reference",
		Provider: "host-environment", Reference: "ACS_NATIVE_PROFILE_TOKEN", Required: true, Classification: "secret",
	}}, func(name string) (string, bool) { return "selected-test-value", name == "ACS_NATIVE_PROFILE_TOKEN" })
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	request.environmentProjection = lease
	bystanderMarker := filepath.Join(filepath.Dir(filepath.Dir(request.workspace)), "outside-bystander.ready")
	bystander := exec.Command(os.Args[0], "-test.run=^TestSeatbeltHelperProcess$", "--", "bystander-heartbeat", bystanderMarker)
	bystander.Env = []string{"PATH=/usr/bin:/bin"}
	if err := bystander.Start(); err != nil {
		t.Fatal(err)
	}
	bystanderWaited := false
	cleanupBystander := func() {
		if !bystanderWaited {
			_ = bystander.Process.Kill()
			_ = bystander.Wait()
			bystanderWaited = true
		}
	}
	t.Cleanup(cleanupBystander)
	if _, err := waitForSeatbeltHeartbeat(bystanderMarker, 0, time.Second); err != nil {
		t.Fatalf("outside bystander did not start its heartbeat: %v", err)
	}
	procAPI, err := loadSeatbeltProcAPI()
	if err != nil {
		t.Fatal(err)
	}
	bystanderIdentity, err := procAPI.info(bystander.Process.Pid)
	if err != nil || bystanderIdentity.PID != uint32(bystander.Process.Pid) {
		t.Fatalf("read outside bystander identity: identity=%+v err=%v", bystanderIdentity, err)
	}
	runnerIdentity, err := procAPI.info(os.Getpid())
	if err != nil || runnerIdentity.PID != uint32(os.Getpid()) {
		t.Fatalf("read test runner identity: identity=%+v err=%v", runnerIdentity, err)
	}
	observerStop := make(chan struct{})
	observerDone := make(chan error, 1)
	go func() {
		observerDone <- observeSeatbeltBystander(observerStop, procAPI, bystanderMarker,
			bystander.Process.Pid, bystanderIdentity, os.Getpid(), runnerIdentity)
	}()
	observerStopped := false
	stopObserver := func() error {
		if !observerStopped {
			close(observerStop)
			observerStopped = true
		}
		return <-observerDone
	}
	t.Cleanup(func() {
		if !observerStopped {
			_ = stopObserver()
		}
	})
	request.arguments = []string{
		"-test.run=^TestSeatbeltHelperProcess$", "--", "environment-transport-blocked-target", target,
		strconv.Itoa(bystander.Process.Pid), denialReceipt, descendantReady, descendantPIDPath,
	}
	backend := &seatbeltBackend{
		executable: seatbeltEnvironmentSandboxExecFixture(t),
		policy: func(validatedProcessRequest) (string, []string, error) {
			return seatbeltEnvironmentTestPolicy(request, trace)
		},
	}
	fixtureContext, cancelFixture := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancelFixture()
	process, err := backend.prepare(fixtureContext, request)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("selected environment fixture phase: prepared")
	startResult := make(chan error, 1)
	go func() { startResult <- process.Start() }()
	select {
	case err := <-startResult:
		if err != nil {
			t.Fatalf("selected environment composition start: %v; trace=%s", err, seatbeltEnvironmentTraceState(trace))
		}
		t.Log("selected environment fixture phase: started")
	case <-time.After(6 * time.Second):
		cancelFixture()
		if prepared, ok := process.(*seatbeltProcess); ok {
			prepared.closeControl()
		}
		select {
		case <-startResult:
		case <-time.After(time.Second):
		}
		t.Fatalf("selected environment composition start exceeded its test bound; trace=%s", seatbeltEnvironmentTraceState(trace))
	}
	waitResult := make(chan error, 1)
	go func() { waitResult <- process.Wait() }()
	readyDeadline := time.Now().Add(5 * time.Second)
	var descendantPID int
	var descendantIdentity seatbeltBSDInfo
	for {
		targetContents, targetErr := os.ReadFile(target)
		denialContents, denialErr := os.ReadFile(denialReceipt)
		readyContents, readyErr := os.ReadFile(descendantReady)
		pidContents, pidErr := os.ReadFile(descendantPIDPath)
		if targetErr == nil && string(targetContents) == "true" && denialErr == nil &&
			string(denialContents) == "EPERM" && readyErr == nil && string(readyContents) == "ready" && pidErr == nil {
			pid, parseErr := strconv.Atoi(strings.TrimSpace(string(pidContents)))
			if parseErr != nil || pid <= 0 {
				t.Fatalf("contained descendant PID receipt=%q err=%v", pidContents, parseErr)
			}
			descendantPID = pid
			descendantIdentity, err = procAPI.info(descendantPID)
			if err != nil || descendantIdentity.PID != uint32(descendantPID) || descendantIdentity.Status == seatbeltProcStatusZombie {
				t.Fatalf("contained descendant identity=%+v err=%v", descendantIdentity, err)
			}
			break
		}
		select {
		case waitErr := <-waitResult:
			t.Fatalf("selected environment target exited before cancellation readiness: %v", waitErr)
		default:
		}
		if time.Now().After(readyDeadline) {
			cleanupErr := process.Signal(syscall.SIGKILL)
			cleanupSettled := false
			if cleanupErr == nil {
				select {
				case <-waitResult:
					cleanupSettled = true
				case <-time.After(6 * time.Second):
				}
			}
			if !cleanupSettled {
				cancelFixture()
			}
			prepared, _ := process.(*seatbeltProcess)
			if prepared != nil && !cleanupSettled {
				prepared.closeControl()
				prepared.closeStatusControl()
			}
			if !cleanupSettled {
				select {
				case <-waitResult:
				case <-time.After(time.Second):
				}
			}
			t.Fatalf("selected environment target/descendant did not become ready: cleanup_error=%v cleanup_settled=%t trace=%s", cleanupErr, cleanupSettled, seatbeltEnvironmentTraceState(trace))
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err := process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("selected environment cancellation signal: %v", err)
	}
	select {
	case err := <-waitResult:
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			t.Fatalf("selected environment canceled Wait error=%v, want SIGKILL; trace=%s", err, seatbeltEnvironmentTraceState(trace))
		}
		status, ok := exitError.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatalf("selected environment canceled Wait status=%v, want SIGKILL", exitError.Sys())
		}
		select {
		case <-process.(ProcessCleanup).CleanupDone():
		default:
			t.Fatal("selected environment target completed without authenticated cleanup")
		}
		t.Log("selected environment fixture phase: waited")
	case <-time.After(6 * time.Second):
		cancelFixture()
		waitAfterControlClose := "not-attempted"
		signalResult := make(chan error, 1)
		go func() { signalResult <- process.Signal(syscall.SIGKILL) }()
		select {
		case <-signalResult:
		case <-time.After(time.Second):
			if prepared, ok := process.(*seatbeltProcess); ok {
				prepared.closeControl()
			}
			select {
			case <-signalResult:
			case <-time.After(time.Second):
			}
		}
		select {
		case <-waitResult:
		case <-time.After(time.Second):
			waitAfterControlClose = "unsettled"
			if prepared, ok := process.(*seatbeltProcess); ok {
				prepared.closeControl()
				prepared.closeStatusControl()
			}
			select {
			case <-waitResult:
				waitAfterControlClose = "settled"
			case <-time.After(time.Second):
			}
		}
		t.Fatalf("selected environment composition cleanup exceeded its test bound; wait-after-control-close=%s; trace=%s", waitAfterControlClose, seatbeltEnvironmentTraceState(trace))
	}
	if err := stopObserver(); err != nil {
		t.Fatalf("outside bystander or test runner changed during contained cleanup: %v", err)
	}
	descendantExited := false
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		currentIdentity, err := procAPI.info(descendantPID)
		if errors.Is(err, syscall.ESRCH) || err == nil &&
			(currentIdentity.StartSecond != descendantIdentity.StartSecond ||
				currentIdentity.StartMicrosecond != descendantIdentity.StartMicrosecond ||
				currentIdentity.Status == seatbeltProcStatusZombie) {
			descendantExited = true
			break
		} else if err != nil {
			t.Fatalf("inspect contained descendant after cleanup: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !descendantExited {
		info, err := procAPI.info(descendantPID)
		t.Fatalf("contained descendant survived authenticated cleanup: original=%+v current=%+v err=%v", descendantIdentity, info, err)
	}
	for _, stage := range []string{"validation", "proxy"} {
		contents, err := os.ReadFile(trace + "-" + stage)
		if err != nil || string(contents) != "true" {
			t.Fatalf("selected environment %s observation=%q err=%v", stage, contents, err)
		}
	}
	if contents, err := os.ReadFile(target); err != nil || string(contents) != "true" {
		t.Fatalf("selected environment target observation=%q err=%v", contents, err)
	}
	denial, err := os.ReadFile(denialReceipt)
	if err != nil || string(denial) != "EPERM" {
		t.Fatalf("sandbox outside-signal denial receipt=%q err=%v", denial, err)
	}
	if _, err := os.Stat(bystanderMarker); err != nil {
		t.Fatalf("outside bystander heartbeat disappeared after target cleanup: %v", err)
	}
	heartbeatAtCleanup, err := readSeatbeltHeartbeat(bystanderMarker)
	if err != nil {
		t.Fatalf("read bystander heartbeat after contained cleanup: %v", err)
	}
	if _, err := waitForSeatbeltHeartbeat(bystanderMarker, heartbeatAtCleanup, time.Second); err != nil {
		t.Fatalf("outside bystander made no fresh progress after target cleanup: %v", err)
	}
	liveIdentity, err := procAPI.info(bystander.Process.Pid)
	if err != nil || liveIdentity.PID != bystanderIdentity.PID ||
		liveIdentity.StartSecond != bystanderIdentity.StartSecond ||
		liveIdentity.StartMicrosecond != bystanderIdentity.StartMicrosecond ||
		liveIdentity.Status == seatbeltProcStatusStop || liveIdentity.Status == seatbeltProcStatusZombie {
		t.Fatalf("outside bystander identity/state changed after target cleanup: before=%+v after=%+v err=%v", bystanderIdentity, liveIdentity, err)
	}
	liveRunnerIdentity, err := procAPI.info(os.Getpid())
	if err != nil || liveRunnerIdentity.PID != runnerIdentity.PID ||
		liveRunnerIdentity.StartSecond != runnerIdentity.StartSecond ||
		liveRunnerIdentity.StartMicrosecond != runnerIdentity.StartMicrosecond ||
		liveRunnerIdentity.Status == seatbeltProcStatusStop || liveRunnerIdentity.Status == seatbeltProcStatusZombie {
		t.Fatalf("test runner identity/state changed after target cleanup: before=%+v after=%+v err=%v", runnerIdentity, liveRunnerIdentity, err)
	}
	if err := bystander.Process.Kill(); err != nil {
		t.Fatalf("harness-owned bystander teardown: %v", err)
	}
	if err := bystander.Wait(); err == nil {
		t.Fatal("harness-owned bystander kill returned a successful exit")
	}
	bystanderWaited = true
	if _, err := procAPI.info(bystander.Process.Pid); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("bystander remained after owned teardown: %v", err)
	}
}

func seatbeltEnvironmentTraceState(trace string) string {
	states := make([]string, 0, 2)
	for _, stage := range []string{"validation", "proxy"} {
		contents, err := os.ReadFile(trace + "-" + stage)
		state := "missing"
		if err == nil {
			state = "invalid"
			if string(contents) == "true" {
				state = "true"
			}
		}
		states = append(states, stage+"="+state)
	}
	return strings.Join(states, ",")
}

func closeUnstartedSeatbeltFixture(t *testing.T, process *seatbeltProcess) {
	t.Helper()
	process.closeControl()
	process.closeStatusControl()
	if process.helperControl != nil {
		if err := process.helperControl.Close(); err != nil {
			t.Errorf("close prepared helper control: %v", err)
		}
		process.helperControl = nil
	}
	if process.proxyStatus != nil {
		if err := process.proxyStatus.Close(); err != nil {
			t.Errorf("close prepared proxy status: %v", err)
		}
		process.proxyStatus = nil
	}
}

func TestSeatbeltSupervisorAuthenticatesDescriptorPreflightFailure(t *testing.T) {
	control, peer := seatbeltTestSocketPair(t)
	supervisorFD, err := unix.Dup(int(peer.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err := peer.Close(); err != nil {
		t.Fatal(err)
	}
	challenge := bytes.Repeat([]byte{0x4d}, seatbeltChallengeSize)
	result := make(chan int, 1)
	go func() {
		result <- runSeatbeltSupervisorWithDescriptorSealer(
			supervisorFD, "/usr/bin/true", nil,
			func(seatbeltDescriptorEnumerator) error { return errors.New("injected descriptor preflight failure") },
		)
	}()
	seatbeltTestStartTarget(t, control, challenge)
	proof, err := io.ReadAll(control)
	if err != nil {
		t.Fatal(err)
	}
	if status := <-result; status != 125 {
		t.Fatalf("descriptor preflight supervisor status = %d, want 125", status)
	}
	if err := validateSeatbeltCleanupProof(proof, challenge); err != nil {
		t.Fatalf("descriptor preflight proof = %q, want valid: %v", proof, err)
	}
	var decoded seatbeltCleanupProof
	if err := json.Unmarshal(proof, &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.NoTargetStarted || decoded.TargetExited || decoded.TargetExitCode != 0 || decoded.TargetSignal != 0 {
		t.Fatalf("descriptor preflight proof = %#v, want an explicit no-target result", decoded)
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
	parent, peer := seatbeltTestDeadlineSocketPair(t)
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

func TestSeatbeltCancellationCleanupProofTimeoutFailsClosed(t *testing.T) {
	parent, peer := seatbeltTestDeadlineSocketPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	process := newSeatbeltLifecycleTestProcess(exec.Command("/usr/bin/true"))
	process.ctx = ctx
	process.supervised = true
	process.control = parent
	process.challenge = bytes.Repeat([]byte{0xa5}, seatbeltChallengeSize)
	timedOut := make(chan time.Time)
	close(timedOut)
	process.proofTimeout = func() <-chan time.Time { return timedOut }
	releasePeer := make(chan struct{})
	go func() {
		_, _ = seatbeltTestAcceptTargetStart(peer, process.challenge)
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

func TestSeatbeltNormalWaitDoesNotApplyCancellationProofTimeout(t *testing.T) {
	control, supervisorControl := seatbeltTestDeadlineSocketPair(t)
	statusControl, proxyStatus := seatbeltTestSocketPair(t)
	challenge := bytes.Repeat([]byte{0xb6}, seatbeltChallengeSize)
	process := newSeatbeltLifecycleTestProcess(exec.Command("/bin/sleep", "0.05"))
	process.ctx = context.Background()
	process.supervised = true
	process.control = control
	process.statusControl = statusControl
	process.challenge = challenge
	timedOut := make(chan time.Time)
	close(timedOut)
	process.proofTimeout = func() <-chan time.Time { return timedOut }

	go func() {
		gotChallenge, err := seatbeltTestAcceptTargetStart(supervisorControl, challenge)
		if err != nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
		_ = json.NewEncoder(supervisorControl).Encode(seatbeltCleanupProof{
			Magic: seatbeltProofMagic, Version: seatbeltProofVersion,
			Challenge: hex.EncodeToString(gotChallenge), ZeroLiveTargets: true,
			TargetExited: true,
		})
		_ = supervisorControl.Close()
	}()

	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatalf("normal Wait applied the cancellation proof timeout: %v", err)
	}
	status := make([]byte, seatbeltStatusPacketSize)
	if _, err := io.ReadFull(proxyStatus, status); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(status, []byte{seatbeltStatusExit, 0}) {
		t.Fatalf("target status = %v, want successful exit", status)
	}
	select {
	case <-process.CleanupDone():
	default:
		t.Fatal("valid delayed cleanup proof did not complete cleanup")
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

func TestSeatbeltTransientZombieSnapshotDoesNotPoisonCleanupProof(t *testing.T) {
	pid := os.Getpid()
	secondSnapshot := make(chan struct{})
	enumerator := &seatbeltTransientZombieEnumerator{pid: pid, secondSnapshot: secondSnapshot}
	ledger := newSeatbeltIdentityLedger()
	stop := make(chan struct{})
	done := make(chan struct{})
	go observeSeatbeltTargets(enumerator, -1, ledger, stop, done)
	select {
	case <-secondSnapshot:
	case <-time.After(time.Second):
		close(stop)
		<-done
		t.Fatal("observer did not retry transient zombie snapshot")
	}
	close(stop)
	<-done
	if err := ledger.failure(); err != nil {
		t.Fatalf("transient zombie snapshot poisoned cleanup proof: %v", err)
	}

	unstable := seatbeltTestEnumerator{
		pids:  []int{pid},
		infos: map[int]seatbeltBSDInfo{pid: {PID: uint32(pid), Status: seatbeltProcStatusIdle}},
	}
	if err := settleSeatbeltInstance(unstable, newSeatbeltIdentityLedger(), -1, 0, time.Now().Add(3*seatbeltSettlementRetryDelay)); err == nil {
		t.Fatal("persistent unstable snapshot unexpectedly proved cleanup")
	}
}

func TestSeatbeltRevalidationTreatsLiveEnumerationFailureAsUnstable(t *testing.T) {
	pid := os.Getpid()
	matched, err := sameSeatbeltProcessIdentity(
		seatbeltTestEnumerator{},
		pid,
		seatbeltBSDInfo{PID: uint32(pid), StartSecond: 1, StartMicrosecond: 2},
	)
	if matched {
		t.Fatal("unreadable process identity unexpectedly matched")
	}
	if !errors.Is(err, errSeatbeltProcessSnapshotUnstable) {
		t.Fatalf("revalidation error = %v, want transient snapshot", err)
	}
}

func TestSeatbeltDescriptorSealingRetriesTransientEBADF(t *testing.T) {
	sentinel, err := os.CreateTemp(t.TempDir(), "seatbelt-retry-descriptor")
	if err != nil {
		t.Fatal(err)
	}
	defer sentinel.Close()

	sentinelFD := int(sentinel.Fd())
	originalFlags, err := unix.FcntlInt(uintptr(sentinelFD), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(sentinelFD), unix.F_SETFD, originalFlags&^unix.FD_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = unix.FcntlInt(uintptr(sentinelFD), unix.F_SETFD, originalFlags)
	}()

	vanishedFD, err := unix.FcntlInt(sentinel.Fd(), unix.F_DUPFD, seatbeltTestMinimumSentinelDescriptor)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Close(vanishedFD); err != nil {
		t.Fatal(err)
	}

	enumerations := 0
	enumerator := seatbeltTestDescriptorEnumerator{list: func(int) ([]int, error) {
		enumerations++
		if enumerations == 1 {
			return []int{vanishedFD}, nil
		}
		return []int{sentinelFD}, nil
	}}
	if err := sealSeatbeltTargetDescriptors(enumerator); err != nil {
		t.Fatalf("seal descriptors after transient EBADF: %v", err)
	}
	if enumerations < 4 {
		t.Fatalf("descriptor enumerations = %d, want a retry after EBADF", enumerations)
	}
	flags, err := unix.FcntlInt(uintptr(sentinelFD), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("descriptor discovered after EBADF remained inheritable")
	}
}

func TestSeatbeltDescriptorSealingNonconvergenceFailsClosed(t *testing.T) {
	first, err := os.CreateTemp(t.TempDir(), "seatbelt-first-descriptor")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := os.CreateTemp(t.TempDir(), "seatbelt-second-descriptor")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()

	enumerations := 0
	enumerator := seatbeltTestDescriptorEnumerator{list: func(int) ([]int, error) {
		enumerations++
		if enumerations%2 == 1 {
			return []int{int(first.Fd())}, nil
		}
		return []int{int(second.Fd())}, nil
	}}
	if err := sealSeatbeltTargetDescriptors(enumerator); err == nil {
		t.Fatal("changing descriptor snapshots unexpectedly proved sealed")
	}
	if want := seatbeltDescriptorSealAttempts * 2; enumerations != want {
		t.Fatalf("descriptor enumerations = %d, want bounded %d", enumerations, want)
	}
}

type seatbeltTestDescriptorEnumerator struct {
	list func(int) ([]int, error)
}

func (enumerator seatbeltTestDescriptorEnumerator) descriptors(pid int) ([]int, error) {
	return enumerator.list(pid)
}

func TestSeatbeltCredentialAmbiguityFailsClosed(t *testing.T) {
	pid := os.Getpid()
	info := seatbeltBSDInfo{
		PID: uint32(pid), Status: seatbeltProcStatusStop, UID: uint32(os.Geteuid() + 1), RUID: uint32(os.Geteuid() + 1),
		SVUID: uint32(os.Geteuid() + 1), GID: uint32(os.Getegid()),
		RGID: uint32(os.Getegid()), SVGID: uint32(os.Getegid()),
		StartSecond: 1, StartMicrosecond: 2,
	}
	enumerator := seatbeltTestEnumerator{pids: []int{pid}, infos: map[int]seatbeltBSDInfo{pid: info}}
	if err := recordSeatbeltTargets(enumerator, -1, newSeatbeltIdentityLedger()); err == nil {
		t.Fatal("changed target credentials unexpectedly remained eligible for cleanup proof")
	}
}

const seatbeltTestMinimumSentinelDescriptor = 64 // Above the former bounded probe range.

func TestSeatbeltTargetCannotInheritOrSpoofControlDescriptor(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	sentinel, err := os.CreateTemp(t.TempDir(), "seatbelt-descriptor-sentinel")
	if err != nil {
		t.Fatal(err)
	}
	sentinelFD, err := unix.FcntlInt(sentinel.Fd(), unix.F_DUPFD, seatbeltTestMinimumSentinelDescriptor)
	if err != nil {
		_ = sentinel.Close()
		t.Fatal(err)
	}
	if err := sentinel.Close(); err != nil {
		_ = unix.Close(sentinelFD)
		t.Fatal(err)
	}
	sentinel = os.NewFile(uintptr(sentinelFD), "seatbelt-descriptor-sentinel")
	if sentinel == nil {
		_ = unix.Close(sentinelFD)
		t.Fatal("wrap duplicated descriptor sentinel")
	}
	flags, err := unix.FcntlInt(uintptr(sentinelFD), unix.F_GETFD, 0)
	if err != nil {
		_ = sentinel.Close()
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(sentinelFD), unix.F_SETFD, flags&^unix.FD_CLOEXEC); err != nil {
		_ = sentinel.Close()
		t.Fatal(err)
	}
	defer func() {
		_, _ = unix.FcntlInt(uintptr(sentinelFD), unix.F_SETFD, flags)
		_ = sentinel.Close()
	}()
	sentinelIdentity, err := seatbeltTestDescriptorIdentityForFD(sentinelFD)
	if err != nil {
		t.Fatal(err)
	}

	request := seatbeltTestRequest(t)
	request.arguments = []string{
		"-test.run=TestSeatbeltHelperProcess", "--", "check-extra-descriptors",
		strconv.FormatUint(sentinelIdentity.device, 10), strconv.FormatUint(sentinelIdentity.inode, 10),
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
		t.Fatalf("descriptor probe failed: %v; output=%q", err, output.String())
	}
	if got := strings.TrimSpace(output.String()); got != "sealed" {
		t.Fatalf("descriptor probe = %q, want sealed", got)
	}
}

type seatbeltTestDescriptorIdentity struct {
	device uint64
	inode  uint64
}

func seatbeltTestDescriptorIdentityForFD(fd int) (seatbeltTestDescriptorIdentity, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return seatbeltTestDescriptorIdentity{}, err
	}
	return seatbeltTestDescriptorIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
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

func TestSeatbeltRuntimeProbeDistinguishesAbsentFromDenied(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	root := filepath.Dir(filepath.Dir(request.workspace))
	probeDirectory := filepath.Join(root, "runtime-probes")
	if err := os.MkdirAll(probeDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(probeDirectory, "requirements.toml")
	if err := os.WriteFile(existing, []byte("managed"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(probeDirectory, "missing.toml")
	denied := filepath.Join(probeDirectory, "denied.toml")
	if err := os.WriteFile(denied, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	systemMissing := filepath.Join("/etc/codex", fmt.Sprintf("acs-runtime-probe-test-%d.toml", os.Getpid()))
	if _, err := os.Stat(systemMissing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("system probe fixture unexpectedly exists or is inaccessible: %v", err)
	}
	canonicalSystemMissing, err := resolveFuturePath(systemMissing)
	if err != nil {
		t.Fatal(err)
	}
	request.runtimeProbePaths = []string{existing, missing, systemMissing, canonicalSystemMissing}
	request.runtimeProbeTraversalPaths = []string{"/etc"}
	request.arguments = []string{
		"-test.run=TestSeatbeltHelperProcess", "--", "runtime-probes",
		existing, missing, denied, systemMissing, "/etc/passwd", "/etc",
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
		t.Fatalf("runtime probe helper failed: %v; output=%q", err, output.String())
	}
	if got := strings.TrimSpace(output.String()); got != "probed" {
		t.Fatalf("runtime probe helper output = %q", got)
	}
}

func TestSeatbeltPermitsSessionPrefixMetadataWithoutDirectoryContents(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	database := filepath.Join(request.sessionHome, ".codex", "state_5.sqlite")
	sibling := filepath.Join(request.sessionsDirectory, "sibling-secret")
	siblingWrite := filepath.Join(request.sessionsDirectory, "sibling-write")
	if err := os.WriteFile(sibling, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	request.arguments = []string{
		"-test.run=TestSeatbeltHelperProcess", "--", "session-prefix-metadata",
		database, request.sessionsDirectory, sibling, siblingWrite,
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
		t.Fatalf("Session prefix metadata helper failed: %v; output=%q", err, output.String())
	}
	if got := strings.TrimSpace(output.String()); got != "session-prefix-metadata" {
		t.Fatalf("Session prefix metadata helper output = %q", got)
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

const seatbeltNativePTYHarnessEnvironment = "ACS_SEATBELT_NATIVE_PTY_HARNESS"

func TestSeatbeltNativeRoutesTerminalSignalsOnlyToContainedTarget(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	for _, test := range []struct {
		name   string
		signal syscall.Signal
	}{
		{name: "terminal interrupt", signal: syscall.SIGINT},
		{name: "terminal resize", signal: syscall.SIGWINCH},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, err := os.MkdirTemp("/private/tmp", "acs-seatbelt-terminal-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(root) })
			master, terminal, err := pty.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer terminal.Close()
			command := exec.Command(os.Args[0], "-test.run=^TestSeatbeltNativePTYHarness$")
			command.Env = append(os.Environ(),
				seatbeltNativePTYHarnessEnvironment+"=1",
				"ACS_SEATBELT_NATIVE_PTY_ROOT="+root,
				"ACS_SEATBELT_NATIVE_PTY_SIGNAL="+strconv.Itoa(int(test.signal)),
			)
			command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
			command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			paths := seatbeltNativePTYPaths(root)
			ptyOutput, err := os.OpenFile(paths.ptyOutput, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if err := unix.SetNonblock(int(master.Fd()), true); err != nil {
				_ = ptyOutput.Close()
				t.Fatal(err)
			}
			drainCancel := make(chan struct{})
			drainDone := make(chan error, 1)
			go func() { drainDone <- drainSeatbeltPTYOutput(master, ptyOutput, drainCancel) }()
			drainStopped := false
			stopDrain := func() {
				if drainStopped {
					return
				}
				drainStopped = true
				close(drainCancel)
				joined := false
				select {
				case err := <-drainDone:
					joined = true
					if err != nil {
						t.Errorf("drain native PTY output: %v", err)
					}
				case <-time.After(time.Second):
					t.Error("native PTY output drain did not stop after explicit cancellation")
				}
				if joined {
					_ = master.Close()
					_ = ptyOutput.Close()
				}
			}
			defer stopDrain()
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = command.Process.Kill() })
			commandDone := make(chan error, 1)
			go func() { commandDone <- command.Wait() }()
			if err := terminal.Close(); err != nil {
				t.Fatal(err)
			}
			_ = waitForSeatbeltPTYReadyWithDiagnostics(t, paths.ready, commandDone, master, paths)
			waitForSeatbeltPTYMarkerWithDiagnostics(t, paths.scannerStarted, commandDone, master, paths)
			switch test.signal {
			case syscall.SIGINT:
				if err := writeSeatbeltPTYMaster(master, []byte{3}); err != nil {
					t.Fatal(err)
				}
			case syscall.SIGWINCH:
				if err := pty.Setsize(master, &pty.Winsize{Rows: 41, Cols: 119}); err != nil {
					t.Fatal(err)
				}
			}
			waitForSeatbeltPTYMarkerWithDiagnostics(t, paths.received, commandDone, master, paths)
			if err := writeSeatbeltPTYMaster(master, []byte("snapshot\n")); err != nil {
				t.Fatal(err)
			}
			waitForSeatbeltPTYMarkerWithDiagnostics(t, paths.snapshot, commandDone, master, paths)
			if err := writeSeatbeltPTYMaster(master, []byte("release\n")); err != nil {
				t.Fatal(err)
			}
			waitSeatbeltNativePTYHarness(t, command, commandDone, master, paths)
			stopDrain()
			if count, err := os.ReadFile(paths.observed); err != nil || string(count) != "1\n" {
				t.Fatalf("terminal %s deliveries after release = %q, %v; want exactly one", test.signal, count, err)
			}
			if count, err := os.ReadFile(paths.harnessObserved); err != nil || string(count) != "0\n" {
				t.Fatalf("harness %s deliveries = %q, %v; want none", test.signal, count, err)
			}
		})
	}
}

func TestSeatbeltPTYReadyPublicationIsAtomicAndContentValid(t *testing.T) {
	root := t.TempDir()
	ready := filepath.Join(root, "ready")
	beforeRename := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- publishSeatbeltPTYReady(ready, 1234, func(string) {
			close(beforeRename)
			<-release
		})
	}()
	<-beforeRename
	if contents, err := os.ReadFile(ready); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ready path became visible before committed publication: contents=%q err=%v", contents, err)
	}
	if group, published, err := readSeatbeltPTYReady(ready); err != nil || published || group != 0 {
		t.Fatalf("reader accepted prepublication state: group=%d published=%v err=%v", group, published, err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if group, published, err := readSeatbeltPTYReady(ready); err != nil || !published || group != 1234 {
		t.Fatalf("reader rejected committed ready state: group=%d published=%v err=%v", group, published, err)
	}
}

func TestSeatbeltPTYOutputDrainCancelsWhileSlaveRemainsOpen(t *testing.T) {
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	if err := unix.SetNonblock(int(master.Fd()), true); err != nil {
		t.Fatal(err)
	}
	output, err := os.CreateTemp(t.TempDir(), "pty-output-*")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	cancel := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- drainSeatbeltPTYOutput(master, output, cancel) }()
	if _, err := terminal.Write([]byte("drain-reader-active\n")); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for {
		contents, err := os.ReadFile(output.Name())
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(contents, []byte("drain-reader-active")) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("PTY drain did not demonstrate reader activity before cancellation")
		}
		time.Sleep(time.Millisecond)
	}
	close(cancel)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("nonblocking PTY drain did not honor cancellation while slave remained open")
	}
}

func TestSeatbeltNativePTYHarness(t *testing.T) {
	if os.Getenv(seatbeltNativePTYHarnessEnvironment) != "1" {
		return
	}
	root := os.Getenv("ACS_SEATBELT_NATIVE_PTY_ROOT")
	signalNumber, err := strconv.Atoi(os.Getenv("ACS_SEATBELT_NATIVE_PTY_SIGNAL"))
	if err != nil {
		t.Fatal(err)
	}
	paths := seatbeltNativePTYPaths(root)
	request, err := seatbeltNativePTYRequest(root)
	if err != nil {
		t.Fatal(err)
	}
	request.arguments = []string{
		"-test.run=^TestSeatbeltNativePTYTarget$", "--", strconv.Itoa(signalNumber),
		paths.ready, paths.received, paths.snapshot, paths.observed, paths.diagnostic, paths.observation, paths.scannerStarted,
	}
	request.terminal = Terminal{Input: os.Stdin, Output: os.Stdout, ErrorOutput: os.Stderr}
	harnessSignals := make(chan os.Signal, 8)
	signal.Notify(harnessSignals, syscall.Signal(signalNumber))
	defer signal.Stop(harnessSignals)
	process, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	targetGroup := waitForSeatbeltPTYReady(t, paths.ready)
	assertSeatbeltPTYForegroundTarget(t, os.Stdin, targetGroup)
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	assertSeatbeltPTYForegroundRestored(t, os.Stdin)
	signal.Stop(harnessSignals)
	harnessDeliveries := drainSeatbeltPTYSignals(t, harnessSignals, syscall.Signal(signalNumber))
	if err := os.WriteFile(paths.harnessObserved, []byte(strconv.Itoa(harnessDeliveries)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSeatbeltNativePTYTarget(t *testing.T) {
	arguments := seatbeltPTYTargetArguments()
	if arguments == nil {
		return
	}
	signalNumber, err := strconv.Atoi(arguments[0])
	if err != nil {
		t.Fatal(err)
	}
	want := syscall.Signal(signalNumber)
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, want)
	defer signal.Stop(signals)
	commands := make(chan string, 2)
	recordSeatbeltPTYObservation(arguments[6], "target-start "+seatbeltPTYTerminalObservation(os.Stdin))
	go func() {
		defer close(commands)
		scanner := bufio.NewScanner(os.Stdin)
		if err := os.WriteFile(arguments[7], []byte("scanner-started\n"), 0o600); err != nil {
			recordSeatbeltPTYObservation(arguments[6], "scanner-start-marker-failed "+err.Error())
			return
		}
		for scanner.Scan() {
			line := scanner.Text()
			recordSeatbeltPTYObservation(arguments[6], "scanner-line "+strconv.Quote(line))
			commands <- line
		}
		diagnostic := "terminal scanner reached EOF"
		if err := scanner.Err(); err != nil {
			diagnostic = "terminal scanner failed: " + err.Error()
		}
		_ = os.WriteFile(arguments[5], []byte(diagnostic+"\n"), 0o600)
	}()
	if err := publishSeatbeltPTYReady(arguments[1], syscall.Getpgrp(), nil); err != nil {
		t.Fatal(err)
	}
	deliveries := 0
	observed := false
	for {
		select {
		case received := <-signals:
			if received != want {
				t.Fatalf("received terminal signal %v, want %v", received, want)
			}
			deliveries++
			recordSeatbeltPTYObservation(arguments[6], "signal-received "+received.String()+" "+seatbeltPTYTerminalObservation(os.Stdin))
			if err := os.WriteFile(arguments[2], []byte(strconv.Itoa(deliveries)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		case command, open := <-commands:
			if !open {
				t.Fatal("terminal scanner ended before release")
			}
			switch command {
			case "snapshot":
				if err := os.WriteFile(arguments[3], []byte("snapshot\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				observed = true
			case "release":
				if !observed {
					t.Fatal("terminal signal delivery was released before observation")
				}
				signal.Stop(signals)
				deliveries += drainSeatbeltPTYSignals(t, signals, want)
				if err := os.WriteFile(arguments[4], []byte(strconv.Itoa(deliveries)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return
			default:
				t.Fatalf("unexpected native PTY command %q", command)
			}
		}
	}
}

func drainSeatbeltPTYSignals(t *testing.T, signals <-chan os.Signal, want syscall.Signal) int {
	t.Helper()
	deliveries := 0
	for {
		select {
		case received := <-signals:
			if received != want {
				t.Fatalf("received terminal signal %v, want %v", received, want)
			}
			deliveries++
		default:
			return deliveries
		}
	}
}

type seatbeltPTYPaths struct {
	ready, received, snapshot, observed, harnessObserved, diagnostic, observation, scannerStarted, ptyOutput string
}

func seatbeltNativePTYPaths(root string) seatbeltPTYPaths {
	base := filepath.Join(root, "sessions", "session-one")
	return seatbeltPTYPaths{
		ready: filepath.Join(base, "terminal-signal-ready"), received: filepath.Join(base, "terminal-signal-received"),
		snapshot: filepath.Join(base, "terminal-signal-snapshot"), observed: filepath.Join(base, "terminal-signal-observed"),
		harnessObserved: filepath.Join(base, "harness-terminal-signal-observed"), diagnostic: filepath.Join(base, "terminal-input-diagnostic"),
		observation: filepath.Join(base, "terminal-input-observation"), scannerStarted: filepath.Join(base, "terminal-scanner-started"),
		ptyOutput: filepath.Join(root, "harness-pty-output.log"),
	}
}

func seatbeltNativePTYRequest(root string) (validatedProcessRequest, error) {
	workspace := filepath.Join(root, "home", "workspace")
	session := filepath.Join(root, "sessions", "session-one")
	home := filepath.Join(session, "home")
	temporary := filepath.Join(session, "tmp")
	for _, directory := range []string{workspace, home, temporary} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return validatedProcessRequest{}, err
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return validatedProcessRequest{}, err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return validatedProcessRequest{}, err
	}
	environment, err := buildProcessEnvironment(home, temporary, []string{"TERM=xterm-256color"})
	if err != nil {
		return validatedProcessRequest{}, err
	}
	return validatedProcessRequest{
		workspace: workspace, sessionsDirectory: filepath.Dir(session), sessionDirectory: session,
		sessionHome: home, temporaryDirectory: temporary, executable: executable, environment: environment,
	}, nil
}

func seatbeltPTYTargetArguments() []string {
	for index, argument := range os.Args {
		if argument == "--" {
			arguments := os.Args[index+1:]
			if len(arguments) == 8 {
				return arguments
			}
			break
		}
	}
	return nil
}

func assertSeatbeltPTYForegroundTarget(t *testing.T, terminal *os.File, targetGroup int) {
	t.Helper()
	foregroundGroup, err := unix.IoctlGetInt(int(terminal.Fd()), unix.TIOCGPGRP)
	if err != nil {
		t.Fatal(err)
	}
	if foregroundGroup != targetGroup || foregroundGroup == syscall.Getpgrp() {
		t.Fatalf("terminal foreground group = %d, target = %d, harness = %d; want only the contained target", foregroundGroup, targetGroup, syscall.Getpgrp())
	}
}

func publishSeatbeltPTYReady(path string, processGroup int, beforeRename func(string)) (result error) {
	if processGroup <= 0 {
		return errors.New("invalid ready process group")
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".terminal-ready-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(temporary, "%d\n", processGroup); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if beforeRename != nil {
		beforeRename(temporaryPath)
	}
	return os.Rename(temporaryPath, path)
}

func readSeatbeltPTYReady(path string) (int, bool, error) {
	contents, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	group, err := strconv.Atoi(strings.TrimSpace(string(contents)))
	if err != nil || group <= 0 {
		return 0, false, nil
	}
	return group, true, nil
}

func waitForSeatbeltPTYReady(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		group, published, err := readSeatbeltPTYReady(path)
		if err != nil {
			t.Fatal(err)
		}
		if published {
			return group
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for valid Seatbelt terminal ready publication; raw=%q", readSeatbeltPTYFile(path))
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForSeatbeltPTYReadyWithDiagnostics(t *testing.T, path string, commandDone <-chan error, master *os.File, paths seatbeltPTYPaths) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		group, published, err := readSeatbeltPTYReady(path)
		if err != nil {
			t.Fatal(err)
		}
		if published {
			return group
		}
		select {
		case err := <-commandDone:
			t.Fatalf("native PTY harness exited before valid ready publication: %v; raw-ready=%q; %s", err, readSeatbeltPTYFile(path), seatbeltPTYFailureDiagnostics(master, paths))
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for valid Seatbelt terminal ready publication; raw-ready=%q; %s", readSeatbeltPTYFile(path), seatbeltPTYFailureDiagnostics(master, paths))
		}
		time.Sleep(time.Millisecond)
	}
}

func readSeatbeltPTYFile(path string) []byte {
	contents, _ := os.ReadFile(path)
	return contents
}

func drainSeatbeltPTYOutput(master, output *os.File, cancel <-chan struct{}) error {
	descriptor := int(master.Fd())
	buffer := make([]byte, 4096)
	for {
		select {
		case <-cancel:
			return nil
		default:
		}
		count, err := unix.Read(descriptor, buffer)
		if count > 0 {
			if _, writeErr := output.Write(buffer[:count]); writeErr != nil {
				return writeErr
			}
		}
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			select {
			case <-cancel:
				return nil
			case <-time.After(10 * time.Millisecond):
				continue
			}
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if count == 0 {
			return nil
		}
	}
}

func writeSeatbeltPTYMaster(master *os.File, contents []byte) error {
	deadline := time.Now().Add(5 * time.Second)
	for len(contents) != 0 {
		count, err := unix.Write(int(master.Fd()), contents)
		if count > 0 {
			contents = contents[count:]
		}
		if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
			if time.Now().After(deadline) {
				return errors.New("timed out writing native PTY input")
			}
			time.Sleep(time.Millisecond)
			continue
		}
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func assertSeatbeltPTYForegroundRestored(t *testing.T, terminal *os.File) {
	t.Helper()
	foregroundGroup, err := unix.IoctlGetInt(int(terminal.Fd()), unix.TIOCGPGRP)
	if err != nil {
		t.Fatal(err)
	}
	if foregroundGroup != syscall.Getpgrp() {
		t.Fatalf("terminal foreground group after native cleanup = %d, want harness group %d", foregroundGroup, syscall.Getpgrp())
	}
}

func waitForSeatbeltPTYMarker(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			diagnostic, err := os.ReadFile(filepath.Join(filepath.Dir(path), "terminal-input-diagnostic"))
			if err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			t.Fatalf("timed out waiting for Seatbelt terminal marker %q; input diagnostic=%q", filepath.Base(path), diagnostic)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForSeatbeltPTYMarkerWithDiagnostics(t *testing.T, path string, commandDone <-chan error, master *os.File, paths seatbeltPTYPaths) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		select {
		case err := <-commandDone:
			t.Fatalf("native PTY harness exited before marker %q: %v; %s", filepath.Base(path), err, seatbeltPTYFailureDiagnostics(master, paths))
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for Seatbelt terminal marker %q; %s", filepath.Base(path), seatbeltPTYFailureDiagnostics(master, paths))
		}
		time.Sleep(time.Millisecond)
	}
}

func seatbeltPTYFailureDiagnostics(master *os.File, paths seatbeltPTYPaths) string {
	diagnostic, _ := os.ReadFile(paths.diagnostic)
	observation, _ := os.ReadFile(paths.observation)
	output, _ := os.ReadFile(paths.ptyOutput)
	return fmt.Sprintf("parent-terminal=(%s); input-diagnostic=%q; input-observation=%q; drained-pty-output=%q",
		seatbeltPTYTerminalObservation(master), diagnostic, observation, output)
}

func seatbeltPTYTerminalObservation(terminal *os.File) string {
	foreground, foregroundErr := unix.IoctlGetInt(int(terminal.Fd()), unix.TIOCGPGRP)
	settings, settingsErr := unix.IoctlGetTermios(int(terminal.Fd()), unix.TIOCGETA)
	if settingsErr != nil {
		return fmt.Sprintf("foreground=%d foreground-error=%v termios-error=%v", foreground, foregroundErr, settingsErr)
	}
	return fmt.Sprintf("foreground=%d foreground-error=%v pgrp=%d lflag=%#x iflag=%#x", foreground, foregroundErr, syscall.Getpgrp(), settings.Lflag, settings.Iflag)
}

func recordSeatbeltPTYObservation(path, observation string) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	_, _ = fmt.Fprintln(file, observation)
	_ = file.Close()
}

func waitSeatbeltNativePTYHarness(t *testing.T, command *exec.Cmd, wait <-chan error, master *os.File, paths seatbeltPTYPaths) {
	t.Helper()
	select {
	case err := <-wait:
		if err != nil {
			t.Fatalf("native PTY harness failed: %v; %s", err, seatbeltPTYFailureDiagnostics(master, paths))
		}
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		<-wait
		t.Fatalf("native PTY harness did not exit after target release; %s", seatbeltPTYFailureDiagnostics(master, paths))
	}
}

func TestSeatbeltCandidateMCPAmbientReadDenialWithAbsentAtPrepareAndAliases(t *testing.T) {
	if os.Getenv("ACS_RUN_MCP_AMBIENT_FEASIBILITY") != "1" {
		t.Skip("run through the explicit native MCP ambient feasibility gate")
	}
	skipSeatbeltNativeTestBinaryUnderRace(t)
	fixture := newSeatbeltMCPTestFixture(t)
	request := fixture.request
	request.workspaceAccess = WorkspaceAccessReadWrite
	configDir := filepath.Join(request.workspace, ".devin")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(configDir, "mcp_config.json")
	neighbor := filepath.Join(configDir, "ordinary.json")
	if err := os.WriteFile(neighbor, []byte("neighbor"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(configDir, "mcp_config.alias.json")
	hardlink := filepath.Join(configDir, "mcp_config.hardlink.json")
	if err := os.Symlink(config, symlink); err != nil {
		t.Fatal(err)
	}
	// The file is deliberately absent while the real backend prepares its policy.
	marker := filepath.Join(request.workspace, "ambient-read-observation.json")
	request.arguments = []string{"-test.run=^TestSeatbeltHelperProcess$", "--", "mcp-feasibility-read", config, symlink, hardlink, neighbor, marker}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	process, err := seatbeltCandidateMCPDenySandbox(t, []string{config}, nil).Prepare(ctx, processRequestFromValidated(request))
	if err != nil {
		t.Fatalf("prepare real Seatbelt process: %v", err)
	}
	if err := os.WriteFile(config, []byte("created-after-prepare"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(config, hardlink); err != nil {
		t.Fatal(err)
	}
	configInfo, err := os.Stat(config)
	if err != nil {
		t.Fatalf("stat ambient config source: %v", err)
	}
	hardlinkInfo, err := os.Stat(hardlink)
	if err != nil || !os.SameFile(configInfo, hardlinkInfo) {
		t.Fatalf("hardlink alias does not identify the ambient config inode: %v", err)
	}
	fixture.started = true
	if err := process.Start(); err != nil {
		settleSeatbeltCandidateStartFailure(t, process, fixture)
		t.Fatalf("start real Seatbelt process: %v", err)
	}
	waitSeatbeltCandidateProcess(t, process, fixture)
	var observed []struct {
		Path             string `json:"path"`
		Read             string `json:"read"`
		PermissionDenied bool   `json:"permissionDenied"`
	}
	contents, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read parent-observed marker: %v", err)
	}
	if err := json.Unmarshal(contents, &observed); err != nil {
		t.Fatalf("decode marker: %v", err)
	}
	if len(observed) != 4 {
		t.Fatalf("observations = %#v", observed)
	}
	if !observed[0].PermissionDenied || observed[0].Read != "" {
		t.Fatalf("canonical ambient config read was not denied: %+v", observed[0])
	}
	if !observed[1].PermissionDenied || observed[1].Read != "" {
		t.Errorf("symlink alias bypassed the exact-path denial: %+v", observed[1])
	}
	if observed[2].PermissionDenied || observed[2].Read != "created-after-prepare" {
		t.Fatalf("hardlink limitation changed: observed=%+v want readable original bytes", observed[2])
	}
	t.Logf("measured limitation: exact-path denial permits reading the verified hardlink alias; bytes=%q", observed[2].Read)
	if observed[3].PermissionDenied || observed[3].Read != "neighbor" {
		t.Fatalf("neighbor read changed: %+v", observed[3])
	}
}

func TestSeatbeltCandidatePinnedDevinUsesSelectedHomeMCPConfigOnly(t *testing.T) {
	if os.Getenv("ACS_RUN_MCP_AMBIENT_FEASIBILITY") != "1" {
		t.Skip("run through the checksum-locked native MCP ambient feasibility gate")
	}
	skipSeatbeltNativeTestBinaryUnderRace(t)
	binary := os.Getenv("ACS_TEST_DEVIN_BINARY")
	if binary == "" {
		t.Fatal("native MCP feasibility requires the checksum-locked Devin binary")
	}
	binaryInfo, err := os.Lstat(binary)
	if err != nil || !binaryInfo.Mode().IsRegular() || binaryInfo.Mode()&0111 == 0 {
		t.Fatal("checksum-locked Devin target is unavailable or unsafe")
	}

	selected := seatbeltCandidateDevinConfig(t, "acs-selected-feasibility")
	projectDecoy := seatbeltCandidateDevinConfig(t, "acs-project-ambient-decoy")
	localDecoy := seatbeltCandidateDevinConfig(t, "acs-local-ambient-decoy")
	makeFixture := func() (*seatbeltMCPTestFixture, ProcessRequest, string, string) {
		t.Helper()
		fixture := newSeatbeltMCPTestFixture(t)
		request := fixture.request
		request.workspaceAccess = WorkspaceAccessReadWrite
		projectConfig := filepath.Join(request.workspace, ".devin", "mcp_config.json")
		localConfig := filepath.Join(request.workspace, ".devin", "mcp_config.local.json")
		userConfig := filepath.Join(request.sessionHome, ".config", "devin", "mcp_config.json")
		if err := os.MkdirAll(filepath.Dir(userConfig), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(userConfig, selected, 0o600); err != nil {
			t.Fatal(err)
		}
		for _, item := range []struct {
			path string
			data []byte
		}{{projectConfig, projectDecoy}, {localConfig, localDecoy}} {
			if err := os.MkdirAll(filepath.Dir(item.path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(item.path, item.data, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		processRequest := ProcessRequest{
			Workspace: request.workspace, WorkspaceAccess: WorkspaceAccessReadWrite,
			SessionsDirectory: request.sessionsDirectory, SessionDirectory: request.sessionDirectory,
			SessionHome: request.sessionHome, TemporaryDirectory: request.temporaryDirectory,
			Executable: binary, RuntimeAuthority: DefaultRuntimeAuthority(), Arguments: []string{"mcp", "list"},
		}
		return fixture, processRequest, projectConfig, localConfig
	}
	runList := func(fixture *seatbeltMCPTestFixture, processRequest ProcessRequest, label string, sandbox ProcessSandbox) string {
		t.Helper()
		var output bytes.Buffer
		processRequest.Terminal = Terminal{Output: &output, ErrorOutput: &output}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		process, err := sandbox.Prepare(ctx, processRequest)
		if err != nil {
			t.Fatalf("prepare pinned Devin mcp list %s: %v", label, err)
		}
		fixture.settled = false
		fixture.started = true
		if err := process.Start(); err != nil {
			settleSeatbeltCandidateStartFailure(t, process, fixture)
			t.Fatalf("start pinned Devin mcp list %s: %v", label, err)
		}
		waitSeatbeltCandidateProcess(t, process, fixture)
		return output.String()
	}
	// Paired fresh fixtures prove these exact roots are discovered under the
	// unmodified production backend before measuring the candidate denial.
	baselineFixture, baselineRequest, _, _ := makeFixture()
	baseline := runList(baselineFixture, baselineRequest, "without candidate denial", NewProcessSandbox())
	for _, expected := range []string{"acs-selected-feasibility", "acs-project-ambient-decoy", "acs-local-ambient-decoy"} {
		if !strings.Contains(baseline, expected) {
			t.Fatalf("pinned Devin baseline did not load fixture entry %q: %q", expected, baseline)
		}
	}
	deniedFixture, deniedRequest, projectConfig, localConfig := makeFixture()
	result := runList(deniedFixture, deniedRequest, "under candidate denial", seatbeltCandidateMCPDenySandbox(t, []string{projectConfig, localConfig}, nil))
	afterInfo, err := os.Lstat(binary)
	if err != nil || !os.SameFile(binaryInfo, afterInfo) || binaryInfo.Size() != afterInfo.Size() || !binaryInfo.ModTime().Equal(afterInfo.ModTime()) {
		t.Fatal("pinned Devin identity changed during native config observation")
	}
	if !strings.Contains(result, "acs-selected-feasibility") {
		t.Fatalf("selected user projection was not usable: %q", result)
	}
	for _, ambient := range []string{"acs-project-ambient-decoy", "acs-local-ambient-decoy"} {
		if strings.Contains(result, ambient) {
			t.Errorf("ambient Devin MCP entry loaded despite candidate denial: %q", ambient)
		}
	}
}

func TestSeatbeltCandidatePinnedDevinConfigPathReplacementIsolation(t *testing.T) {
	if os.Getenv("ACS_RUN_MCP_AMBIENT_FEASIBILITY") != "1" {
		t.Skip("run through the checksum-locked native MCP ambient feasibility gate")
	}
	skipSeatbeltNativeTestBinaryUnderRace(t)
	binary := os.Getenv("ACS_TEST_DEVIN_BINARY")
	if binary == "" {
		t.Fatal("native MCP feasibility requires the checksum-locked Devin binary")
	}
	binaryInfo, err := os.Lstat(binary)
	if err != nil || !binaryInfo.Mode().IsRegular() || binaryInfo.Mode()&0111 == 0 {
		t.Fatal("checksum-locked Devin target is unavailable or unsafe")
	}

	for _, root := range []string{"project", "local"} {
		for _, replacementKind := range []string{"symlink", "hardlink", "atomic-replacement"} {
			root, replacementKind := root, replacementKind
			t.Run(root+"/"+replacementKind, func(t *testing.T) {
				t.Run("baseline", func(t *testing.T) {
					runSeatbeltPinnedDevinReplacementCase(t, binary, root, replacementKind, false)
				})
				t.Run("candidate-denial", func(t *testing.T) {
					runSeatbeltPinnedDevinReplacementCase(t, binary, root, replacementKind, true)
				})
			})
		}
	}
	if afterInfo, err := os.Lstat(binary); err != nil || !os.SameFile(binaryInfo, afterInfo) || binaryInfo.Size() != afterInfo.Size() || !binaryInfo.ModTime().Equal(afterInfo.ModTime()) {
		t.Fatal("pinned Devin identity changed during config path replacement observation")
	}
}

type seatbeltDevinReplacementFixture struct {
	fixture         *seatbeltMCPTestFixture
	request         ProcessRequest
	configPath      string
	neighbor        string
	selectedName    string
	ambientName     string
	ambientContents []byte
}

func newSeatbeltDevinReplacementFixture(t *testing.T, binary, root, replacementKind string) seatbeltDevinReplacementFixture {
	t.Helper()
	selectedName := "acs-selected-replacement-control"
	ambientName := "acs-ambient-" + root + "-" + replacementKind
	selectedConfig := seatbeltCandidateDevinConfig(t, selectedName)
	ambientConfig := seatbeltCandidateDevinConfig(t, ambientName)
	fixture := newSeatbeltMCPTestFixture(t)
	validated := fixture.request
	validated.workspaceAccess = WorkspaceAccessReadWrite
	configRoot := validated.workspace
	configDir := filepath.Join(configRoot, ".devin")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	projectConfig := filepath.Join(configDir, "mcp_config.json")
	localConfig := filepath.Join(configDir, "mcp_config.local.json")
	configPath := projectConfig
	if root == "local" {
		configPath = localConfig
		if err := os.WriteFile(projectConfig, []byte(`{"mcpServers":{}}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(configPath, []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	userConfig := filepath.Join(validated.sessionHome, ".config", "devin", "mcp_config.json")
	if err := os.MkdirAll(filepath.Dir(userConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userConfig, selectedConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	neighbor := filepath.Join(configDir, "allowed-neighbor-"+replacementKind+".json")
	if err := os.WriteFile(neighbor, ambientConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	request := ProcessRequest{
		Workspace: validated.workspace, WorkspaceAccess: WorkspaceAccessReadWrite,
		SessionsDirectory: validated.sessionsDirectory, SessionDirectory: validated.sessionDirectory,
		SessionHome: validated.sessionHome, TemporaryDirectory: validated.temporaryDirectory,
		Executable: binary, RuntimeAuthority: DefaultRuntimeAuthority(), Arguments: []string{"mcp", "list"},
	}
	return seatbeltDevinReplacementFixture{fixture: fixture, request: request, configPath: configPath,
		neighbor: neighbor, selectedName: selectedName, ambientName: ambientName, ambientContents: ambientConfig}
}

func runSeatbeltPinnedDevinReplacementCase(t *testing.T, binary, root, replacementKind string, denied bool) {
	t.Helper()
	fixture := newSeatbeltDevinReplacementFixture(t, binary, root, replacementKind)
	sandbox := NewProcessSandbox()
	label := "baseline"
	if denied {
		label = "candidate denial"
		sandbox = seatbeltCandidateMCPDenySandbox(t, []string{fixture.configPath}, nil)
	}
	var output bytes.Buffer
	fixture.request.Terminal = Terminal{Output: &output, ErrorOutput: &output}
	targetContext, targetCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer targetCancel()
	targetProcess, err := sandbox.Prepare(targetContext, fixture.request)
	if err != nil {
		t.Fatalf("prepare pinned Devin %s: %v", label, err)
	}
	configIdentity := replaceSeatbeltDevinConfigAfterPrepare(t, fixture.configPath, fixture.neighbor, replacementKind, fixture.ambientContents)
	verifySeatbeltDevinReplacement(t, fixture.configPath, fixture.neighbor, configIdentity, fixture.ambientContents)

	// A separate child proves the allowed neighboring JSON remains readable
	// under the same production backend and exact-path candidate denial.
	marker := filepath.Join(fixture.fixture.request.workspace, "neighbor-read.json")
	validated := fixture.fixture.request
	validated.workspaceAccess = WorkspaceAccessReadWrite
	neighborRequest := processRequestFromValidated(validated)
	neighborRequest.Arguments = []string{"-test.run=^TestSeatbeltHelperProcess$", "--", "mcp-feasibility-read", fixture.neighbor, marker}
	neighborContext, neighborCancel := context.WithTimeout(context.Background(), 15*time.Second)
	neighborProcess, err := sandbox.Prepare(neighborContext, neighborRequest)
	if err != nil {
		neighborCancel()
		t.Fatalf("prepare neighboring-file control under %s: %v", label, err)
	}
	fixture.fixture.started = true
	fixture.fixture.settled = false
	if err := neighborProcess.Start(); err != nil {
		settleSeatbeltCandidateStartFailure(t, neighborProcess, fixture.fixture)
		neighborCancel()
		t.Fatalf("start neighboring-file control under %s: %v", label, err)
	}
	waitSeatbeltCandidateProcess(t, neighborProcess, fixture.fixture)
	neighborCancel()
	markerBytes, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read neighboring-file control receipt: %v", err)
	}
	var observations []struct {
		Read             string `json:"read"`
		PermissionDenied bool   `json:"permissionDenied"`
	}
	if err := json.Unmarshal(markerBytes, &observations); err != nil || len(observations) != 1 || observations[0].PermissionDenied || observations[0].Read != string(fixture.ambientContents) {
		t.Fatalf("neighbor was not readable under %s: %+v, %v", label, observations, err)
	}
	verifySeatbeltDevinReplacement(t, fixture.configPath, fixture.neighbor, configIdentity, fixture.ambientContents)

	fixture.fixture.settled = false
	if err := targetProcess.Start(); err != nil {
		settleSeatbeltCandidateStartFailure(t, targetProcess, fixture.fixture)
		t.Fatalf("start pinned Devin %s after config replacement: %v", label, err)
	}
	waitSeatbeltCandidateProcess(t, targetProcess, fixture.fixture)
	result := output.String()
	if denied {
		if !strings.Contains(result, fixture.selectedName) {
			t.Fatalf("selected user entry missing under %s: %q", label, result)
		}
		if strings.Contains(result, fixture.ambientName) {
			t.Fatalf("ambient entry survived %s: %q", label, result)
		}
	} else if !strings.Contains(result, fixture.selectedName) || !strings.Contains(result, fixture.ambientName) {
		t.Fatalf("baseline did not load selected and retargeted ambient entries: %q", result)
	}
	verifySeatbeltDevinReplacement(t, fixture.configPath, fixture.neighbor, configIdentity, fixture.ambientContents)
}

func replaceSeatbeltDevinConfigAfterPrepare(t *testing.T, configPath, neighbor, kind string, contents []byte) os.FileInfo {
	t.Helper()
	neighborBefore, err := os.Lstat(neighbor)
	if err != nil || !neighborBefore.Mode().IsRegular() {
		t.Fatalf("stat allowed neighbor before replacement: %v", err)
	}
	neighborBytes, err := os.ReadFile(neighbor)
	if err != nil || !bytes.Equal(neighborBytes, contents) {
		t.Fatalf("allowed neighbor bytes before replacement = %q, %v", neighborBytes, err)
	}
	switch kind {
	case "symlink", "hardlink":
		if err := os.Remove(configPath); err != nil {
			t.Fatal(err)
		}
		if kind == "symlink" {
			if err := os.Symlink(neighbor, configPath); err != nil {
				t.Fatal(err)
			}
		} else if err := os.Link(neighbor, configPath); err != nil {
			t.Fatal(err)
		}
	case "atomic-replacement":
		temporary := configPath + ".replacement"
		if err := os.WriteFile(temporary, contents, 0o600); err != nil {
			t.Fatal(err)
		}
		temporaryInfo, err := os.Lstat(temporary)
		if err != nil || !temporaryInfo.Mode().IsRegular() {
			t.Fatalf("stat atomic replacement temporary: %v", err)
		}
		if err := os.Rename(temporary, configPath); err != nil {
			t.Fatalf("atomically replace exact config pathname: %v", err)
		}
		replaced, err := os.Lstat(configPath)
		if err != nil || !os.SameFile(temporaryInfo, replaced) {
			t.Fatalf("atomic replacement did not install the prepared file identity: %v", err)
		}
	default:
		t.Fatalf("unknown config replacement kind %q", kind)
	}
	configInfo, err := os.Lstat(configPath)
	if err != nil {
		t.Fatalf("stat replaced config pathname: %v", err)
	}
	switch kind {
	case "symlink":
		if configInfo.Mode()&os.ModeSymlink == 0 {
			t.Fatal("replacement pathname is not a symlink")
		}
		target, err := os.Readlink(configPath)
		if err != nil || target != neighbor {
			t.Fatalf("symlink target = %q, %v", target, err)
		}
		targetInfo, err := os.Stat(configPath)
		if err != nil || !os.SameFile(neighborBefore, targetInfo) {
			t.Fatalf("symlink does not resolve to the allowed neighbor: %v", err)
		}
	case "hardlink":
		if !configInfo.Mode().IsRegular() || !os.SameFile(neighborBefore, configInfo) {
			t.Fatal("hardlink replacement is not the allowed neighbor inode")
		}
	case "atomic-replacement":
		if !configInfo.Mode().IsRegular() || os.SameFile(neighborBefore, configInfo) {
			t.Fatal("atomic replacement is not a distinct regular config file")
		}
	}
	verifySeatbeltDevinReplacement(t, configPath, neighbor, configInfo, contents)
	return configInfo
}

func verifySeatbeltDevinReplacement(t *testing.T, configPath, neighbor string, configIdentity os.FileInfo, contents []byte) {
	t.Helper()
	current, err := os.Lstat(configPath)
	if err != nil || !os.SameFile(configIdentity, current) {
		t.Fatalf("replaced config identity changed: %v", err)
	}
	actual, err := os.ReadFile(configPath)
	if err != nil || !bytes.Equal(actual, contents) {
		t.Fatalf("replaced config bytes = %q, %v", actual, err)
	}
	neighborInfo, err := os.Lstat(neighbor)
	if err != nil || !neighborInfo.Mode().IsRegular() {
		t.Fatalf("allowed neighboring config is unavailable: %v", err)
	}
	neighborBytes, err := os.ReadFile(neighbor)
	if err != nil || !bytes.Equal(neighborBytes, contents) {
		t.Fatalf("allowed neighbor bytes = %q, %v", neighborBytes, err)
	}
}

func TestSeatbeltCandidatePinnedDevinNestedDiscoveryGrantScope(t *testing.T) {
	if os.Getenv("ACS_RUN_MCP_AMBIENT_FEASIBILITY") != "1" {
		t.Skip("run through the checksum-locked native MCP ambient feasibility gate")
	}
	skipSeatbeltNativeTestBinaryUnderRace(t)
	binary := os.Getenv("ACS_TEST_DEVIN_BINARY")
	if binary == "" {
		t.Fatal("native MCP feasibility requires the checksum-locked Devin binary")
	}
	for _, gitMode := range []string{"non-git", "initialized-git"} {
		gitMode := gitMode
		t.Run(gitMode, func(t *testing.T) {
			var baselineLoaded []string
			t.Run("baseline", func(t *testing.T) {
				fixture := newSeatbeltDevinNestedDiscoveryFixture(t, binary, gitMode)
				output := runSeatbeltDevinTargetList(t, fixture.fixture, NewProcessSandbox(), fixture.request)
				baselineLoaded = loadedSeatbeltMCPNames(output, fixture.namePaths)
				t.Logf("nested %s fixture marker paths: %v", gitMode, fixture.namePaths)
				t.Logf("nested %s baseline loaded ambient IDs: %v", gitMode, baselineLoaded)
				if len(baselineLoaded) == 0 {
					t.Fatal("nested baseline did not load any measured ambient marker")
				}
				if !strings.Contains(output, fixture.selectedName) {
					t.Fatalf("selected HOME entry missing from nested %s baseline: %q", gitMode, output)
				}
				requiredIDs := []string{"acs-nested-cwd-project", "acs-nested-cwd-local"}
				if gitMode == "initialized-git" {
					requiredIDs = append(requiredIDs, "acs-nested-intermediate-project", "acs-nested-intermediate-local", "acs-nested-outer-project", "acs-nested-outer-local")
				}
				for _, required := range requiredIDs {
					if !strings.Contains(output, required) {
						t.Fatalf("nested %s baseline did not discover measured ancestor %s: %q", gitMode, required, output)
					}
				}
			})
			t.Run("candidate-denial", func(t *testing.T) {
				fixture := newSeatbeltDevinNestedDiscoveryFixture(t, binary, gitMode)
				denyPaths := make([]string, 0, len(baselineLoaded))
				for _, name := range baselineLoaded {
					denyPaths = append(denyPaths, fixture.namePaths[name])
				}
				if len(denyPaths) == 0 {
					for _, path := range fixture.namePaths {
						denyPaths = append(denyPaths, path)
					}
				}
				output := runSeatbeltDevinTargetList(t, fixture.fixture, seatbeltCandidateMCPDenySandbox(t, denyPaths, nil), fixture.request)
				candidateLoaded := loadedSeatbeltMCPNames(output, fixture.namePaths)
				t.Logf("nested %s candidate loaded ambient IDs: %v (baseline IDs: %v)", gitMode, candidateLoaded, baselineLoaded)
				if !strings.Contains(output, fixture.selectedName) {
					t.Fatalf("selected HOME entry missing under nested %s candidate denial: %q", gitMode, output)
				}
				if len(candidateLoaded) != 0 {
					t.Fatalf("ambient IDs survived nested %s candidate denial: candidate IDs=%v baseline IDs=%v: %q", gitMode, candidateLoaded, baselineLoaded, output)
				}
			})
		})
	}
}

func TestSeatbeltCandidatePinnedDevinDirectorySymlinkRedirection(t *testing.T) {
	if os.Getenv("ACS_RUN_MCP_AMBIENT_FEASIBILITY") != "1" {
		t.Skip("run through the checksum-locked native MCP ambient feasibility gate")
	}
	skipSeatbeltNativeTestBinaryUnderRace(t)
	binary := os.Getenv("ACS_TEST_DEVIN_BINARY")
	if binary == "" {
		t.Fatal("native MCP feasibility requires the checksum-locked Devin binary")
	}
	for _, denied := range []bool{false, true} {
		label := "baseline"
		if denied {
			label = "rejected-literal-path-limitation"
		}
		t.Run(label, func(t *testing.T) {
			fixture := newSeatbeltMCPTestFixture(t)
			validated := fixture.request
			validated.workspaceAccess = WorkspaceAccessReadWrite
			configDir := filepath.Join(validated.workspace, ".devin")
			if _, err := os.Lstat(configDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf(".devin must be absent at Prepare: %v", err)
			}
			selectedName := "acs-selected-directory-redirection"
			projectName := "acs-ambient-directory-project"
			localName := "acs-ambient-directory-local"
			selectedConfig := seatbeltCandidateDevinConfig(t, selectedName)
			userConfig := filepath.Join(validated.sessionHome, ".config", "devin", "mcp_config.json")
			if err := os.MkdirAll(filepath.Dir(userConfig), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(userConfig, selectedConfig, 0o600); err != nil {
				t.Fatal(err)
			}
			neighborDir := filepath.Join(validated.workspace, "allowed-neighbor-directory")
			if err := os.Mkdir(neighborDir, 0o700); err != nil {
				t.Fatal(err)
			}
			projectBytes := seatbeltCandidateDevinConfig(t, projectName)
			localBytes := seatbeltCandidateDevinConfig(t, localName)
			projectPath := filepath.Join(configDir, "mcp_config.json")
			localPath := filepath.Join(configDir, "mcp_config.local.json")
			candidatePaths := []string{projectPath, localPath}
			request := ProcessRequest{
				Workspace: validated.workspace, WorkspaceAccess: WorkspaceAccessReadWrite,
				SessionsDirectory: validated.sessionsDirectory, SessionDirectory: validated.sessionDirectory,
				SessionHome: validated.sessionHome, TemporaryDirectory: validated.temporaryDirectory,
				Executable: binary, RuntimeAuthority: DefaultRuntimeAuthority(), Arguments: []string{"mcp", "list"},
			}
			var sandbox ProcessSandbox = NewProcessSandbox()
			if denied {
				sandbox = seatbeltCandidateMCPDenySandbox(t, candidatePaths, nil)
			}
			var output bytes.Buffer
			request.Terminal = Terminal{Output: &output, ErrorOutput: &output}
			targetContext, targetCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer targetCancel()
			targetProcess, err := sandbox.Prepare(targetContext, request)
			if err != nil {
				t.Fatalf("prepare pinned Devin %s before .devin exists: %v", label, err)
			}

			if err := os.WriteFile(filepath.Join(neighborDir, "mcp_config.json"), projectBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(neighborDir, "mcp_config.local.json"), localBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(neighborDir, configDir); err != nil {
				t.Fatalf("redirect .devin to readable neighbor after Prepare: %v", err)
			}
			linkInfo, err := os.Lstat(configDir)
			if err != nil || linkInfo.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("stat .devin symlink: %v", err)
			}
			linkTarget, err := os.Readlink(configDir)
			if err != nil || linkTarget != neighborDir {
				t.Fatalf(".devin symlink target = %q, %v", linkTarget, err)
			}
			neighborInfo, err := os.Stat(configDir)
			if err != nil || !os.SameFile(neighborInfo, mustStatSeatbeltDir(t, neighborDir)) {
				t.Fatalf(".devin does not resolve to the prepared neighbor directory: %v", err)
			}
			for _, expected := range []struct {
				path string
				data []byte
			}{{filepath.Join(configDir, "mcp_config.json"), projectBytes}, {filepath.Join(configDir, "mcp_config.local.json"), localBytes}} {
				actual, readErr := os.ReadFile(expected.path)
				if readErr != nil || !bytes.Equal(actual, expected.data) {
					t.Fatalf("redirected config %s changed: %q, %v", expected.path, actual, readErr)
				}
			}
			// A helper child proves the neighboring directory remains readable
			// under the same backend even when exact project/local paths are denied.
			marker := filepath.Join(validated.workspace, "directory-neighbor-read.json")
			neighborRequest := processRequestFromValidated(validated)
			neighborRequest.Arguments = []string{"-test.run=^TestSeatbeltHelperProcess$", "--", "mcp-feasibility-read", filepath.Join(neighborDir, "mcp_config.json"), filepath.Join(neighborDir, "mcp_config.local.json"), marker}
			neighborRequest.Terminal = Terminal{Output: io.Discard, ErrorOutput: io.Discard}
			neighborContext, neighborCancel := context.WithTimeout(context.Background(), 15*time.Second)
			neighborProcess, err := sandbox.Prepare(neighborContext, neighborRequest)
			if err != nil {
				neighborCancel()
				t.Fatalf("prepare neighboring-directory read control: %v", err)
			}
			fixture.started, fixture.settled = true, false
			if err := neighborProcess.Start(); err != nil {
				settleSeatbeltCandidateStartFailure(t, neighborProcess, fixture)
				neighborCancel()
				t.Fatalf("start neighboring-directory read control: %v", err)
			}
			waitSeatbeltCandidateProcess(t, neighborProcess, fixture)
			neighborCancel()
			markerBytes, err := os.ReadFile(marker)
			if err != nil {
				t.Fatalf("read neighboring-directory receipt: %v", err)
			}
			var observations []struct {
				Read             string `json:"read"`
				PermissionDenied bool   `json:"permissionDenied"`
			}
			if err := json.Unmarshal(markerBytes, &observations); err != nil || len(observations) != 2 || observations[0].PermissionDenied || observations[0].Read != string(projectBytes) || observations[1].PermissionDenied || observations[1].Read != string(localBytes) {
				t.Fatalf("neighbor configs were not both readable under %s: %+v, %v", label, observations, err)
			}
			fixture.settled = false
			if err := targetProcess.Start(); err != nil {
				settleSeatbeltCandidateStartFailure(t, targetProcess, fixture)
				t.Fatalf("start pinned Devin %s after .devin redirection: %v", label, err)
			}
			waitSeatbeltCandidateProcess(t, targetProcess, fixture)
			result := output.String()
			if !strings.Contains(result, selectedName) {
				t.Fatalf("selected user entry missing under %s: %q", label, result)
			}
			for _, ambient := range []string{projectName, localName} {
				if !strings.Contains(result, ambient) {
					t.Fatalf("%s did not load measured redirected ambient entry %s: %q", label, ambient, result)
				}
			}
			if denied {
				t.Logf("measured limitation: rejected literal-path policy still loads both redirected ambient entries; selected=%s project=%s local=%s", selectedName, projectName, localName)
			}
			t.Logf("pinned Devin %s receipt: %s", label, result)
		})
	}
}

func mustStatSeatbeltDir(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestSeatbeltCandidatePinnedDevinReservedConfigBasenames(t *testing.T) {
	if os.Getenv("ACS_RUN_MCP_AMBIENT_FEASIBILITY") != "1" {
		t.Skip("run through the checksum-locked native MCP ambient feasibility gate")
	}
	skipSeatbeltNativeTestBinaryUnderRace(t)
	binary := os.Getenv("ACS_TEST_DEVIN_BINARY")
	if binary == "" {
		t.Fatal("native MCP feasibility requires the checksum-locked Devin binary")
	}
	for _, form := range []string{"directory-symlink", "directory-and-file-symlinks", "case-insensitive-basename", "case-insensitive-file-symlinks"} {
		form := form
		t.Run(form, func(t *testing.T) {
			t.Run("baseline", func(t *testing.T) {
				runSeatbeltDevinReservedBasenameCase(t, binary, form, false)
			})
			t.Run("reserved-basename-candidate", func(t *testing.T) {
				runSeatbeltDevinReservedBasenameCase(t, binary, form, true)
			})
		})
	}
}

func runSeatbeltDevinReservedBasenameCase(t *testing.T, binary, form string, candidate bool) {
	t.Helper()
	fixture := newSeatbeltMCPTestFixture(t)
	validated := fixture.request
	validated.workspaceAccess = WorkspaceAccessReadWrite
	configDir := filepath.Join(validated.workspace, ".devin")
	if _, err := os.Lstat(configDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf(".devin must be absent at Prepare: %v", err)
	}
	selectedName := "acs-selected-reserved-basename"
	projectName := "acs-ambient-reserved-project"
	localName := "acs-ambient-reserved-local"
	selectedBytes := seatbeltCandidateDevinConfig(t, selectedName)
	projectBytes := seatbeltCandidateDevinConfig(t, projectName)
	localBytes := seatbeltCandidateDevinConfig(t, localName)
	selectedConfig := filepath.Join(validated.sessionHome, ".config", "devin", "mcp_config.json")
	selectedConfigDir := filepath.Dir(selectedConfig)
	if err := os.MkdirAll(selectedConfigDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(selectedConfig, selectedBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	selectedIdentity, err := os.Lstat(selectedConfig)
	if err != nil || !selectedIdentity.Mode().IsRegular() {
		t.Fatalf("stat selected HOME config before Prepare: %v", err)
	}
	selectedConfigParent := filepath.Dir(selectedConfigDir)
	selectedDirs := []string{validated.sessionsDirectory, validated.sessionDirectory, validated.sessionHome, selectedConfigParent, selectedConfigDir}
	selectedDirIdentities := make(map[string]os.FileInfo, len(selectedDirs))
	for _, path := range selectedDirs {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			t.Fatalf("stat selected config ancestor %q before Prepare: %v", path, statErr)
		}
		selectedDirIdentities[path] = info
	}
	neighborDir := filepath.Join(validated.workspace, "allowed-neighbor-directory")
	if err := os.Mkdir(neighborDir, 0o700); err != nil {
		t.Fatal(err)
	}
	caseInsensitiveEntries := form == "case-insensitive-basename"
	caseInsensitiveFileSymlinks := form == "case-insensitive-file-symlinks"
	ordinaryProject := filepath.Join(neighborDir, "ordinary-project.json")
	ordinaryLocal := filepath.Join(neighborDir, "ordinary-local.json")
	ordinaryJSON := filepath.Join(neighborDir, "ordinary.json")
	nearReservedName := filepath.Join(neighborDir, "mcp_configXjson")
	ordinaryWorkspace := filepath.Join(validated.workspace, "ordinary-workspace.txt")
	rulesPath := filepath.Join(configDir, "rules")
	reservedProject := filepath.Join(neighborDir, "mcp_config.json")
	reservedLocal := filepath.Join(neighborDir, "mcp_config.local.json")
	physicalProject := reservedProject
	physicalLocal := reservedLocal
	if caseInsensitiveEntries {
		physicalProject = filepath.Join(neighborDir, "MCP_CONFIG.JSON")
		physicalLocal = filepath.Join(neighborDir, "MCP_CONFIG.LOCAL.JSON")
	}
	if caseInsensitiveFileSymlinks {
		caseAliasTargetDir := filepath.Join(validated.workspace, "casefold-reserved-targets")
		if err := os.Mkdir(caseAliasTargetDir, 0o700); err != nil {
			t.Fatalf("create separate case-alias target directory: %v", err)
		}
		physicalProject = filepath.Join(caseAliasTargetDir, "MCP_CONFIG.JSON")
		physicalLocal = filepath.Join(caseAliasTargetDir, "MCP_CONFIG.LOCAL.JSON")
	}
	selectedWriteDenials := []seatbeltCandidateWriteDeny{
		{path: validated.sessionsDirectory},
		{path: validated.sessionDirectory},
		{path: validated.sessionHome},
		{path: selectedConfigParent},
		{path: selectedConfigDir, descendants: true},
	}
	var sandbox ProcessSandbox = NewProcessSandbox()
	if candidate {
		sandbox = seatbeltCandidateMCPBasenameDenySandbox(t, selectedConfig, selectedWriteDenials)
	}
	request := ProcessRequest{
		Workspace: validated.workspace, WorkspaceAccess: WorkspaceAccessReadWrite,
		SessionsDirectory: validated.sessionsDirectory, SessionDirectory: validated.sessionDirectory,
		SessionHome: validated.sessionHome, TemporaryDirectory: validated.temporaryDirectory,
		Executable: binary, RuntimeAuthority: DefaultRuntimeAuthority(), Arguments: []string{"mcp", "list"},
	}
	var output bytes.Buffer
	request.Terminal = Terminal{Output: &output, ErrorOutput: &output}
	targetContext, targetCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer targetCancel()
	targetProcess, err := sandbox.Prepare(targetContext, request)
	if err != nil {
		t.Fatalf("prepare pinned Devin %s before project config discovery: %v", form, err)
	}
	targetStarted := false
	defer func() {
		if targetStarted {
			return
		}
		fixture.started, fixture.settled = true, false
		if startErr := targetProcess.Start(); startErr != nil {
			settleSeatbeltCandidateStartFailure(t, targetProcess, fixture)
			t.Errorf("settle prepared pinned Devin after an earlier fixture failure: %v", startErr)
			return
		}
		targetStarted = true
		waitSeatbeltCandidateProcess(t, targetProcess, fixture)
	}()

	if form == "directory-and-file-symlinks" || caseInsensitiveFileSymlinks {
		if err := os.WriteFile(ordinaryProject, projectBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ordinaryLocal, localBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		projectTarget, localTarget := ordinaryProject, ordinaryLocal
		if caseInsensitiveFileSymlinks {
			projectTarget, localTarget = physicalProject, physicalLocal
			if err := os.WriteFile(physicalProject, projectBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(physicalLocal, localBytes, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Symlink(projectTarget, reservedProject); err != nil {
			t.Fatalf("create project config-file symlink after Prepare: %v", err)
		}
		if err := os.Symlink(localTarget, reservedLocal); err != nil {
			t.Fatalf("create local config-file symlink after Prepare: %v", err)
		}
	} else {
		if err := os.WriteFile(ordinaryProject, projectBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(ordinaryLocal, localBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(physicalProject, projectBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(physicalLocal, localBytes, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, item := range []struct {
		path string
		data []byte
	}{{ordinaryJSON, []byte("ordinary neighbor JSON")}, {nearReservedName, []byte("near reserved basename")}, {ordinaryWorkspace, []byte("ordinary workspace content")}, {filepath.Join(neighborDir, "rules"), []byte("ordinary inherited Devin rule")}} {
		if err := os.WriteFile(item.path, item.data, 0o600); err != nil {
			t.Fatalf("write control file %s after Prepare: %v", item.path, err)
		}
	}
	neighborIdentity, err := os.Lstat(neighborDir)
	if err != nil || !neighborIdentity.IsDir() {
		t.Fatalf("stat readable neighboring directory before redirection: %v", err)
	}
	projectInfo, err := os.Lstat(reservedProject)
	if err != nil {
		t.Fatalf("stat project entry before directory redirection: %v", err)
	}
	localInfo, err := os.Lstat(reservedLocal)
	if err != nil {
		t.Fatalf("stat local entry before directory redirection: %v", err)
	}
	if form == "directory-and-file-symlinks" || caseInsensitiveFileSymlinks {
		projectTarget, localTarget := ordinaryProject, ordinaryLocal
		if caseInsensitiveFileSymlinks {
			projectTarget, localTarget = physicalProject, physicalLocal
		}
		for _, link := range []struct{ path, target string }{{reservedProject, projectTarget}, {reservedLocal, localTarget}} {
			linkInfo, statErr := os.Lstat(link.path)
			linkTarget, readErr := os.Readlink(link.path)
			resolvedInfo, resolveErr := os.Stat(link.path)
			wantInfo := mustStatSeatbeltDir(t, link.target)
			if statErr != nil || linkInfo.Mode()&os.ModeSymlink == 0 || readErr != nil || linkTarget != link.target || resolveErr != nil || !os.SameFile(wantInfo, resolvedInfo) {
				t.Fatalf("file redirection receipt for %s: lstat=%v target=%q readlink=%v stat=%v", link.path, statErr, linkTarget, readErr, resolveErr)
			}
		}
	} else {
		for _, item := range []struct {
			path string
			data []byte
		}{{reservedProject, projectBytes}, {reservedLocal, localBytes}} {
			actual, readErr := os.ReadFile(item.path)
			if readErr != nil || !bytes.Equal(actual, item.data) {
				t.Fatalf("regular reserved config %s bytes = %q, %v", item.path, actual, readErr)
			}
		}
	}
	if caseInsensitiveEntries {
		entries, readErr := os.ReadDir(neighborDir)
		if readErr != nil {
			t.Fatalf("read case-insensitive fixture directory entries: %v", readErr)
		}
		spelling := map[string]bool{}
		for _, entry := range entries {
			spelling[entry.Name()] = true
		}
		if !spelling["MCP_CONFIG.JSON"] || !spelling["MCP_CONFIG.LOCAL.JSON"] {
			t.Fatalf("uppercase reserved directory-entry spellings missing: %v", spelling)
		}
		for _, item := range []struct{ actual, canonical string }{{physicalProject, reservedProject}, {physicalLocal, reservedLocal}} {
			actualInfo, actualErr := os.Lstat(item.actual)
			canonicalInfo, canonicalErr := os.Lstat(item.canonical)
			if actualErr != nil || canonicalErr != nil || !os.SameFile(actualInfo, canonicalInfo) {
				t.Fatalf("case-insensitive APFS alias is not physically verified: actual=%s (%v) canonical=%s (%v)", item.actual, actualErr, item.canonical, canonicalErr)
			}
		}
	}
	if caseInsensitiveFileSymlinks {
		entries, readErr := os.ReadDir(filepath.Dir(physicalProject))
		if readErr != nil {
			t.Fatalf("read uppercase reserved-target directory entries: %v", readErr)
		}
		spelling := map[string]bool{}
		for _, entry := range entries {
			spelling[entry.Name()] = true
		}
		if !spelling["MCP_CONFIG.JSON"] || !spelling["MCP_CONFIG.LOCAL.JSON"] {
			t.Fatalf("uppercase reserved target spellings missing: %v", spelling)
		}
		for _, item := range []struct{ link string }{{reservedProject}, {reservedLocal}} {
			actual := physicalProject
			if item.link == reservedLocal {
				actual = physicalLocal
			}
			actualInfo, actualErr := os.Stat(actual)
			canonicalInfo, canonicalErr := os.Stat(item.link)
			if actualErr != nil || canonicalErr != nil || !os.SameFile(actualInfo, canonicalInfo) {
				t.Fatalf("uppercase reserved config symlink target is not physically verified: alias=%s actual=%s (%v) target=%v", item.link, actual, actualErr, canonicalErr)
			}
		}
	}
	if err := os.Symlink(neighborDir, configDir); err != nil {
		t.Fatalf("redirect .devin after Prepare: %v", err)
	}
	configLinkInfo, err := os.Lstat(configDir)
	if err != nil || configLinkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("stat .devin symlink: %v", err)
	}
	configLinkTarget, err := os.Readlink(configDir)
	if err != nil || configLinkTarget != neighborDir {
		t.Fatalf(".devin symlink target = %q, %v", configLinkTarget, err)
	}
	resolvedDir, err := os.Stat(configDir)
	if err != nil || !os.SameFile(neighborIdentity, resolvedDir) {
		t.Fatalf(".devin does not resolve to the prepared neighbor identity: %v", err)
	}
	verifyReservedConfigEntries := func() {
		t.Helper()
		currentConfigLink, linkStatErr := os.Lstat(configDir)
		currentLinkTarget, linkReadErr := os.Readlink(configDir)
		currentNeighbor, neighborStatErr := os.Stat(configDir)
		if linkStatErr != nil || !os.SameFile(configLinkInfo, currentConfigLink) || linkReadErr != nil || currentLinkTarget != neighborDir || neighborStatErr != nil || !os.SameFile(neighborIdentity, currentNeighbor) {
			t.Fatalf(".devin directory redirection changed: lstat=%v target=%q readlink=%v stat=%v", linkStatErr, currentLinkTarget, linkReadErr, neighborStatErr)
		}
		for _, expected := range []struct {
			path string
			info os.FileInfo
			data []byte
		}{{reservedProject, projectInfo, projectBytes}, {reservedLocal, localInfo, localBytes}} {
			current, statErr := os.Lstat(expected.path)
			actual, readErr := os.ReadFile(expected.path)
			if statErr != nil || !os.SameFile(expected.info, current) || readErr != nil || !bytes.Equal(actual, expected.data) {
				t.Fatalf("reserved entry %s changed after retarget: stat=%v read=%v bytes=%q", expected.path, statErr, readErr, actual)
			}
			redirected := filepath.Join(configDir, filepath.Base(expected.path))
			actual, readErr = os.ReadFile(redirected)
			if readErr != nil || !bytes.Equal(actual, expected.data) {
				t.Fatalf("discovered entry %s changed after retarget: %q, %v", redirected, actual, readErr)
			}
		}
		for path, identity := range selectedDirIdentities {
			current, statErr := os.Lstat(path)
			if statErr != nil || !os.SameFile(identity, current) {
				t.Fatalf("selected config ancestor identity changed for %s: %v", path, statErr)
			}
		}
		current, statErr := os.Lstat(selectedConfig)
		actual, readErr := os.ReadFile(selectedConfig)
		if statErr != nil || !os.SameFile(selectedIdentity, current) || readErr != nil || !bytes.Equal(actual, selectedBytes) {
			t.Fatalf("selected config identity/bytes changed: stat=%v read=%v bytes=%q", statErr, readErr, actual)
		}
	}
	verifyReservedConfigEntries()

	runReadControls := func() {
		t.Helper()
		if !candidate {
			return
		}
		marker := filepath.Join(validated.workspace, "reserved-basename-control.json")
		controlRequest := processRequestFromValidated(validated)
		controlRequest.Arguments = []string{"-test.run=^TestSeatbeltHelperProcess$", "--", "mcp-feasibility-read", ordinaryJSON, nearReservedName, ordinaryProject, ordinaryLocal, ordinaryWorkspace, rulesPath, reservedProject, reservedLocal, physicalProject, physicalLocal, marker}
		controlContext, controlCancel := context.WithTimeout(context.Background(), 15*time.Second)
		controlProcess, err := sandbox.Prepare(controlContext, controlRequest)
		if err != nil {
			controlCancel()
			t.Fatalf("prepare reserved-name and ordinary-read controls: %v", err)
		}
		fixture.started, fixture.settled = true, false
		if err := controlProcess.Start(); err != nil {
			settleSeatbeltCandidateStartFailure(t, controlProcess, fixture)
			controlCancel()
			t.Fatalf("start reserved-name and ordinary-read controls: %v", err)
		}
		waitSeatbeltCandidateProcess(t, controlProcess, fixture)
		controlCancel()
		markerBytes, err := os.ReadFile(marker)
		if err != nil {
			t.Fatalf("read reserved basename control marker: %v", err)
		}
		var observations []struct {
			Read             string `json:"read"`
			PermissionDenied bool   `json:"permissionDenied"`
		}
		if err := json.Unmarshal(markerBytes, &observations); err != nil || len(observations) != 10 {
			t.Fatalf("decode reserved basename control: observations=%+v err=%v", observations, err)
		}
		wantReadable := []string{"ordinary neighbor JSON", "near reserved basename", string(projectBytes), string(localBytes), "ordinary workspace content", "ordinary inherited Devin rule"}
		for index, expected := range wantReadable {
			if observations[index].PermissionDenied || observations[index].Read != expected {
				t.Errorf("ordinary control %d was not readable: %+v want=%q", index, observations[index], expected)
			}
		}
		for index := 6; index < 10; index++ {
			if !observations[index].PermissionDenied || observations[index].Read != "" {
				t.Errorf("reserved-name neighbor control %d was not explicitly denied: %+v", index, observations[index])
			}
		}
	}

	verifyReservedConfigEntries()
	fixture.started = true
	fixture.settled = false
	if err := targetProcess.Start(); err != nil {
		targetStarted = true
		settleSeatbeltCandidateStartFailure(t, targetProcess, fixture)
		t.Fatalf("start pinned Devin %s after directory and file retarget: %v", form, err)
	}
	targetStarted = true
	waitSeatbeltCandidateProcess(t, targetProcess, fixture)
	result := output.String()
	if !strings.Contains(result, selectedName) {
		t.Errorf("selected HOME projection missing from %s (candidate=%v): %q", form, candidate, result)
	}
	t.Logf("pinned Devin case receipt: form=%s candidate=%v lowercase-project=%s lowercase-local=%s uppercase-project=%s uppercase-local=%s output=%q", form, candidate, reservedProject, reservedLocal, physicalProject, physicalLocal, result)
	for _, ambient := range []string{projectName, localName} {
		if candidate && strings.Contains(result, ambient) {
			t.Errorf("ambient entry %s survived reserved-basename candidate in %s: %q", ambient, form, result)
		}
		if !candidate && !strings.Contains(result, ambient) {
			t.Errorf("paired baseline did not load ambient entry %s in %s: %q", ambient, form, result)
		}
	}
	verifyReservedConfigEntries()
	runReadControls()
	verifyReservedConfigEntries()
}

type seatbeltDevinNestedDiscoveryFixture struct {
	fixture      *seatbeltMCPTestFixture
	request      ProcessRequest
	selectedName string
	namePaths    map[string]string
}

func newSeatbeltDevinNestedDiscoveryFixture(t *testing.T, binary, gitMode string) seatbeltDevinNestedDiscoveryFixture {
	t.Helper()
	userHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	fixture := newSeatbeltMCPTestFixtureUnder(t, userHome)
	validated := fixture.request
	workspaceRoot := validated.workspace
	grantRoot := filepath.Dir(workspaceRoot)
	nested := filepath.Join(workspaceRoot, "nested", "child")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	if gitMode == "initialized-git" {
		output, err := exec.Command("git", "init", "--quiet", workspaceRoot).CombinedOutput()
		if err != nil {
			t.Fatalf("initialize synthetic Git root: %v: %s", err, output)
		}
	} else {
		for _, path := range []string{filepath.Join(workspaceRoot, ".git"), filepath.Join(nested, ".git")} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("non-Git nested fixture unexpectedly contains %s: %v", path, err)
			}
		}
	}
	validated.workspace = nested
	validated.workspaceAccess = WorkspaceAccessReadWrite
	fixture.request.workspace = nested
	ancestorGrants, err := ResolveFilesystemGrants([]PathGrantIntent{{
		ID: "mcp-discovery-ancestor", Access: PathAccessReadOnly, Type: PathTypeDirectory,
		ReferenceKind: PathReferenceLocalAbsolute, Path: grantRoot,
	}}, nested, validated.sessionsDirectory, WorkspaceAccessReadWrite)
	if err != nil || len(ancestorGrants) != 1 || !ancestorGrants[0].effective {
		t.Fatalf("explicit readable ancestor grant is unavailable or ineffective: grants=%+v err=%v", ancestorGrants, err)
	}
	selectedName := "acs-nested-selected"
	selectedConfig := seatbeltCandidateDevinConfig(t, selectedName)
	userConfig := filepath.Join(validated.sessionHome, ".config", "devin", "mcp_config.json")
	if err := os.MkdirAll(filepath.Dir(userConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userConfig, selectedConfig, 0o600); err != nil {
		t.Fatal(err)
	}
	type discoveryRoot struct {
		name string
		path string
	}
	roots := []discoveryRoot{
		{name: "cwd", path: nested},
		{name: "intermediate", path: filepath.Dir(nested)},
		{name: "outer", path: workspaceRoot},
		{name: "above-git", path: grantRoot},
	}
	namePaths := make(map[string]string)
	for _, root := range roots {
		configDir := filepath.Join(root.path, ".devin")
		if err := os.MkdirAll(configDir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, config := range []struct {
			suffix string
			file   string
		}{{"project", "mcp_config.json"}, {"local", "mcp_config.local.json"}} {
			name := "acs-nested-" + root.name + "-" + config.suffix
			contents := seatbeltCandidateDevinConfig(t, name)
			path := filepath.Join(configDir, config.file)
			if err := os.WriteFile(path, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			namePaths[name] = path
		}
	}
	request := ProcessRequest{
		Workspace: nested, WorkspaceAccess: WorkspaceAccessReadWrite,
		SessionsDirectory: validated.sessionsDirectory, SessionDirectory: validated.sessionDirectory,
		SessionHome: validated.sessionHome, TemporaryDirectory: validated.temporaryDirectory,
		Executable: binary, RuntimeAuthority: DefaultRuntimeAuthority(), Arguments: []string{"mcp", "list"},
		FilesystemGrants: ancestorGrants,
	}
	return seatbeltDevinNestedDiscoveryFixture{fixture: fixture, request: request, selectedName: selectedName, namePaths: namePaths}
}

func loadedSeatbeltMCPNames(output string, namePaths map[string]string) []string {
	loaded := make([]string, 0, len(namePaths))
	for name := range namePaths {
		if strings.Contains(output, name) {
			loaded = append(loaded, name)
		}
	}
	sort.Strings(loaded)
	return loaded
}

func runSeatbeltDevinTargetList(t *testing.T, fixture *seatbeltMCPTestFixture, sandbox ProcessSandbox, request ProcessRequest) string {
	t.Helper()
	var output bytes.Buffer
	request.Terminal = Terminal{Output: &output, ErrorOutput: &output}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	process, err := sandbox.Prepare(ctx, request)
	if err != nil {
		t.Fatalf("prepare pinned Devin mcp list: %v", err)
	}
	fixture.started = true
	fixture.settled = false
	if err := process.Start(); err != nil {
		settleSeatbeltCandidateStartFailure(t, process, fixture)
		t.Fatalf("start pinned Devin mcp list: %v", err)
	}
	waitSeatbeltCandidateProcess(t, process, fixture)
	return output.String()
}

func TestSeatbeltCandidateMCPRecipeWriteAndAncestorDenialsPreserveOrdinaryHome(t *testing.T) {
	if os.Getenv("ACS_RUN_MCP_AMBIENT_FEASIBILITY") != "1" {
		t.Skip("run through the explicit native MCP ambient feasibility gate")
	}
	skipSeatbeltNativeTestBinaryUnderRace(t)
	// This bounded experiment protects the recipe file and each target-writable
	// directory ancestor (recipe directory, HOME, and Session root). Directory
	// truncation is not an OS operation; regular-file truncation is exercised.
	for _, kind := range []string{"ordinary-home-write", "overwrite", "truncate", "unlink", "rename-out", "atomic-replace", "rename-recipe-ancestor", "rename-home-ancestor", "rename-session-ancestor"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newSeatbeltMCPTestFixture(t)
			request := fixture.request
			request.workspaceAccess = WorkspaceAccessReadWrite
			recipeDir := filepath.Join(request.sessionHome, ".acs-mcp")
			if err := os.MkdirAll(recipeDir, 0o700); err != nil {
				t.Fatal(err)
			}
			recipe := filepath.Join(recipeDir, "recipe.json")
			original := []byte("immutable-recipe")
			if err := os.WriteFile(recipe, original, 0o600); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(request.workspace, "recipe-operation.json")
			request.arguments = []string{"-test.run=^TestSeatbeltHelperProcess$", "--", "mcp-feasibility-recipe-op", marker, kind, recipe, recipeDir, request.sessionHome, request.sessionDirectory}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			process, err := seatbeltCandidateMCPDenySandbox(t, nil, []seatbeltCandidateWriteDeny{{path: request.sessionDirectory}, {path: request.sessionHome}, {path: recipeDir, descendants: true}}).Prepare(ctx, processRequestFromValidated(request))
			if err != nil {
				t.Fatalf("prepare real Seatbelt process: %v", err)
			}
			before := make(map[string]os.FileInfo)
			for _, path := range []string{request.sessionDirectory, request.sessionHome, recipeDir, recipe} {
				info, statErr := os.Lstat(path)
				if statErr != nil {
					t.Fatalf("stat protected path before launch %q: %v", path, statErr)
				}
				before[path] = info
			}
			fixture.started = true
			if err := process.Start(); err != nil {
				settleSeatbeltCandidateStartFailure(t, process, fixture)
				t.Fatalf("start real Seatbelt process: %v", err)
			}
			waitSeatbeltCandidateProcess(t, process, fixture)
			var result struct {
				Operation              string
				PermissionDenied       bool
				Succeeded              bool
				PrepareSucceeded       bool
				RenamePermissionDenied bool
				RenameSucceeded        bool
			}
			markerBytes, err := os.ReadFile(marker)
			if err != nil {
				t.Fatalf("read marker after cleanup: %v", err)
			}
			if err := json.Unmarshal(markerBytes, &result); err != nil {
				t.Fatalf("decode operation receipt: %v", err)
			}
			if kind == "ordinary-home-write" {
				if !result.Succeeded || result.PermissionDenied {
					t.Fatalf("ordinary HOME write should be allowed: %+v", result)
				}
				if got, err := os.ReadFile(filepath.Join(request.sessionHome, "ordinary-home-write")); err != nil || string(got) != "allowed" {
					t.Fatalf("HOME write effect = %q, %v", got, err)
				}
			} else if kind == "atomic-replace" {
				if !result.PrepareSucceeded || !result.RenamePermissionDenied || result.RenameSucceeded {
					t.Fatalf("atomic replacement did not reach and deny the protected rename: %+v", result)
				}
			} else if kind == "rename-session-ancestor" {
				// This is a combined-boundary observation: the production Session
				// policy and candidate ancestor/destination restrictions both apply.
				if !result.PermissionDenied || result.Succeeded {
					t.Fatalf("Session ancestor rename was not denied: %+v", result)
				}
			} else if !result.PermissionDenied || result.Succeeded {
				t.Fatalf("protected recipe operation was not denied: %+v", result)
			}
			for path, identity := range before {
				after, statErr := os.Lstat(path)
				if statErr != nil || !os.SameFile(identity, after) {
					t.Errorf("protected path identity changed for %q: before=%v after=%v", path, identity, statErr)
					continue
				}
				if path == recipe {
					afterBytes, readErr := os.ReadFile(path)
					if readErr != nil || !bytes.Equal(afterBytes, original) {
						t.Errorf("recipe bytes changed after cleanup: %q %v", afterBytes, readErr)
					}
				}
			}
		})
	}
}

type seatbeltMCPTestFixture struct {
	request validatedProcessRequest
	root    string
	started bool
	settled bool
}

func newSeatbeltMCPTestFixture(t *testing.T) *seatbeltMCPTestFixture {
	return newSeatbeltMCPTestFixtureUnder(t, "/private/tmp")
}

func newSeatbeltMCPTestFixtureUnder(t *testing.T, parent string) *seatbeltMCPTestFixture {
	t.Helper()
	root, err := os.MkdirTemp(parent, "acs-seatbelt-mcp-")
	if err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(root, "home", "workspace")
	session := filepath.Join(root, "sessions", "session-one")
	home, temporary := filepath.Join(session, "home"), filepath.Join(session, "tmp")
	for _, directory := range []string{workspace, home, temporary} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			_ = os.RemoveAll(root)
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		_ = os.RemoveAll(root)
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		_ = os.RemoveAll(root)
		t.Fatal(err)
	}
	environment, err := buildProcessEnvironment(home, temporary, []string{"TERM=xterm-256color"})
	if err != nil {
		_ = os.RemoveAll(root)
		t.Fatal(err)
	}
	fixture := &seatbeltMCPTestFixture{root: root, request: validatedProcessRequest{
		workspace: workspace, workspaceAccess: WorkspaceAccessReadWrite,
		sessionsDirectory: filepath.Dir(session), sessionDirectory: session,
		sessionHome: home, temporaryDirectory: temporary, executable: executable, environment: environment,
	}}
	t.Cleanup(func() {
		if !fixture.started || fixture.settled {
			_ = os.RemoveAll(fixture.root)
			return
		}
		t.Logf("retaining unsettled native Seatbelt fixture at %s", fixture.root)
	})
	return fixture
}

func waitSeatbeltCandidateProcess(t *testing.T, process Process, fixture *seatbeltMCPTestFixture) {
	t.Helper()
	waitDone := make(chan error, 1)
	go func() { waitDone <- process.Wait() }()
	var waitErr error
	timedOut := false
	waitSettled := true
	select {
	case waitErr = <-waitDone:
	case <-time.After(10 * time.Second):
		timedOut = true
		waitSettled = false
		_ = process.Signal(syscall.SIGKILL)
		select {
		case waitErr = <-waitDone:
			waitSettled = true
		case <-time.After(5 * time.Second):
			// Still inspect CleanupDone below. Keep the fixture if Wait never
			// confirms that the process lifecycle has settled.
		}
	}
	requireSeatbeltCandidateCleanup(t, process)
	fixture.settled = waitSettled
	if timedOut {
		t.Fatal("Seatbelt fixture exceeded its 10 second bound after cleanup")
	}
	if waitErr != nil {
		t.Fatalf("bounded Seatbelt fixture failed after cleanup: %v", waitErr)
	}
}

func settleSeatbeltCandidateStartFailure(t *testing.T, process Process, fixture *seatbeltMCPTestFixture) {
	t.Helper()
	waitDone := make(chan error, 1)
	go func() { waitDone <- process.Wait() }()
	waitSettled := true
	select {
	case <-waitDone:
	case <-time.After(10 * time.Second):
		waitSettled = false
		_ = process.Signal(syscall.SIGKILL)
		select {
		case <-waitDone:
			waitSettled = true
		case <-time.After(5 * time.Second):
			// Still inspect CleanupDone below and retain the fixture unless
			// both lifecycle signals settle.
		}
	}
	requireSeatbeltCandidateCleanup(t, process)
	fixture.settled = waitSettled
	if !waitSettled {
		t.Fatal("Seatbelt Start failure did not settle after bounded kill; fixture retained")
	}
}

func seatbeltCandidateDevinConfig(t *testing.T, server string) []byte {
	t.Helper()
	contents, err := json.Marshal(map[string]any{"mcpServers": map[string]any{
		server: map[string]any{"command": "/usr/bin/true", "args": []string{}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func requireSeatbeltCandidateCleanup(t *testing.T, process Process) {
	t.Helper()
	cleanup, ok := process.(ProcessCleanup)
	if !ok {
		t.Fatal("real Seatbelt process lacks ProcessCleanup proof")
	}
	done := cleanup.CleanupDone()
	if done == nil {
		t.Fatal("real Seatbelt CleanupDone returned nil")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Seatbelt cleanup proof did not complete")
	}
}

func processRequestFromValidated(request validatedProcessRequest) ProcessRequest {
	return ProcessRequest{Workspace: request.workspace, WorkspaceAccess: request.workspaceAccess,
		SessionsDirectory: request.sessionsDirectory, SessionDirectory: request.sessionDirectory,
		SessionHome: request.sessionHome, TemporaryDirectory: request.temporaryDirectory,
		Executable: request.executable, RuntimeInputs: []string{request.executable}, RuntimeAuthority: DefaultRuntimeAuthority(),
		Arguments: request.arguments, Terminal: Terminal{Output: io.Discard, ErrorOutput: io.Discard}}
}

type seatbeltCandidateWriteDeny struct {
	path        string
	descendants bool
}

func seatbeltCandidateMCPDenySandbox(t *testing.T, readPaths []string, writePaths []seatbeltCandidateWriteDeny) ProcessSandbox {
	t.Helper()
	// Capture canonical intended paths when this candidate sandbox is built.
	// In retargeting experiments this happens before mutation, so subsequent
	// Prepare calls for the target and positive control share one fixed policy.
	canonicalReadPaths := make([]string, len(readPaths))
	for index, path := range readPaths {
		canonicalReadPaths[index] = canonicalSeatbeltCandidatePath(path)
	}
	canonicalWritePaths := make([]seatbeltCandidateWriteDeny, len(writePaths))
	for index, denied := range writePaths {
		denied.path = canonicalSeatbeltCandidatePath(denied.path)
		canonicalWritePaths[index] = denied
	}
	sandbox, ok := NewProcessSandbox().(*nativeProcessSandbox)
	if !ok {
		t.Fatalf("NewProcessSandbox() = %T, want production native sandbox", sandbox)
	}
	backend, ok := sandbox.backends["darwin"].(*seatbeltBackend)
	if !ok || backend == nil {
		t.Fatalf("production Darwin backend = %T", sandbox.backends["darwin"])
	}
	backend.policy = func(request validatedProcessRequest) (string, []string, error) {
		policy, definitions, err := buildSeatbeltPolicy(request)
		if err != nil {
			return "", nil, err
		}
		var rules strings.Builder
		for index, path := range canonicalReadPaths {
			name := "MCP_CANDIDATE_READ_DENY_" + strconv.Itoa(index)
			definitions = append(definitions, "-D"+name+"="+path)
			fmt.Fprintf(&rules, "\n(deny file-read* (literal (param %q)))", name)
		}
		for index, denied := range canonicalWritePaths {
			path := denied.path
			name := "MCP_CANDIDATE_WRITE_DENY_" + strconv.Itoa(index)
			definitions = append(definitions, "-D"+name+"="+path)
			fmt.Fprintf(&rules, "\n(deny file-write* (literal (param %q))", name)
			if denied.descendants {
				fmt.Fprintf(&rules, " (subpath (param %q))", name)
			}
			rules.WriteString(")")
		}
		return policy + rules.String(), definitions, nil
	}
	return sandbox
}

func seatbeltCandidateMCPBasenameDenySandbox(t *testing.T, selectedConfig string, writePaths []seatbeltCandidateWriteDeny) ProcessSandbox {
	t.Helper()
	selectedConfig = canonicalSeatbeltCandidatePath(selectedConfig)
	canonicalWritePaths := make([]seatbeltCandidateWriteDeny, len(writePaths))
	for index, denied := range writePaths {
		denied.path = canonicalSeatbeltCandidatePath(denied.path)
		canonicalWritePaths[index] = denied
	}
	sandbox, ok := NewProcessSandbox().(*nativeProcessSandbox)
	if !ok {
		t.Fatalf("NewProcessSandbox() = %T, want production native sandbox", sandbox)
	}
	backend, ok := sandbox.backends["darwin"].(*seatbeltBackend)
	if !ok || backend == nil {
		t.Fatalf("production Darwin backend = %T", sandbox.backends["darwin"])
	}
	backend.policy = func(request validatedProcessRequest) (string, []string, error) {
		policy, definitions, err := buildSeatbeltPolicy(request)
		if err != nil {
			return "", nil, err
		}
		var rules strings.Builder
		selectedName := "MCP_CANDIDATE_SELECTED_CONFIG"
		definitions = append(definitions, "-D"+selectedName+"="+selectedConfig)
		for _, basenamePattern := range []string{`[mM][cC][pP]_[cC][oO][nN][fF][iI][gG][.][jJ][sS][oO][nN]`, `[mM][cC][pP]_[cC][oO][nN][fF][iI][gG][.][lL][oO][cC][aA][lL][.][jJ][sS][oO][nN]`} {
			// Deny each reserved basename at every path except the one exact
			// canonical selected projection, expressed structurally in Seatbelt.
			// Explicit ASCII case classes cover case-insensitive filesystem names
			// without broadening the exact-dot near-name boundary.
			fmt.Fprintf(&rules, "\n(deny file-read* (require-all (regex #\"(^|/)%s$\") (require-not (literal (param %q)))))", basenamePattern, selectedName)
		}
		for index, denied := range canonicalWritePaths {
			name := "MCP_CANDIDATE_WRITE_DENY_" + strconv.Itoa(index)
			definitions = append(definitions, "-D"+name+"="+denied.path)
			fmt.Fprintf(&rules, "\n(deny file-write* (literal (param %q))", name)
			if denied.descendants {
				fmt.Fprintf(&rules, " (subpath (param %q))", name)
			}
			rules.WriteString(")")
		}
		return policy + rules.String(), definitions, nil
	}
	return sandbox
}

func canonicalSeatbeltCandidatePath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	current := filepath.Clean(absolute)
	var suffix []string
	for {
		resolved, resolveErr := filepath.EvalSymlinks(current)
		if resolveErr == nil {
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return filepath.Clean(resolved)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return filepath.Clean(absolute)
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
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
	case "environment-transport-target":
		if len(arguments) != 2 && len(arguments) != 5 {
			os.Exit(126)
		}
		if _, exists := os.LookupEnv("ACS_NATIVE_PROFILE_TOKEN"); exists {
			os.Exit(127)
		}
		value, exists := os.LookupEnv("PROFILE_SELECTED_TOKEN")
		if !exists || value != "selected-test-value" {
			os.Exit(128)
		}
		if len(arguments) == 5 {
			if arguments[2] != "signal" {
				os.Exit(135)
			}
			pid, err := strconv.Atoi(arguments[3])
			if err != nil || pid <= 0 {
				os.Exit(136)
			}
			if err := syscall.Kill(pid, syscall.SIGCONT); !errors.Is(err, syscall.EPERM) {
				os.Exit(137)
			}
			if err := os.WriteFile(arguments[4], []byte("EPERM"), 0o600); err != nil {
				os.Exit(138)
			}
		}
		if err := os.WriteFile(arguments[1], []byte("true"), 0o600); err != nil {
			os.Exit(129)
		}
		os.Exit(0)
	case "bystander-heartbeat":
		var sequence uint64
		for {
			sequence++
			temporary := arguments[1] + ".tmp"
			if err := os.WriteFile(temporary, []byte(strconv.FormatUint(sequence, 10)), 0o600); err != nil {
				os.Exit(139)
			}
			if err := os.Rename(temporary, arguments[1]); err != nil {
				os.Exit(140)
			}
			time.Sleep(10 * time.Millisecond)
		}
	case "environment-transport-blocked-target":
		if len(arguments) != 2 && len(arguments) != 6 {
			os.Exit(130)
		}
		if _, exists := os.LookupEnv("ACS_NATIVE_PROFILE_TOKEN"); exists {
			os.Exit(131)
		}
		value, exists := os.LookupEnv("PROFILE_SELECTED_TOKEN")
		if !exists || value != "selected-test-value" {
			os.Exit(132)
		}
		if len(arguments) == 6 {
			pid, err := strconv.Atoi(arguments[2])
			if err != nil || pid <= 0 {
				os.Exit(141)
			}
			if err := syscall.Kill(pid, syscall.SIGCONT); !errors.Is(err, syscall.EPERM) {
				os.Exit(142)
			}
			if err := os.WriteFile(arguments[3], []byte("EPERM"), 0o600); err != nil {
				os.Exit(143)
			}
			child := exec.Command(os.Args[0], "-test.run=^TestSeatbeltHelperProcess$", "--", "environment-transport-descendant", arguments[4])
			child.Env = os.Environ()
			child.Stdin = nil
			child.Stdout = nil
			child.Stderr = nil
			child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
			if err := child.Start(); err != nil {
				os.Exit(144)
			}
			if err := os.WriteFile(arguments[5], []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
				_ = child.Process.Kill()
				_ = child.Wait()
				os.Exit(145)
			}
		}
		if err := os.WriteFile(arguments[1], []byte("true"), 0o600); err != nil {
			os.Exit(133)
		}
		time.Sleep(30 * time.Second)
		os.Exit(134)
	case "environment-transport-descendant":
		if len(arguments) != 2 {
			os.Exit(146)
		}
		if err := os.WriteFile(arguments[1], []byte("ready"), 0o600); err != nil {
			os.Exit(147)
		}
		time.Sleep(30 * time.Second)
		os.Exit(148)
	case "mark":
		if err := os.WriteFile(arguments[1], []byte("started"), 0o600); err != nil {
			os.Exit(71)
		}
		os.Exit(0)
	case "proof-cleared":
		if _, err := os.Stat(arguments[1]); !errors.Is(err, os.ErrNotExist) {
			os.Exit(120)
		}
		os.Exit(0)
	case "containment":
		runSeatbeltContainmentHelper(arguments[1:])
	case "runtime-probes":
		contents, err := os.ReadFile(arguments[1])
		if err != nil || string(contents) != "managed" {
			os.Exit(114)
		}
		if _, err := os.ReadFile(arguments[2]); !errors.Is(err, os.ErrNotExist) {
			os.Exit(115)
		}
		if _, err := os.ReadFile(arguments[3]); !isSeatbeltPermission(err) {
			os.Exit(116)
		}
		if _, err := os.ReadFile(arguments[4]); !errors.Is(err, os.ErrNotExist) {
			os.Exit(117)
		}
		if _, err := os.ReadFile(arguments[5]); !isSeatbeltPermission(err) {
			os.Exit(118)
		}
		if _, err := os.ReadDir(arguments[6]); !isSeatbeltPermission(err) {
			os.Exit(119)
		}
		fmt.Fprintln(os.Stdout, "probed")
		os.Exit(0)
	case "session-prefix-metadata":
		current := string(filepath.Separator)
		for _, element := range strings.Split(strings.TrimPrefix(filepath.Clean(arguments[1]), string(filepath.Separator)), string(filepath.Separator)) {
			current = filepath.Join(current, element)
			if _, err := os.Lstat(current); err != nil && !errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(os.Stderr, "prefix-metadata-denied")
				os.Exit(121)
			}
		}
		if _, err := os.ReadDir(arguments[2]); !isSeatbeltPermission(err) {
			fmt.Fprintln(os.Stderr, "Session parent contents exposed")
			os.Exit(122)
		}
		if _, err := os.ReadFile(arguments[3]); !isSeatbeltPermission(err) {
			fmt.Fprintln(os.Stderr, "Session sibling contents exposed")
			os.Exit(123)
		}
		if err := os.WriteFile(arguments[4], []byte("bad"), 0o600); !isSeatbeltPermission(err) {
			fmt.Fprintln(os.Stderr, "Session sibling write exposed")
			os.Exit(124)
		}
		fmt.Fprintln(os.Stdout, "session-prefix-metadata")
		os.Exit(0)
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
	case "runtime-authority":
		for _, name := range DefaultRuntimeAuthority().SysctlNames {
			if _, err := unix.SysctlUint32(name); err != nil {
				fmt.Fprintf(os.Stderr, "registered sysctl %s failed: %v\n", name, err)
				os.Exit(125)
			}
		}
		if _, err := unix.Sysctl("kern.hostname"); !isSeatbeltPermission(err) {
			fmt.Fprintf(os.Stderr, "unregistered sysctl was not denied: %v\n", err)
			os.Exit(126)
		}
		descriptor, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "local-IP socket failed: %v\n", err)
			os.Exit(127)
		}
		unix.CloseOnExec(descriptor)
		if err := unix.Bind(descriptor, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			_ = unix.Close(descriptor)
			fmt.Fprintf(os.Stderr, "local-IP bind failed: %v\n", err)
			os.Exit(127)
		}
		if err := unix.Close(descriptor); err != nil {
			fmt.Fprintf(os.Stderr, "local-IP descriptor close failed: %v\n", err)
			os.Exit(127)
		}
		unixPath := filepath.Join(arguments[1], "denied-bind.sock")
		descriptor, err = unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unix socket creation failed: %v\n", err)
			os.Exit(129)
		}
		unix.CloseOnExec(descriptor)
		err = unix.Bind(descriptor, &unix.SockaddrUnix{Name: unixPath})
		closeErr := unix.Close(descriptor)
		if err == nil {
			_ = os.Remove(unixPath)
			fmt.Fprintln(os.Stderr, "unregistered Unix bind succeeded")
			os.Exit(128)
		}
		if closeErr != nil {
			fmt.Fprintf(os.Stderr, "Unix descriptor close failed: %v\n", closeErr)
			os.Exit(129)
		}
		if !isSeatbeltPermission(err) {
			fmt.Fprintf(os.Stderr, "unregistered Unix bind had unexpected failure: %v\n", err)
			os.Exit(129)
		}
		fmt.Fprintln(os.Stdout, "runtime-authority")
		os.Exit(0)
	case "security-policy-and-local-system-trust":
		if _, inherited := os.LookupEnv(seatbeltParentCredentialSentinel); inherited {
			fmt.Fprintln(os.Stdout, "parent-credential-sentinel-inherited")
			os.Exit(111)
		}
		if err := seatbeltCreateTLSVerificationPolicy(); err != nil {
			fmt.Fprintln(os.Stdout, "tls-policy-unavailable")
			os.Exit(112)
		}
		if err := seatbeltEvaluateLocalSystemTrustCertificate(); err != nil {
			fmt.Fprintln(os.Stdout, "local-system-trust-unavailable")
			os.Exit(113)
		}
		fmt.Fprintln(os.Stdout, "tls-ready")
		os.Exit(0)
	case "check-extra-descriptors":
		if len(arguments) != 3 {
			os.Exit(96)
		}
		device, err := strconv.ParseUint(arguments[1], 10, 64)
		if err != nil {
			os.Exit(96)
		}
		inode, err := strconv.ParseUint(arguments[2], 10, 64)
		if err != nil {
			os.Exit(96)
		}
		api, err := loadSeatbeltProcAPI()
		if err != nil {
			fmt.Fprintln(os.Stdout, "enumerate-descriptors-failed")
			os.Exit(96)
		}
		descriptors, err := api.descriptors(os.Getpid())
		if err != nil {
			fmt.Fprintln(os.Stdout, "enumerate-descriptors-failed")
			os.Exit(96)
		}
		for _, fd := range descriptors {
			identity, err := seatbeltTestDescriptorIdentityForFD(fd)
			if err != nil {
				fmt.Fprintf(os.Stdout, "inspect-fd-%d-failed\n", fd)
				os.Exit(96)
			}
			if identity.device == device && identity.inode == inode {
				fmt.Fprintf(os.Stdout, "leaked-sentinel-fd-%d\n", fd)
				os.Exit(96)
			}
		}
		for _, fd := range descriptors {
			if fd > 2 {
				fmt.Fprintf(os.Stdout, "leaked-control-fd-%d\n", fd)
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
	case "mcp-feasibility-read":
		if len(arguments) < 3 {
			os.Exit(151)
		}
		type observation struct {
			Path             string `json:"path"`
			Read             string `json:"read"`
			PermissionDenied bool   `json:"permissionDenied"`
		}
		observations := make([]observation, 0, (len(arguments)-1)/2)
		for index := 1; index < len(arguments)-1; index++ {
			contents, err := os.ReadFile(arguments[index])
			entry := observation{Path: filepath.Base(arguments[index])}
			if err != nil {
				entry.PermissionDenied = isSeatbeltPermission(err)
			} else {
				entry.Read = string(contents)
			}
			observations = append(observations, entry)
		}
		encoded, err := json.Marshal(observations)
		if err != nil {
			os.Exit(152)
		}
		if err := os.WriteFile(arguments[len(arguments)-1], encoded, 0o600); err != nil {
			os.Exit(153)
		}
		os.Exit(0)
	case "mcp-feasibility-recipe-op":
		if len(arguments) != 7 {
			os.Exit(154)
		}
		marker, kind, recipe, recipeDir, home, session := arguments[1], arguments[2], arguments[3], arguments[4], arguments[5], arguments[6]
		var operationErr error
		switch kind {
		case "overwrite":
			operationErr = os.WriteFile(recipe, []byte("changed"), 0o600)
		case "truncate":
			file, err := os.OpenFile(recipe, os.O_WRONLY|os.O_TRUNC, 0)
			if err != nil {
				operationErr = err
			} else {
				operationErr = file.Close()
			}
		case "unlink":
			operationErr = os.Remove(recipe)
		case "rename-out":
			operationErr = os.Rename(recipe, filepath.Join(home, "escaped-recipe"))
		case "atomic-replace":
			temporary := filepath.Join(home, "replacement.tmp")
			prepareErr := os.WriteFile(temporary, []byte("replacement"), 0o600)
			renameErr := error(nil)
			if prepareErr == nil {
				renameErr = os.Rename(temporary, recipe)
			}
			result := map[string]any{"operation": kind, "prepareSucceeded": prepareErr == nil,
				"renamePermissionDenied": isSeatbeltPermission(renameErr), "renameSucceeded": renameErr == nil,
				"permissionDenied": isSeatbeltPermission(renameErr), "succeeded": prepareErr == nil && renameErr == nil}
			encoded, err := json.Marshal(result)
			if err != nil {
				os.Exit(156)
			}
			if err := os.WriteFile(marker, encoded, 0o600); err != nil {
				os.Exit(157)
			}
			os.Exit(0)
		case "rename-recipe-ancestor":
			operationErr = os.Rename(recipeDir, filepath.Join(home, "moved-recipe-dir"))
		case "rename-home-ancestor":
			operationErr = os.Rename(home, filepath.Join(session, "moved-home"))
		case "rename-session-ancestor":
			operationErr = os.Rename(session, filepath.Join(filepath.Dir(session), "moved-session"))
		case "ordinary-home-write":
			operationErr = os.WriteFile(filepath.Join(home, "ordinary-home-write"), []byte("allowed"), 0o600)
		default:
			os.Exit(155)
		}
		result := map[string]any{"operation": kind, "permissionDenied": isSeatbeltPermission(operationErr), "succeeded": operationErr == nil}
		encoded, err := json.Marshal(result)
		if err != nil {
			os.Exit(156)
		}
		if err := os.WriteFile(marker, encoded, 0o600); err != nil {
			os.Exit(157)
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

func seatbeltCreateTLSVerificationPolicy() error {
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
	var createSSL func(uint8, unsafe.Pointer) unsafe.Pointer
	var release func(unsafe.Pointer)
	purego.RegisterLibFunc(&createSSL, security, "SecPolicyCreateSSL")
	purego.RegisterLibFunc(&release, coreFoundation, "CFRelease")
	policy := createSSL(1, nil)
	if policy == nil {
		return errors.New("SecPolicyCreateSSL returned nil")
	}
	defer release(policy)
	return nil
}

func seatbeltEvaluateLocalSystemTrustCertificate() error {
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
	var errorCode func(unsafe.Pointer) int64
	var release func(unsafe.Pointer)
	purego.RegisterLibFunc(&copyCertificates, security, "SecTrustSettingsCopyCertificates")
	purego.RegisterLibFunc(&arrayCount, coreFoundation, "CFArrayGetCount")
	purego.RegisterLibFunc(&arrayValueAtIndex, coreFoundation, "CFArrayGetValueAtIndex")
	purego.RegisterLibFunc(&createBasicX509, security, "SecPolicyCreateBasicX509")
	purego.RegisterLibFunc(&createTrust, security, "SecTrustCreateWithCertificates")
	purego.RegisterLibFunc(&setNetworkFetchAllowed, security, "SecTrustSetNetworkFetchAllowed")
	purego.RegisterLibFunc(&evaluateTrust, security, "SecTrustEvaluateWithError")
	purego.RegisterLibFunc(&errorCode, coreFoundation, "CFErrorGetCode")
	purego.RegisterLibFunc(&release, coreFoundation, "CFRelease")
	var certificates unsafe.Pointer
	if status := copyCertificates(2, &certificates); status != 0 || certificates == nil {
		return fmt.Errorf("copy system trust certificates: status=%d certificates=%t", status, certificates != nil)
	}
	defer release(certificates)
	if arrayCount(certificates) <= 0 {
		return errors.New("copy system trust certificates: no certificates")
	}
	certificate := arrayValueAtIndex(certificates, 0)
	if certificate == nil {
		return errors.New("copy system trust certificates: first certificate is nil")
	}
	policy := createBasicX509()
	if policy == nil {
		return errors.New("SecPolicyCreateBasicX509 returned nil")
	}
	defer release(policy)
	var trust unsafe.Pointer
	if status := createTrust(certificate, policy, &trust); status != 0 || trust == nil {
		return fmt.Errorf("SecTrustCreateWithCertificates: status=%d trust=%t", status, trust != nil)
	}
	defer release(trust)
	if status := setNetworkFetchAllowed(trust, 0); status != 0 {
		return fmt.Errorf("SecTrustSetNetworkFetchAllowed: status=%d", status)
	}
	var evaluationError unsafe.Pointer
	trusted := evaluateTrust(trust, &evaluationError)
	if evaluationError != nil {
		defer release(evaluationError)
	}
	if trusted {
		return nil
	}
	if evaluationError == nil {
		return errors.New("SecTrustEvaluateWithError failed without a CFError")
	}
	return fmt.Errorf("SecTrustEvaluateWithError: OSStatus %d", errorCode(evaluationError))
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

func seatbeltEnvironmentSandboxExecFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sandbox-exec-fixture")
	const script = `#!/bin/sh
set -eu
trace=
target=
after_separator=false
for argument do
  case "$argument" in
    -DACS_ENV_TEST_TRACE=*) trace=${argument#-DACS_ENV_TEST_TRACE=} ;;
  esac
  if [ "$after_separator" = true ] && [ -z "$target" ]; then target=$argument; fi
  if [ "$argument" = "--" ]; then after_separator=true; fi
done
if [ -z "$trace" ]; then exit 124; fi
stage=proxy
if [ "$target" = /usr/bin/true ]; then stage=validation; fi
selected_absent=true
if [ "${ACS_NATIVE_PROFILE_TOKEN+x}" = x ] || [ "${PROFILE_SELECTED_TOKEN+x}" = x ]; then selected_absent=false; fi
umask 077
printf '%s' "$selected_absent" > "$trace-$stage"
exec /usr/bin/sandbox-exec "$@"
`
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func seatbeltEnvironmentTestPolicy(request validatedProcessRequest, trace string) (string, []string, error) {
	policy, definitions, err := buildSeatbeltPolicy(request)
	if err != nil {
		return "", nil, err
	}
	return policy, append(definitions, "-DACS_ENV_TEST_TRACE="+trace), nil
}

func readSeatbeltHeartbeat(path string) (uint64, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(string(contents), 10, 64)
}

func waitForSeatbeltHeartbeat(path string, after uint64, timeout time.Duration) (uint64, error) {
	deadline := time.Now().Add(timeout)
	for {
		sequence, err := readSeatbeltHeartbeat(path)
		if err == nil && sequence > after {
			return sequence, nil
		}
		if time.Now().After(deadline) {
			return sequence, fmt.Errorf("heartbeat did not advance beyond %d (last read %d, read error %v)", after, sequence, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func observeSeatbeltBystander(
	stop <-chan struct{}, api seatbeltProcAPI, heartbeatPath string,
	bystanderPID int, bystanderIdentity seatbeltBSDInfo,
	runnerPID int, runnerIdentity seatbeltBSDInfo,
) error {
	lastHeartbeat, err := readSeatbeltHeartbeat(heartbeatPath)
	if err != nil {
		return err
	}
	lastProgress := time.Now()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return nil
		case now := <-ticker.C:
			heartbeat, err := readSeatbeltHeartbeat(heartbeatPath)
			if err != nil {
				return fmt.Errorf("read bystander heartbeat: %w", err)
			}
			if heartbeat > lastHeartbeat {
				lastHeartbeat = heartbeat
				lastProgress = now
			} else if now.Sub(lastProgress) > 250*time.Millisecond {
				return fmt.Errorf("heartbeat stopped advancing at receipt %d", lastHeartbeat)
			}
			currentBystander, err := api.info(bystanderPID)
			if err != nil || currentBystander.PID != bystanderIdentity.PID ||
				currentBystander.StartSecond != bystanderIdentity.StartSecond ||
				currentBystander.StartMicrosecond != bystanderIdentity.StartMicrosecond ||
				currentBystander.Status == seatbeltProcStatusStop ||
				currentBystander.Status == seatbeltProcStatusZombie {
				return fmt.Errorf("outside bystander identity/state changed: before=%+v after=%+v err=%v", bystanderIdentity, currentBystander, err)
			}
			currentRunner, err := api.info(runnerPID)
			if err != nil || currentRunner.PID != runnerIdentity.PID ||
				currentRunner.StartSecond != runnerIdentity.StartSecond ||
				currentRunner.StartMicrosecond != runnerIdentity.StartMicrosecond ||
				currentRunner.Status == seatbeltProcStatusStop || currentRunner.Status == seatbeltProcStatusZombie {
				return fmt.Errorf("test runner identity/state changed: before=%+v after=%+v err=%v", runnerIdentity, currentRunner, err)
			}
		}
	}
}

func seatbeltProductionTLSRequest(t *testing.T) (ProcessRequest, *bytes.Buffer) {
	t.Helper()
	root, err := os.MkdirTemp("/private/tmp", "acs-seatbelt-tls-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	workspace := filepath.Join(root, "workspace")
	sessions := filepath.Join(root, "sessions")
	session := filepath.Join(sessions, "session-one")
	home := filepath.Join(session, "home")
	temporary := filepath.Join(session, "tmp")
	executable := filepath.Join(root, "nested", "launch", "target", "bin", "seatbelt-tls.test")
	for _, directory := range []string{workspace, home, temporary, filepath.Dir(executable)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	sourcePath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.OpenFile(executable, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, source); err != nil {
		_ = target.Close()
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	output := new(bytes.Buffer)
	return ProcessRequest{
		Workspace: workspace, SessionsDirectory: sessions, SessionDirectory: session,
		SessionHome: home, TemporaryDirectory: temporary, Executable: executable,
		Arguments: []string{"-test.run=^TestSeatbeltHelperProcess$", "--", "security-policy-and-local-system-trust"},
		Terminal:  Terminal{Output: output, ErrorOutput: output},
	}, output
}

func seatbeltRunProductionTLS(sandbox ProcessSandbox, request ProcessRequest) error {
	process, err := sandbox.Prepare(context.Background(), request)
	if err != nil {
		return err
	}
	if err := process.Start(); err != nil {
		return err
	}
	return process.Wait()
}

const seatbeltParentCredentialSentinel = "ACS_SEATBELT_PARENT_CREDENTIAL_SENTINEL"

const seatbeltRemoteIPOutboundAllowance = "  (remote ip)\n"

func seatbeltProductionTLSSandbox(t *testing.T, omitted string) ProcessSandbox {
	t.Helper()
	sandbox, ok := NewProcessSandbox().(*nativeProcessSandbox)
	if !ok {
		t.Fatalf("NewProcessSandbox() = %T, want *nativeProcessSandbox", sandbox)
	}
	backend, ok := sandbox.backends["darwin"].(*seatbeltBackend)
	if !ok || backend == nil {
		t.Fatalf("production Darwin backend = %T, want *seatbeltBackend", sandbox.backends["darwin"])
	}
	backend.policy = func(request validatedProcessRequest) (string, []string, error) {
		policy, definitions, err := buildSeatbeltPolicy(request)
		if err != nil {
			return "", nil, err
		}
		if policy, err = seatbeltRemovePolicyTextExactlyOnce(policy, seatbeltRemoteIPOutboundAllowance, "remote-IP outbound allowance"); err != nil {
			return "", nil, err
		}
		switch omitted {
		case "":
			return policy, definitions, nil
		case "executable metadata":
			policy, err = seatbeltRemoveMetadataRule(policy, "EXECUTABLE_ANCESTOR_0", "executable metadata rule")
		case "session metadata":
			policy, err = seatbeltRemoveMetadataRule(policy, "SESSION_ANCESTOR_0", "Session metadata rule")
		case "trustd agent":
			const rule = "(allow mach-lookup\n  (global-name \"com.apple.trustd.agent\"))\n"
			policy, err = seatbeltRemovePolicyTextExactlyOnce(policy, rule, "trustd agent rule")
		default:
			return "", nil, fmt.Errorf("unknown omitted TLS rule %q", omitted)
		}
		if err != nil {
			return "", nil, err
		}
		return policy, definitions, nil
	}
	return sandbox
}

func seatbeltRemoveMetadataRule(policy, firstParameter, description string) (string, error) {
	needle := "(allow file-read-metadata\n  (literal (param \"" + firstParameter + "\"))"
	start := strings.Index(policy, needle)
	if start < 0 {
		return "", fmt.Errorf("%s is missing", description)
	}
	end := strings.Index(policy[start:], ")\n\n")
	if end < 0 {
		return "", fmt.Errorf("%s is malformed", description)
	}
	return seatbeltRemovePolicyTextExactlyOnce(policy, policy[start:start+end+3], description)
}

func seatbeltRemovePolicyTextExactlyOnce(policy, text, description string) (string, error) {
	if count := strings.Count(policy, text); count != 1 {
		return "", fmt.Errorf("%s count = %d, want 1", description, count)
	}
	return strings.Replace(policy, text, "", 1), nil
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
	unix.CloseOnExec(descriptors[0])
	unix.CloseOnExec(descriptors[1])
	parent := os.NewFile(uintptr(descriptors[0]), "seatbelt-test-parent")
	peer := os.NewFile(uintptr(descriptors[1]), "seatbelt-test-peer")
	t.Cleanup(func() {
		_ = parent.Close()
		_ = peer.Close()
	})
	return parent, peer
}

func seatbeltTestDeadlineSocketPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	descriptors, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.CloseOnExec(descriptors[0])
	unix.CloseOnExec(descriptors[1])
	parentFile := os.NewFile(uintptr(descriptors[0]), "seatbelt-test-deadline-parent")
	peerFile := os.NewFile(uintptr(descriptors[1]), "seatbelt-test-deadline-peer")
	if parentFile == nil || peerFile == nil {
		if parentFile != nil {
			_ = parentFile.Close()
		}
		if peerFile != nil {
			_ = peerFile.Close()
		}
		t.Fatal("could not construct deadline socket files")
	}
	parent, err := net.FileConn(parentFile)
	_ = parentFile.Close()
	if err != nil {
		_ = peerFile.Close()
		t.Fatal(err)
	}
	peer, err := net.FileConn(peerFile)
	_ = peerFile.Close()
	if err != nil {
		_ = parent.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = parent.Close()
		_ = peer.Close()
	})
	return parent, peer
}

func seatbeltTestStartTarget(t *testing.T, control *os.File, challenge []byte) {
	t.Helper()
	if _, err := control.Write(challenge); err != nil {
		t.Fatal(err)
	}
	ready := []byte{0}
	if _, err := io.ReadFull(control, ready); err != nil {
		t.Fatal(err)
	}
	if ready[0] != seatbeltSupervisorReady {
		t.Fatalf("supervisor readiness = %q", ready)
	}
	if _, err := control.Write([]byte{seatbeltSupervisorNoEnvironment, seatbeltSupervisorStart}); err != nil {
		t.Fatal(err)
	}
}

func seatbeltTestAcceptTargetStart(control io.ReadWriter, challenge []byte) ([]byte, error) {
	got := make([]byte, len(challenge))
	if _, err := io.ReadFull(control, got); err != nil {
		return nil, err
	}
	if _, err := control.Write([]byte{seatbeltSupervisorReady}); err != nil {
		return nil, err
	}
	start := make([]byte, 2)
	if _, err := io.ReadFull(control, start); err != nil {
		return nil, err
	}
	if start[0] != seatbeltSupervisorNoEnvironment || start[1] != seatbeltSupervisorStart {
		return nil, errors.New("unexpected supervisor start signal")
	}
	return got, nil
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

type seatbeltTransientZombieEnumerator struct {
	pid            int
	secondSnapshot chan struct{}
	calls          atomic.Int32
	once           sync.Once
}

func (enumerator *seatbeltTransientZombieEnumerator) allPIDs() ([]int, error) {
	return []int{enumerator.pid}, nil
}

func (enumerator *seatbeltTransientZombieEnumerator) info(pid int) (seatbeltBSDInfo, error) {
	if pid != enumerator.pid {
		return seatbeltBSDInfo{}, errors.New("unexpected process inspection")
	}
	if enumerator.calls.Add(1) == 1 {
		// proc_pidinfo can expose the entry while its exit fields are being
		// rewritten. It is neither a stable live process nor proof of death.
		return seatbeltBSDInfo{PID: uint32(pid), Status: seatbeltProcStatusIdle}, nil
	}
	enumerator.once.Do(func() { close(enumerator.secondSnapshot) })
	return seatbeltBSDInfo{PID: uint32(pid), Status: seatbeltProcStatusZombie}, nil
}
