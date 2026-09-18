package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeCandidateGatesRequireSuppliedArtifacts(t *testing.T) {
	fixture := newNativeGateFixture(t)
	for _, test := range []struct {
		name       string
		candidate  string
		target     string
		archive    string
		diagnostic string
	}{
		{"candidate", "/missing/acs", fixture.target, fixture.archive, "supplied candidate binary is unavailable or unsafe"},
		{"target", fixture.candidate, "/missing/codex", fixture.archive, "supplied Codex binary is unavailable or unsafe"},
		{"archive", fixture.candidate, fixture.target, "/missing/codex.tar.gz", "supplied Codex archive is unavailable or unsafe"},
	} {
		t.Run(test.name, func(t *testing.T) {
			command := exec.Command("sh", "run-native-candidate-gates.sh", "v0.4.0", test.candidate, test.target, test.archive, filepath.Join(fixture.root, "recovery"), "available")
			command.Env = append(os.Environ(), "ACS_TEST_DEVIN_BINARY="+fixture.devin)
			output, err := command.CombinedOutput()
			if err == nil {
				t.Fatal("native candidate gate accepted a missing supplied artifact")
			}
			if !strings.Contains(string(output), test.diagnostic) {
				t.Fatalf("diagnostic = %q, want %q", output, test.diagnostic)
			}
		})
	}
}

func TestNativeCandidateGatesPropagateFailureRecoverAndProtectIdentity(t *testing.T) {
	t.Run("baseline identity read failures stop before test discovery", func(t *testing.T) {
		for _, mode := range []string{"hash-baseline-fail", "hash-baseline-empty", "hash-baseline-malformed"} {
			t.Run(mode, func(t *testing.T) {
				fixture := newNativeGateFixture(t)
				fixture.run(t, mode, false, "candidate identity could not be read")
				if contents, err := os.ReadFile(fixture.callsPath); err == nil {
					t.Fatalf("baseline identity failure reached Go test discovery:\n%s", contents)
				} else if !os.IsNotExist(err) {
					t.Fatal(err)
				}
			})
		}
	})

	t.Run("final identity read failures fail the gate", func(t *testing.T) {
		for _, mode := range []string{"hash-final-fail", "hash-final-empty", "hash-final-malformed"} {
			t.Run(mode, func(t *testing.T) {
				fixture := newNativeGateFixture(t)
				fixture.run(t, mode, false, "supplied artifact identity changed during validation")
				if !strings.Contains(fixture.calls(t), "TestNativeKeychainRecoveryEntrypoint") {
					t.Fatal("final identity failure omitted recovery")
				}
			})
		}
	})

	t.Run("final identity failure does not erase the primary failure", func(t *testing.T) {
		for _, mode := range []string{"fail-primary-final-fail", "fail-primary-final-empty", "fail-primary-final-malformed"} {
			t.Run(mode, func(t *testing.T) {
				fixture := newNativeGateFixture(t)
				output, err := fixture.command(mode).CombinedOutput()
				if err == nil {
					t.Fatal("native candidate gate accepted primary and final identity failures")
				}
				exitError, ok := err.(*exec.ExitError)
				if !ok || exitError.ExitCode() != 23 {
					t.Fatalf("exit error = %v, want primary status 23; output=%q", err, output)
				}
				if !strings.Contains(string(output), "supplied artifact identity changed during validation") {
					t.Fatalf("final identity diagnostic omitted: %q", output)
				}
			})
		}
	})

	t.Run("missing recovery entrypoint stops before native target work", func(t *testing.T) {
		fixture := newNativeGateFixture(t)
		fixture.run(t, "missing-recovery", false, "required test TestNativeKeychainRecoveryEntrypoint is unavailable")
		calls := fixture.calls(t)
		if !strings.Contains(calls, "-list ^TestNativeKeychainRecoveryEntrypoint$") {
			t.Fatalf("recovery discovery was not attempted:\n%s", calls)
		}
		if strings.Contains(calls, "-run ^TestNativeInstalledACSExecutesLockedCodexToolThroughNamedIdentity$") ||
			strings.Contains(calls, "-run ^TestNativeKeychainRecoveryEntrypoint$") {
			t.Fatalf("missing recovery entrypoint reached native target work or cleanup:\n%s", calls)
		}
	})

	t.Run("gate failure is preserved and recovery runs", func(t *testing.T) {
		fixture := newNativeGateFixture(t)
		fixture.run(t, "fail-primary", false, "primary gate failed")
		calls := fixture.calls(t)
		if !strings.Contains(calls, "TestNativeInstalledACSExecutesLockedCodexToolThroughNamedIdentity") ||
			!strings.Contains(calls, "TestNativeKeychainRecoveryEntrypoint") {
			t.Fatalf("calls omit failing gate or recovery:\n%s", calls)
		}
		if strings.Contains(calls, "go test ./...") {
			t.Fatalf("execution continued after the failing gate:\n%s", calls)
		}
	})

	t.Run("successful commands cannot replace the supplied candidate", func(t *testing.T) {
		fixture := newNativeGateFixture(t)
		fixture.run(t, "mutate-candidate", false, "supplied artifact identity changed")
		if !strings.Contains(fixture.calls(t), "TestNativeKeychainRecoveryEntrypoint") {
			t.Fatal("identity failure omitted recovery")
		}
	})

	t.Run("cleanup failure does not erase the primary failure", func(t *testing.T) {
		fixture := newNativeGateFixture(t)
		output, err := fixture.command("fail-primary-and-recovery").CombinedOutput()
		if err == nil {
			t.Fatal("native candidate gate accepted primary and recovery failures")
		}
		exitError, ok := err.(*exec.ExitError)
		if !ok || exitError.ExitCode() != 23 {
			t.Fatalf("exit error = %v, want primary status 23; output=%q", err, output)
		}
		if !strings.Contains(fixture.calls(t), "TestNativeKeychainRecoveryEntrypoint") {
			t.Fatal("cleanup failure path did not run recovery")
		}
	})

	t.Run("cleanup failure fails an otherwise successful gate", func(t *testing.T) {
		fixture := newNativeGateFixture(t)
		output, err := fixture.command("fail-recovery").CombinedOutput()
		if err == nil {
			t.Fatal("native candidate gate suppressed recovery failure")
		}
		exitError, ok := err.(*exec.ExitError)
		if !ok || exitError.ExitCode() != 29 {
			t.Fatalf("exit error = %v, want recovery status 29; output=%q", err, output)
		}
		if !strings.Contains(string(output), "native authentication recovery failed") {
			t.Fatalf("recovery diagnostic omitted: %q", output)
		}
	})

	t.Run("all gates and recovery succeed", func(t *testing.T) {
		fixture := newNativeGateFixture(t)
		fixture.run(t, "success", true, "")
		calls := fixture.calls(t)
		for _, required := range []string{
			"go test -v ./...",
			"TestPromotedArtifactSharedTargetConformance",
			"generic_literal_command_uses_candidate_containment",
			"effective_explanation_is_linked_and_narrowly_observed",
			"go test -race ./...",
			"TestNativeKeychainCredentialFreeContract",
			"TestNativeRealStoreInstalledTargetComposition",
			"TestSeatbeltCandidateMCPAmbientReadDenialWithAbsentAtPrepareAndAliases",
			"TestSeatbeltCandidateMCPRecipeWriteAndAncestorDenialsPreserveOrdinaryHome",
			"TestSeatbeltCandidatePinnedDevinUsesSelectedHomeMCPConfigOnly",
			"TestSeatbeltCandidatePinnedDevinConfigPathReplacementIsolation",
			"TestSeatbeltCandidatePinnedDevinNestedDiscoveryGrantScope",
			"TestSeatbeltCandidatePinnedDevinDirectorySymlinkRedirection",
			"TestSeatbeltCandidatePinnedDevinReservedConfigBasenames",
			"go test ./internal/launch -run ^TestSeatbeltCandidate(MCPAmbientReadDenialWithAbsentAtPrepareAndAliases|MCPRecipeWriteAndAncestorDenialsPreserveOrdinaryHome|PinnedDevinUsesSelectedHomeMCPConfigOnly|PinnedDevinConfigPathReplacementIsolation|PinnedDevinNestedDiscoveryGrantScope|PinnedDevinDirectorySymlinkRedirection|PinnedDevinReservedConfigBasenames)$ -count=1 -v",
			"TestNativeInstalledTargetContainedStatusWithoutCredentials",
			"TestNativeDirectInstalledTargetInteractiveLifecycle",
			"go test ./acceptance -count=1",
			"TestNativeKeychainRecoveryEntrypoint",
		} {
			if !strings.Contains(calls, required) {
				t.Errorf("calls omit %q:\n%s", required, calls)
			}
		}
		for _, scoped := range []string{
			"auth= promoted= version= backend= recovery= go test -v ./...",
			"go test -v ./... mcp=\n",
			"go test -race ./... mcp=\n",
			"go test ./internal/launch -run ^TestSeatbeltCandidate(MCPAmbientReadDenialWithAbsentAtPrepareAndAliases|MCPRecipeWriteAndAncestorDenialsPreserveOrdinaryHome|PinnedDevinUsesSelectedHomeMCPConfigOnly|PinnedDevinConfigPathReplacementIsolation|PinnedDevinNestedDiscoveryGrantScope|PinnedDevinDirectorySymlinkRedirection|PinnedDevinReservedConfigBasenames)$ -count=1 -v mcp=1\n",
			"auth=1 promoted=" + fixture.candidate + " version= backend= recovery= go test ./internal/codexauthresource -run ^TestNativeKeychainCredentialFreeContract$",
			"auth= promoted=" + fixture.candidate + " version=v0.4.0 backend=available recovery= go test ./acceptance -count=1",
			"auth= promoted= version= backend= recovery=1 go test ./internal/codexauthresource -run ^TestNativeKeychainRecoveryEntrypoint$",
		} {
			if !strings.Contains(calls, scoped) {
				t.Errorf("environment scope omits %q:\n%s", scoped, calls)
			}
		}
	})
}

type nativeGateFixture struct {
	root         string
	bin          string
	candidate    string
	target       string
	archive      string
	devin        string
	devinArchive string
	callsPath    string
	hashCalls    string
}

func newNativeGateFixture(t *testing.T) nativeGateFixture {
	t.Helper()
	root := t.TempDir()
	fixture := nativeGateFixture{
		root:         root,
		bin:          filepath.Join(root, "bin"),
		candidate:    filepath.Join(root, "acs"),
		target:       filepath.Join(root, "codex"),
		archive:      filepath.Join(root, "codex.tar.gz"),
		devin:        filepath.Join(root, "devin"),
		devinArchive: filepath.Join(root, "devin.tar.gz"),
		callsPath:    filepath.Join(root, "calls"),
		hashCalls:    filepath.Join(root, "hash-calls"),
	}
	if err := os.Mkdir(fixture.bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fixture.candidate, fixture.target, fixture.devin} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(fixture.archive, []byte("locked archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.devinArchive, []byte("locked Devin archive"), 0600); err != nil {
		t.Fatal(err)
	}
	fakeGo := `#!/bin/sh
printf 'auth=%s promoted=%s version=%s backend=%s recovery=%s go %s mcp=%s\n' "${ACS_RUN_NATIVE_AUTH_GATE:-}" "${ACS_PROMOTED_BINARY:-}" "${ACS_PROMOTED_VERSION:-}" "${ACS_PROMOTED_SANDBOX_BACKEND:-}" "${ACS_RUN_NATIVE_AUTH_RECOVERY:-}" "$*" "${ACS_RUN_MCP_AMBIENT_FEASIBILITY:-}" >>"$ACS_TEST_CALLS"
printf 'devin-mcp=%s devin-archive=%s go %s\n' "${ACS_RUN_NATIVE_DEVIN_MCP:-}" "${ACS_TEST_DEVIN_ARCHIVE:-}" "$*" >>"$ACS_TEST_CALLS"
previous=
for argument do
  if [ "$previous" = -list ]; then
    case "$ACS_TEST_MODE:$argument" in
      missing-recovery:'^TestNativeKeychainRecoveryEntrypoint$') ;;
 missing-real-devin-mcp:'^TestPromotedArtifactNativeRealDevinMCP$') ;;
      missing-mcp-protection:'^TestPromotedArtifactNativeProductionMCPProtection$') ;;
      *) printf '%s\n' "$argument" | tr -d '^$' ;;
    esac
  fi
  previous="$argument"
done
case "$ACS_TEST_MODE:$*" in
 fail-real-devin-mcp:*"-run ^TestPromotedArtifactNativeRealDevinMCP$"*) exit 37 ;;
  fail-mcp-protection:*"-run ^TestPromotedArtifactNativeProductionMCPProtection$"*) exit 31 ;;
  fail-primary*:*"-run ^TestNativeInstalledACSExecutesLockedCodexToolThroughNamedIdentity$"*) printf '%s\n' 'primary gate failed' >&2; exit 23 ;;
  fail-*recovery:*"-run ^TestNativeKeychainRecoveryEntrypoint$"*) printf '%s\n' 'recovery failed' >&2; exit 29 ;;
  mutate-candidate:*"-run ^TestNativeInstalledACSExecutesLockedCodexToolThroughNamedIdentity$"*) printf '%s\n' replacement >"$ACS_PROMOTED_BINARY"; chmod 0700 "$ACS_PROMOTED_BINARY" ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(fixture.bin, "go"), []byte(fakeGo), 0o700); err != nil {
		t.Fatal(err)
	}
	fakeShasum := `#!/bin/sh
count=0
if [ -f "$ACS_TEST_HASH_CALLS" ]; then read -r count <"$ACS_TEST_HASH_CALLS"; fi
count=$((count + 1))
printf '%s\n' "$count" >"$ACS_TEST_HASH_CALLS"
case "$ACS_TEST_MODE:$count" in
  hash-baseline-fail:1) exit 41 ;;
  hash-baseline-empty:1) exit 0 ;;
  hash-baseline-malformed:1) printf '%s\n' malformed; exit 0 ;;
  hash-final-fail:*|fail-primary-final-fail:*) if [ "$count" -gt 4 ]; then exit 41; fi ;;
  hash-final-empty:*|fail-primary-final-empty:*) if [ "$count" -gt 4 ]; then exit 0; fi ;;
  hash-final-malformed:*|fail-primary-final-malformed:*) if [ "$count" -gt 4 ]; then printf '%s\n' malformed; exit 0; fi ;;
esac
exec "$ACS_REAL_SHASUM" "$@"
`
	if err := os.WriteFile(filepath.Join(fixture.bin, "shasum"), []byte(fakeShasum), 0o700); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (fixture nativeGateFixture) run(t *testing.T, mode string, wantSuccess bool, wantOutput string) {
	t.Helper()
	command := fixture.command(mode)
	output, err := command.CombinedOutput()
	if (err == nil) != wantSuccess {
		t.Fatalf("success = %v, want %v; output=%q", err == nil, wantSuccess, output)
	}
	if wantOutput != "" && !strings.Contains(string(output), wantOutput) {
		t.Fatalf("output = %q, want %q", output, wantOutput)
	}
}

func (fixture nativeGateFixture) command(mode string) *exec.Cmd {
	return fixture.commandWithShell("sh", mode)
}

func (fixture nativeGateFixture) commandWithShell(shell, mode string) *exec.Cmd {
	commandName := shell
	commandArgs := []string{"run-native-candidate-gates.sh", "v0.4.0", fixture.candidate, fixture.target, fixture.archive, filepath.Join(fixture.root, "recovery"), "available"}
	if shell == "bash-posix" {
		commandName = "bash"
		commandArgs = append([]string{"--posix"}, commandArgs...)
	}
	command := exec.Command(commandName, commandArgs...)
	command.Env = append(os.Environ(),
		"PATH="+fixture.bin+":"+os.Getenv("PATH"),
		"ACS_TEST_CALLS="+fixture.callsPath,
		"ACS_TEST_MODE="+mode,
		"ACS_TEST_HASH_CALLS="+fixture.hashCalls,
		"ACS_REAL_SHASUM=/usr/bin/shasum",
		"ACS_PROMOTED_VERSION=ambient-version",
		"ACS_PROMOTED_BINARY=/ambient/candidate",
		"ACS_PROMOTED_SANDBOX_BACKEND=ambient-backend",
		"ACS_RUN_NATIVE_AUTH_GATE=ambient-auth",
		"ACS_RUN_NATIVE_AUTH_RECOVERY=ambient-recovery",
		"ACS_RUN_MCP_AMBIENT_FEASIBILITY=ambient-mcp-feasibility",
		"ACS_NATIVE_AUTH_RECOVERY_ROOT=/ambient/recovery",
		"ACS_TEST_CODEX_BINARY=/ambient/codex",
		"ACS_TEST_CODEX_ARCHIVE=/ambient/codex.tar.gz",
		"ACS_TEST_DEVIN_BINARY="+fixture.devin,
		"ACS_TEST_DEVIN_ARCHIVE="+fixture.devinArchive,
		"ACS_RUN_NATIVE_DEVIN_MCP=ambient-enable",
	)
	return command
}

func TestNativeCandidateScopedDevinEnvironmentAcrossShells(t *testing.T) {
	for _, shell := range []string{"sh", "bash-posix"} {
		t.Run(shell, func(t *testing.T) {
			fixture := newNativeGateFixture(t)
			output, err := fixture.commandWithShell(shell, "success").CombinedOutput()
			if err != nil {
				t.Fatalf("gate failed: %v output=%q", err, output)
			}
			calls := fixture.calls(t)
			assertDevinGateMetadata(t, calls, fixture, true)
		})
	}
}

func TestNativeCandidateScopedDevinFailurePreservesRecoveryAcrossShells(t *testing.T) {
	for _, shell := range []string{"sh", "bash-posix"} {
		t.Run(shell, func(t *testing.T) {
			fixture := newNativeGateFixture(t)
			output, err := fixture.commandWithShell(shell, "fail-real-devin-mcp").CombinedOutput()
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 37 {
				t.Fatalf("exit=%v output=%q", err, output)
			}
			calls := fixture.calls(t)
			if !strings.Contains(calls, "go test ./internal/codexauthresource -run ^TestNativeKeychainRecoveryEntrypoint$") {
				t.Fatalf("recovery invocation missing under %s: %s", shell, calls)
			}
			assertDevinGateMetadata(t, calls, fixture, true)
			const recovery = "devin-mcp= devin-archive= go test ./internal/codexauthresource -run ^TestNativeKeychainRecoveryEntrypoint$ -count=1"
			if strings.Count(calls, recovery) != 1 {
				t.Fatalf("expected one actual recovery invocation under %s: %s", shell, calls)
			}
		})
	}
}

func assertDevinGateMetadata(t *testing.T, calls string, fixture nativeGateFixture, requireEnabled bool) {
	t.Helper()
	const prefix = "devin-mcp="
	enabled := "devin-mcp=1 devin-archive=" + fixture.devinArchive + " go test ./acceptance -run ^TestPromotedArtifactNativeRealDevinMCP$ -count=1 -v"
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(calls), "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		if line == enabled {
			count++
			continue
		}
		if !strings.HasPrefix(line, "devin-mcp= devin-archive= go ") {
			t.Fatalf("unexpected Devin metadata contamination: %s", line)
		}
	}
	want := 0
	if requireEnabled {
		want = 1
	}
	if count != want {
		t.Fatalf("enabled Devin metadata count=%d want=%d: %s", count, want, calls)
	}
}

func (fixture nativeGateFixture) calls(t *testing.T) string {
	t.Helper()
	contents, err := os.ReadFile(fixture.callsPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func TestNativeCandidateRequiresExplicitMCPProtectionGate(t *testing.T) {
	const name = "TestPromotedArtifactNativeProductionMCPProtection"
	t.Run("supplied candidate and verbose invocation", func(t *testing.T) {
		fixture := newNativeGateFixture(t)
		fixture.run(t, "success", true, "")
		calls := fixture.calls(t)
		discovery := "go test ./acceptance -list ^" + name + "$"
		execution := "auth= promoted=" + fixture.candidate + " version=v0.4.0 backend=available recovery= go test ./acceptance -run ^" + name + "$ -count=1 -v"
		if !strings.Contains(calls, discovery) || !strings.Contains(calls, execution) {
			t.Fatalf("required scoped MCP gate absent: %s", calls)
		}
	})
	t.Run("missing declaration refuses and recovers", func(t *testing.T) {
		fixture := newNativeGateFixture(t)
		fixture.run(t, "missing-mcp-protection", false, "required test "+name+" is unavailable")
		calls := fixture.calls(t)
		if strings.Contains(calls, "-run ^"+name+"$") || strings.Contains(calls, "-run ^TestPromotedArtifactNativeInstructionRules$") {
			t.Fatal("continued after missing required test")
		}
		if !strings.Contains(calls, "-run ^TestNativeKeychainRecoveryEntrypoint$") {
			t.Fatal("recovery omitted")
		}
	})
	t.Run("witness failure preserves status and recovers", func(t *testing.T) {
		fixture := newNativeGateFixture(t)
		output, err := fixture.command("fail-mcp-protection").CombinedOutput()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 31 {
			t.Fatalf("got %v output=%q", err, output)
		}
		calls := fixture.calls(t)
		if strings.Contains(calls, "-run ^TestPromotedArtifactNativeInstructionRules$") {
			t.Fatal("continued after failed witness")
		}
		if !strings.Contains(calls, "-run ^TestNativeKeychainRecoveryEntrypoint$") {
			t.Fatal("recovery omitted")
		}
	})
}

func TestNativeCandidateRequiredRealDevinMCPGate(t *testing.T) {
	const name = "TestPromotedArtifactNativeRealDevinMCP"
	t.Run("exact scoped invocation and broad isolation", func(t *testing.T) {
		f := newNativeGateFixture(t)
		f.run(t, "success", true, "")
		calls := f.calls(t)
		for _, want := range []string{
			"go test ./acceptance -list ^" + name + "$",
			"auth= promoted=" + f.candidate + " version=v0.4.0 backend=available recovery= go test ./acceptance -run ^" + name + "$ -count=1 -v",
			"devin-mcp=1 devin-archive=" + f.devinArchive + " go test ./acceptance -run ^" + name + "$ -count=1 -v",
			"devin-mcp= devin-archive= go test -v ./...",
			"devin-mcp= devin-archive= go test -race ./...",
			"devin-mcp= devin-archive= go test ./acceptance -count=1",
		} {
			if !strings.Contains(calls, want) {
				t.Fatalf("missing %q in %s", want, calls)
			}
		}
		if strings.Count(calls, "devin-mcp=1 ") != 1 {
			t.Fatal("native proof enabled outside exact gate")
		}
	})
	t.Run("missing required declaration", func(t *testing.T) {
		f := newNativeGateFixture(t)
		f.run(t, "missing-real-devin-mcp", false, "required test "+name+" is unavailable")
		calls := f.calls(t)
		if strings.Contains(calls, "-run ^"+name+"$") || strings.Contains(calls, "-run ^TestPromotedArtifactNativeInstructionRules$") {
			t.Fatal("missing test did not halt")
		}
		if !strings.Contains(calls, "-run ^TestNativeKeychainRecoveryEntrypoint$") {
			t.Fatal("missing recovery")
		}
	})
	t.Run("failure preserves status and recovers", func(t *testing.T) {
		f := newNativeGateFixture(t)
		out, err := f.command("fail-real-devin-mcp").CombinedOutput()
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 37 {
			t.Fatalf("exit=%v output=%q", err, out)
		}
		calls := f.calls(t)
		if strings.Contains(calls, "-run ^TestPromotedArtifactNativeInstructionRules$") {
			t.Fatal("continued after failure")
		}
		if !strings.Contains(calls, "-run ^TestNativeKeychainRecoveryEntrypoint$") {
			t.Fatal("missing recovery")
		}
	})
	for _, kind := range []string{"absent", "relative", "symlink"} {
		t.Run("archive "+kind, func(t *testing.T) {
			f := newNativeGateFixture(t)
			archive := f.devinArchive
			switch kind {
			case "absent":
				if err := os.Remove(archive); err != nil {
					t.Fatal(err)
				}
			case "relative":
				archive = "relative.tar.gz"
			case "symlink":
				if err := os.Remove(archive); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(f.archive, archive); err != nil {
					t.Fatal(err)
				}
			}
			cmd := f.command("success")
			cmd.Env = append(cmd.Env, "ACS_TEST_DEVIN_ARCHIVE="+archive)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "Devin archive") {
				t.Fatalf("archive refusal=%v %q", err, out)
			}
			if _, err := os.Stat(f.callsPath); !os.IsNotExist(err) {
				t.Fatal("invalid archive reached Go/native work")
			}
		})
	}
}
