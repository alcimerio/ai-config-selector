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
			"go test ./...",
			"TestPromotedArtifactSharedTargetConformance",
			"generic_literal_command_uses_candidate_containment",
			"effective_explanation_is_linked_and_narrowly_observed",
			"go test -race ./...",
			"TestNativeKeychainCredentialFreeContract",
			"TestNativeRealStoreInstalledTargetComposition",
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
			"auth= promoted= version= backend= recovery= go test ./...",
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
	root      string
	bin       string
	candidate string
	target    string
	archive   string
	callsPath string
}

func newNativeGateFixture(t *testing.T) nativeGateFixture {
	t.Helper()
	root := t.TempDir()
	fixture := nativeGateFixture{
		root:      root,
		bin:       filepath.Join(root, "bin"),
		candidate: filepath.Join(root, "acs"),
		target:    filepath.Join(root, "codex"),
		archive:   filepath.Join(root, "codex.tar.gz"),
		callsPath: filepath.Join(root, "calls"),
	}
	if err := os.Mkdir(fixture.bin, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{fixture.candidate, fixture.target} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(fixture.archive, []byte("locked archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeGo := `#!/bin/sh
printf 'auth=%s promoted=%s version=%s backend=%s recovery=%s go %s\n' "${ACS_RUN_NATIVE_AUTH_GATE:-}" "${ACS_PROMOTED_BINARY:-}" "${ACS_PROMOTED_VERSION:-}" "${ACS_PROMOTED_SANDBOX_BACKEND:-}" "${ACS_RUN_NATIVE_AUTH_RECOVERY:-}" "$*" >>"$ACS_TEST_CALLS"
previous=
for argument do
  if [ "$previous" = -list ]; then
    printf '%s\n' "$argument" | tr -d '^$'
  fi
  previous="$argument"
done
case "$ACS_TEST_MODE:$*" in
  fail-primary*:*"-run ^TestNativeInstalledACSExecutesLockedCodexToolThroughNamedIdentity$"*) printf '%s\n' 'primary gate failed' >&2; exit 23 ;;
  fail-*recovery:*TestNativeKeychainRecoveryEntrypoint*) printf '%s\n' 'recovery failed' >&2; exit 29 ;;
  mutate-candidate:*"-run ^TestNativeInstalledACSExecutesLockedCodexToolThroughNamedIdentity$"*) printf '%s\n' replacement >"$ACS_PROMOTED_BINARY"; chmod 0700 "$ACS_PROMOTED_BINARY" ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(fixture.bin, "go"), []byte(fakeGo), 0o700); err != nil {
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
	command := exec.Command("sh", "run-native-candidate-gates.sh", "v0.4.0", fixture.candidate, fixture.target, fixture.archive, filepath.Join(fixture.root, "recovery"), "available")
	command.Env = append(os.Environ(),
		"PATH="+fixture.bin+":"+os.Getenv("PATH"),
		"ACS_TEST_CALLS="+fixture.callsPath,
		"ACS_TEST_MODE="+mode,
		"ACS_PROMOTED_VERSION=ambient-version",
		"ACS_PROMOTED_BINARY=/ambient/candidate",
		"ACS_PROMOTED_SANDBOX_BACKEND=ambient-backend",
		"ACS_RUN_NATIVE_AUTH_GATE=ambient-auth",
		"ACS_RUN_NATIVE_AUTH_RECOVERY=ambient-recovery",
		"ACS_NATIVE_AUTH_RECOVERY_ROOT=/ambient/recovery",
		"ACS_TEST_CODEX_BINARY=/ambient/codex",
		"ACS_TEST_CODEX_ARCHIVE=/ambient/codex.tar.gz",
	)
	return command
}

func (fixture nativeGateFixture) calls(t *testing.T) string {
	t.Helper()
	contents, err := os.ReadFile(fixture.callsPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}
