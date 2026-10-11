package scripts

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestLinuxNativeWorkflowContract(t *testing.T) {
	workflow := readRepositoryFile(t, "..", ".github/workflows/linux-native.yml")
	for _, required := range []string{
		"  pull_request:\n", "  push:\n", "  workflow_dispatch:\n",
		"permissions:\n  contents: read\n", "runs-on: ubuntu-24.04\n",
		"ACS_LINUX_NATIVE_REQUIRED: \"1\"", "CGO_ENABLED: \"0\"",
		"persist-credentials: false", "uname -a", "^TestNativeLinuxHostEvidence$",
		"sudo apt-get install --no-install-recommends -y bubblewrap",
		"bash scripts/run-linux-native-gates.sh", "do not require this check in branch protection",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("native workflow omits %q", required)
		}
	}
	for _, action := range regexp.MustCompile(`(?m)^\s+uses: (\S+)`).FindAllStringSubmatch(workflow, -1) {
		if !regexp.MustCompile(`@[0-9a-f]{40}$`).MatchString(action[1]) {
			t.Errorf("action is not SHA-pinned: %s", action[1])
		}
	}
	for _, forbidden := range []string{"continue-on-error:", "pull_request_target:", "paths-ignore:", "container:", "-race"} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("native workflow contains %q", forbidden)
		}
	}
	if strings.Index(workflow, "uname -a") > strings.Index(workflow, "sudo apt-get") {
		t.Fatal("host evidence must be recorded before setup")
	}
}

func TestLinuxNativeGateFailsClosed(t *testing.T) {
	for _, mode := range []string{"success", "delegation", "prerequisite", "install", "skip", "missing", "empty", "test-failure"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newLinuxNativeGateFixture(t)
			output, err := fixture.run(t, mode)
			calls, readErr := os.ReadFile(fixture.calls)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if (err == nil) != (mode == "success") {
				t.Fatalf("gate result: %v\n%s", err, output)
			}
			if !strings.Contains(string(calls), "systemd-run --user --scope --property=Delegate=yes --quiet") {
				t.Fatal("gate did not request user cgroup delegation")
			}
			if mode == "delegation" || mode == "prerequisite" {
				if strings.Contains(string(calls), "install-") || strings.Contains(string(calls), "./internal/launch") {
					t.Fatal("missing prerequisite reached target installation or containment")
				}
				if !strings.Contains(output, "do not require this check in branch protection yet") {
					t.Fatal("missing prerequisite omitted runner qualification guidance")
				}
			}
			if mode == "success" {
				for _, required := range []string{
					"install-devin-test-target.sh", "fetch-codex-test-targets.sh",
					"install-codex-test-target.sh", "0.149.1", "0.156.0",
					"./internal/launch", "./internal/codexauthresource", "./internal/executor",
					"required=1 cgo=0",
				} {
					if !strings.Contains(string(calls), required) {
						t.Errorf("gate omitted %s: %s", required, calls)
					}
				}
			}
			if mode == "skip" && !strings.Contains(output, "skipped an assertion") {
				t.Fatal("nested skip was not rejected")
			}
			if (mode == "missing" || mode == "empty") && !strings.Contains(output, "did not pass required test") {
				t.Fatal("missing assertion was not rejected")
			}
		})
	}
}

type linuxNativeGateFixture struct {
	script, root, bin, calls, transcript string
}

func newLinuxNativeGateFixture(t *testing.T) linuxNativeGateFixture {
	t.Helper()
	root := filepath.Join(t.TempDir(), "native fixture with spaces")
	scripts := filepath.Join(root, "scripts")
	bin := filepath.Join(root, "bin")
	for _, dir := range []string{scripts, bin} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	gate := readRepositoryFile(t, ".", "run-linux-native-gates.sh")
	script := filepath.Join(scripts, "run-linux-native-gates.sh")
	writeFakeExecutable(t, script, gate)
	// Synthetic test output tests the gate's handling of Go's exit status,
	// missing assertions and nested skips; it supplies no kernel evidence.
	var transcript strings.Builder
	for _, name := range regexp.MustCompile(`\bTest[A-Za-z0-9_]+\b`).FindAllString(gate, -1) {
		transcript.WriteString("--- PASS: " + name + " (0.00s)\n")
	}
	transcriptPath := filepath.Join(root, "transcript")
	if err := os.WriteFile(transcriptPath, []byte(transcript.String()), 0600); err != nil {
		t.Fatal(err)
	}
	writeFakeExecutable(t, filepath.Join(bin, "systemd-run"), `#!/bin/sh
printf 'systemd-run %s\n' "$*" >> "$NATIVE_GATE_CALLS"
if [ "$NATIVE_GATE_MODE" = delegation ]; then exit 1; fi
[ "$1 $2 $3 $4" = '--user --scope --property=Delegate=yes --quiet' ] || exit 91
shift 4
exec "$@"
`)
	writeFakeExecutable(t, filepath.Join(bin, "go"), `#!/bin/sh
printf 'go %s required=%s cgo=%s\n' "$*" "$ACS_LINUX_NATIVE_REQUIRED" "$CGO_ENABLED" >> "$NATIVE_GATE_CALLS"
[ "$ACS_LINUX_NATIVE_REQUIRED:$CGO_ENABLED" = 1:0 ] || exit 92
case "$*" in
  *./internal/linuxprobe*)
    if [ "$NATIVE_GATE_MODE" = prerequisite ]; then
      printf 'linux.kernel: fail: observed kernel 6.8; require >=6.12\n'
      exit 1
    fi ;;
  *./internal/launch*)
    case "$NATIVE_GATE_MODE" in
      skip) cat "$NATIVE_GATE_TRANSCRIPT"; printf '    --- SKIP: TestLinuxNativeBwrapComposition/denial (0.00s)\n'; exit 0 ;;
      missing) sed '/^--- PASS: TestLinuxNativeBwrapComposition (/d' "$NATIVE_GATE_TRANSCRIPT"; exit 0 ;;
      empty) printf 'testing: warning: no tests to run\nPASS\n'; exit 0 ;;
      test-failure) cat "$NATIVE_GATE_TRANSCRIPT"; exit 1 ;;
    esac ;;
esac
cat "$NATIVE_GATE_TRANSCRIPT"
`)
	for _, name := range []string{"install-devin-test-target.sh", "fetch-codex-test-targets.sh", "install-codex-test-target.sh"} {
		writeFakeExecutable(t, filepath.Join(scripts, name), `#!/bin/sh
printf '%s %s\n' "$0" "$*" >> "$NATIVE_GATE_CALLS"
if [ "$NATIVE_GATE_MODE" = install ]; then exit 1; fi
`)
	}
	return linuxNativeGateFixture{script, root, bin, filepath.Join(root, "calls"), transcriptPath}
}

func (f linuxNativeGateFixture) run(t *testing.T, mode string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", f.script, filepath.Join(f.root, "evidence"))
	for _, variable := range os.Environ() {
		key, _, _ := strings.Cut(variable, "=")
		if key != "PATH" && key != "ACS_LINUX_NATIVE_REQUIRED" && key != "CGO_ENABLED" && !strings.HasPrefix(key, "NATIVE_GATE_") {
			cmd.Env = append(cmd.Env, variable)
		}
	}
	cmd.Env = append(cmd.Env, "PATH="+f.bin+":"+os.Getenv("PATH"),
		"NATIVE_GATE_MODE="+mode, "NATIVE_GATE_CALLS="+f.calls, "NATIVE_GATE_TRANSCRIPT="+f.transcript,
		"ACS_LINUX_NATIVE_REQUIRED=0", "CGO_ENABLED=1")
	output, err := cmd.CombinedOutput()
	return string(output), err
}
