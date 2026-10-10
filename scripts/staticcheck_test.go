package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestStaticcheckUsesModuleToolchainAndTarget(t *testing.T) {
	for _, target := range [][2]string{{"linux", "amd64"}, {"darwin", "arm64"}} {
		t.Run(strings.Join(target[:], "/"), func(t *testing.T) {
			log, cmd := staticcheckCommand(t, target[:]...)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("check failed: %v\n%s", err, output)
			}
			data, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			module := strings.Fields(readRepositoryFile(t, "..", "go.mod"))
			var version string
			for i, field := range module[:len(module)-1] {
				if field == "go" {
					version = "go" + module[i+1]
					break
				}
			}
			want := version + "///\nrun\n-exec\nenv GOOS=" + target[0] + " GOARCH=" + target[1] + " CGO_ENABLED=0\n" +
				"honnef.co/go/tools/cmd/staticcheck@v0.7.0-0.dev.0.20261009230814-452d5bb86b45\n-tests\n./...\n"
			if version == "" || string(data) != want {
				t.Fatalf("analyzer must build on the host with the module's Go version and analyze the requested target:\ngot %q\nwant %q", data, want)
			}
			data, err = os.ReadFile(log + ".analyzer")
			if err != nil {
				t.Fatal(err)
			}
			want = version + "/" + target[0] + "/" + target[1] + "/0\n-tests\n./...\n"
			if string(data) != want {
				t.Fatalf("analyzer did not receive the target, module toolchain and test scope:\ngot %q\nwant %q", data, want)
			}
		})
	}
}

func TestStaticcheckPreservesAnalyzerFailure(t *testing.T) {
	_, cmd := staticcheckCommand(t, "linux", "amd64")
	cmd.Env = append(cmd.Env, "ANALYZER_EXIT=17")
	output, err := cmd.CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 17 || !strings.Contains(string(output), "synthetic analyzer finding") {
		t.Fatalf("analyzer failure was hidden: %v\n%s", err, output)
	}
}

func TestStaticcheckRejectsInvalidTargetsBeforeRunningGo(t *testing.T) {
	for _, args := range [][]string{nil, {"linux"}, {"linux", "amd64", "extra"}, {"darwin", "amd64"}, {"linux", "amd64 arbitrary-command"}} {
		log, cmd := staticcheckCommand(t, args...)
		output, err := cmd.CombinedOutput()
		if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 {
			t.Fatalf("invalid target must fail with usage status 2: %q: %v\n%s", args, err, output)
		}
		if _, err := os.Stat(log); !os.IsNotExist(err) {
			t.Fatalf("invalid target ran Go: %v", err)
		}
	}
}

func staticcheckCommand(t *testing.T, args ...string) (string, *exec.Cmd) {
	t.Helper()
	script, err := filepath.Abs("check-go-staticcheck.sh")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	log := filepath.Join(root, "go.log")
	goStub := `#!/bin/sh
set -eu
printf '%s/%s/%s/%s\n' "$GOTOOLCHAIN" "${GOOS-}" "${GOARCH-}" "${CGO_ENABLED-}" > "$GO_LOG"
printf '%s\n' "$@" >> "$GO_LOG"
[ "$1" = run ] && [ "$2" = -exec ] || exit 80
executor="$3"
shift 4
# Exercise the execution prefix just as go run does, without downloading Go
# or an analyzer during the unit test. Only this prefix is word-split.
set -f
exec $executor "$ANALYZER_STUB" "$@"
`
	analyzerStub := `#!/bin/sh
set -eu
printf '%s/%s/%s/%s\n' "$GOTOOLCHAIN" "$GOOS" "$GOARCH" "$CGO_ENABLED" > "$GO_LOG.analyzer"
printf '%s\n' "$@" >> "$GO_LOG.analyzer"
if [ "${ANALYZER_EXIT:-0}" -ne 0 ]; then
  printf '%s\n' 'synthetic analyzer finding' >&2
  exit "$ANALYZER_EXIT"
fi
`
	if err := os.WriteFile(filepath.Join(root, "go"), []byte(goStub), 0700); err != nil {
		t.Fatal(err)
	}
	analyzer := filepath.Join(root, "analyzer stub")
	if err := os.WriteFile(analyzer, []byte(analyzerStub), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", append([]string{script}, args...)...)
	cmd.Dir = root // The helper must find go.mod independently of the caller.
	cmd.Env = append(os.Environ(),
		"PATH="+root+":"+os.Getenv("PATH"), "GO_LOG="+log, "ANALYZER_STUB="+analyzer,
		"GOOS=windows", "GOARCH=386", "CGO_ENABLED=1", "GOTOOLCHAIN=go1.26.9")
	return log, cmd
}
