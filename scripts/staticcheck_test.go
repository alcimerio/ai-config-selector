package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestStaticcheckUsesProjectToolchainAndPreservesFailures(t *testing.T) {
	for _, target := range []struct{ os, arch string }{{"linux", "amd64"}, {"darwin", "arm64"}} {
		for _, status := range []int{0, 3} {
			t.Run(target.os+"/"+target.arch+"/status="+strconv.Itoa(status), func(t *testing.T) {
				root := t.TempDir()
				writeExecutable(t, root, "go", `#!/bin/sh
set -eu
[ -f go.mod ] || exit 90
[ -z "${GOOS:-}${GOARCH:-}${CGO_ENABLED:-}${GOVERSION:-}" ] || exit 91
case "$1" in
  env)
    [ "$#" -eq 2 ] && [ "$2" = GOVERSION ] || exit 92
    printf '%s\n' go1.99.0
    ;;
  run)
    [ "$GOTOOLCHAIN" = go1.99.0 ] || exit 93
    printf '%s\n' "$@" > "$STATICCHECK_TEST_ROOT/arguments"
    printf '%s\n' 'staticcheck output'
    exit "$STATICCHECK_TEST_STATUS"
    ;;
  *) exit 94 ;;
esac
`)
				script, err := filepath.Abs("check-go-staticcheck.sh")
				if err != nil {
					t.Fatal(err)
				}
				command := exec.Command("sh", script, target.os, target.arch)
				command.Dir = root // The helper must resolve the repository itself.
				command.Env = os.Environ()
				command.Env = append(command.Env,
					"PATH="+root+string(os.PathListSeparator)+os.Getenv("PATH"),
					"GOTOOLCHAIN=auto", "GOOS=freebsd", "GOARCH=386", "CGO_ENABLED=1", "GOVERSION=go1.26.0",
					"STATICCHECK_TEST_ROOT="+root, "STATICCHECK_TEST_STATUS="+strconv.Itoa(status))
				output, err := command.CombinedOutput()
				gotStatus := 0
				if err != nil {
					exitError, ok := err.(*exec.ExitError)
					if !ok {
						t.Fatal(err)
					}
					gotStatus = exitError.ExitCode()
				}
				if gotStatus != status || string(output) != "staticcheck output\n" {
					t.Fatalf("status=%d, want=%d, output=%q", gotStatus, status, output)
				}
				arguments, err := os.ReadFile(filepath.Join(root, "arguments"))
				if err != nil {
					t.Fatal(err)
				}
				want := strings.Join([]string{
					"run", "-exec", "env GOOS=" + target.os + " GOARCH=" + target.arch + " CGO_ENABLED=0",
					"honnef.co/go/tools/cmd/staticcheck@v0.7.0-0.dev.0.20261009230814-452d5bb86b45", "-tests=true", "./...", "",
				}, "\n")
				if string(arguments) != want {
					t.Fatalf("arguments=%q, want=%q", arguments, want)
				}
			})
		}
	}
}
