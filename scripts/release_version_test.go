package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var noncanonicalReleaseVersions = []string{
	"", "latest", "1.2.3", "V1.2.3", "vv1.2.3", "v",
	"v1", "v1.2", "v1.2.3.4", "v.1.2", "v1..2", "v1.2.",
	"v1.2.3.", "v1.2.3..", "v1.2..3", "v1.2.3.4.",
	"v01.2.3", "v1.02.3", "v1.2.03", "v00.0.0",
	"v1.2.3-rc.1", "v1.2.3+build", "v0.0.0-20260805002849-816e7b63d8fb",
	"v1.2.3x", "v1.2.30x", "v10x.2.3", "v1.20x.3",
	"v1.2.30/extra", "v1.2.30*", "v1.2.30?", "v1.2.30[0]",
	" v1.2.3", "v1.2.3 ", "v1.2.30\t", "v1.2.30\r", "v1.2.30\n",
	"v12\n.3.4", "v1.2.30\x1b[31m", "v١.2.3", "v1.２.3",
}

func TestReleaseVersionPredicatePreservesCallerState(t *testing.T) {
	module, err := filepath.Abs("release-version.sh")
	if err != nil {
		t.Fatal(err)
	}
	versions := []struct {
		version string
		valid   bool
	}{
		{"v0.0.0", true},
		{"v1.2.3", true},
		{"v9.10.99", true},
		{"v10.200.3000", true},
		{"v0.12.0", true},
		{"v" + strings.Repeat("9", 64) + ".0.1", true},
		{"v1." + strings.Repeat("9", 64) + ".0", true},
		{"v0.1." + strings.Repeat("9", 64), true},
	}
	for _, version := range noncanonicalReleaseVersions {
		versions = append(versions, struct {
			version string
			valid   bool
		}{version, false})
	}
	for _, shell := range []string{"sh", "bash"} {
		t.Run(shell, func(t *testing.T) {
			for _, version := range versions {
				t.Run(version.version, func(t *testing.T) {
					want := "invalid"
					if version.valid {
						want = "valid"
					}
					command := exec.Command(shell, "-c", `
set -eu
. "$1"
input="$2"
want="$3"
# The predicate needs no external commands and must not alter its caller.
PATH=/unavailable
IFS=:
LC_ALL=C
version=version
major=major
minor_patch=minor_patch
minor=minor
patch=patch
component=component
set -f
set -- first 'second argument'
options=$-
if acs_is_release_version "$input"; then result=valid; else result=invalid; fi
[ "$result" = "$want" ]
if acs_is_release_version || acs_is_release_version "$input" extra; then exit 1; fi
[ "$#" -eq 2 ]
[ "$1" = first ]
[ "$2" = 'second argument' ]
[ "$IFS" = : ]
[ "$LC_ALL" = C ]
[ "$-" = "$options" ]
[ "$version" = version ]
[ "$major" = major ]
[ "$minor_patch" = minor_patch ]
[ "$minor" = minor ]
[ "$patch" = patch ]
[ "$component" = component ]
`, "release-version-test", module, version.version, want)
					if output, err := command.CombinedOutput(); err != nil || len(output) != 0 {
						t.Fatalf("predicate must return %s without output or caller changes: %v; output=%q", want, err, output)
					}
				})
			}
		})
	}
}

func TestReleaseScriptsRejectNoncanonicalVersionsBeforeExternalWork(t *testing.T) {
	for _, script := range []struct {
		name      string
		shell     string
		arguments []string
		message   string
		status    int
	}{
		{"release-candidate.sh", "sh", nil, "release candidate version must be a canonical SemVer tag", 2},
		{"release-tag-identity.sh", "sh", nil, "tag=unvalidated stage=tag-name: tag is not a canonical SemVer release", 1},
		{"prepare-release-tag.sh", "sh", nil, "tag=unvalidated source=unvalidated stage=arguments: release tag is not canonical SemVer", 1},
		{"validate-promoted-artifact.sh", "sh", []string{"darwin", "arm64", "candidate", "install"}, "target=unvalidated candidate=unvalidated stage=arguments: candidate version is not a canonical SemVer tag", 1},
		{"publish-release.sh", "bash", []string{publicationSource, publicationTagObject, "candidate", "notes"}, "tag=unvalidated source=unvalidated stage=arguments: release tag is invalid", 1},
	} {
		t.Run(script.name, func(t *testing.T) {
			scriptPath, err := filepath.Abs(script.name)
			if err != nil {
				t.Fatal(err)
			}
			for _, version := range noncanonicalReleaseVersions {
				t.Run(version, func(t *testing.T) {
					workspace := t.TempDir()
					log := filepath.Join(workspace, "external-calls")
					for _, tool := range []string{"git", "go", "gh", "uname"} {
						writeExecutable(t, workspace, tool, "#!/bin/sh\nprintf '%s\\n' unexpected >>\"$ACS_TEST_CALLS\"\nexit 91\n")
					}
					arguments := append([]string{scriptPath, version}, script.arguments...)
					command := exec.Command(script.shell, arguments...)
					command.Dir = workspace
					command.Env = append(os.Environ(), "PATH="+workspace+string(os.PathListSeparator)+os.Getenv("PATH"), "ACS_TEST_CALLS="+log)
					output, err := command.CombinedOutput()
					if err == nil || command.ProcessState == nil || command.ProcessState.ExitCode() != script.status {
						t.Errorf("exit = %v, want status %d; output=%q", err, script.status, output)
					}
					if !strings.Contains(string(output), script.message) {
						t.Errorf("diagnostic = %q, want %q", output, script.message)
					}
					if strings.ContainsAny(strings.TrimSuffix(string(output), "\n"), "\r\n\x1b") {
						t.Errorf("diagnostic contains untrusted controls: %q", output)
					}
					if calls, err := os.ReadFile(log); !os.IsNotExist(err) {
						t.Errorf("invalid version reached external work: %q (read error: %v)", calls, err)
					}
				})
			}
		})
	}
}
