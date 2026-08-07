package scripts

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublisherFailsBeforeMutationWhenImmutableReleasesAreDisabled(t *testing.T) {
	candidate := publicationCandidate(t)
	notes := publicationNotes(t)
	tools, log := fakeGH(t, "false", "")
	command := publicationCommand(t, candidate, notes, tools, log)
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "immutable Releases are not enabled") {
		t.Fatalf("immutable-setting rejection = %v, output=%q", err, output)
	}
	calls, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(calls), "--method") || strings.Contains(string(calls), "release upload") {
		t.Fatalf("publisher mutated GitHub before immutable-setting gate: %q", calls)
	}
}

func TestPublisherLeavesAnExactImmutableReleaseUnchanged(t *testing.T) {
	candidate := publicationCandidate(t)
	notes := publicationNotes(t)
	release := publicationReleaseJSON(t, candidate)
	tools, log := fakeGH(t, "true", release)
	command := publicationCommand(t, candidate, notes, tools, log)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("exact immutable retry failed: %v; output=%q", err, output)
	}
	if !strings.Contains(string(output), "status=unchanged") {
		t.Fatalf("retry output = %q", output)
	}
	calls, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(calls), "--method") || strings.Contains(string(calls), "release upload") {
		t.Fatalf("exact retry attempted mutation: %q", calls)
	}
}

func publicationCommand(t *testing.T, candidate, notes, tools, log string) *exec.Cmd {
	t.Helper()
	repository, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", "scripts/publish-release.sh", "v0.2.0", "0123456789abcdef0123456789abcdef01234567", candidate, notes)
	command.Dir = repository
	command.Env = append(os.Environ(),
		"PATH="+tools+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GITHUB_REPOSITORY=owner/repository", "GH_TOKEN=test-token", "FAKE_GH_LOG="+log,
	)
	return command
}

func fakeGH(t *testing.T, immutable, release string) (string, string) {
	t.Helper()
	directory := t.TempDir()
	log := filepath.Join(directory, "calls")
	releasePath := filepath.Join(directory, "release.json")
	if err := os.WriteFile(releasePath, []byte(release), 0o600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
printf '%s\n' "$*" >>"$FAKE_GH_LOG"
case "$*" in
  "api repos/owner/repository/immutable-releases --jq .enabled") printf '%s\n' "` + immutable + `" ;;
  "api repos/owner/repository/releases/tags/v0.2.0") cat "` + releasePath + `" ;;
  *) exit 64 ;;
esac
`
	if err := os.WriteFile(filepath.Join(directory, "gh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return directory, log
}

func publicationCandidate(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	for _, name := range []string{
		"acs_0.2.0_darwin_arm64.tar.gz", "acs_0.2.0_darwin_amd64.tar.gz",
		"acs_0.2.0_linux_amd64.tar.gz", "acs_0.2.0_linux_arm64.tar.gz",
		"SHA256SUMS", "install.sh",
	} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("fixture "+name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return directory
}

func publicationNotes(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notes.md")
	if err := os.WriteFile(path, []byte("Release notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func publicationReleaseJSON(t *testing.T, candidate string) string {
	t.Helper()
	names := []string{
		"acs_0.2.0_darwin_arm64.tar.gz", "acs_0.2.0_darwin_amd64.tar.gz",
		"acs_0.2.0_linux_amd64.tar.gz", "acs_0.2.0_linux_arm64.tar.gz",
		"SHA256SUMS", "install.sh",
	}
	var assets strings.Builder
	for index, name := range names {
		contents, err := os.ReadFile(filepath.Join(candidate, name))
		if err != nil {
			t.Fatal(err)
		}
		if index != 0 {
			assets.WriteByte(',')
		}
		fmt.Fprintf(&assets, `{"name":%q,"size":%d,"digest":"sha256:%x","state":"uploaded"}`, name, len(contents), sha256.Sum256(contents))
	}
	return `{"id":42,"tag_name":"v0.2.0","target_commitish":"0123456789abcdef0123456789abcdef01234567","name":"ACS v0.2.0","body":"Release notes\n","draft":false,"prerelease":false,"immutable":true,"assets":[` + assets.String() + `]}`
}
