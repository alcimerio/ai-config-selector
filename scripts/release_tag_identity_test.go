package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReleaseTagIdentityRequiresAnnotatedTagNotesAndCleanExactSource(t *testing.T) {
	script, err := filepath.Abs("release-tag-identity.sh")
	if err != nil {
		t.Fatal(err)
	}
	repository := t.TempDir()
	runGit(t, repository, "init", "--quiet")
	runGit(t, repository, "config", "user.name", "Release Test")
	runGit(t, repository, "config", "user.email", "release@example.invalid")
	if err := os.MkdirAll(filepath.Join(repository, "docs", "releases"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "source"), []byte("source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repository, "docs", "releases", "v1.2.3.md"), []byte("notes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, repository, "add", ".")
	runGit(t, repository, "commit", "--quiet", "-m", "source")
	runGit(t, repository, "tag", "-a", "v1.2.3", "-m", "Release v1.2.3")

	command := exec.Command("sh", script, "v1.2.3")
	command.Dir = repository
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("annotated release tag rejected: %v; output=%q", err, output)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 2 || len(lines[0]) != 40 || len(lines[1]) != 40 {
		t.Fatalf("release identity output = %q", output)
	}
	command = exec.Command("sh", script, "v1.2.3x")
	command.Dir = repository
	output, err = command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "not a canonical SemVer") {
		t.Fatalf("malformed tag rejection = %v, output=%q", err, output)
	}
	runGit(t, repository, "tag", "v1.2.4")
	command = exec.Command("sh", script, "v1.2.4")
	command.Dir = repository
	output, err = command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "not annotated") {
		t.Fatalf("lightweight tag rejection = %v, output=%q", err, output)
	}
}

func runGit(t *testing.T, directory string, arguments ...string) {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = directory
	command.Env = append(os.Environ(), "GIT_AUTHOR_DATE=2026-08-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-08-02T00:00:00Z")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v; output=%q", arguments, err, output)
	}
}
