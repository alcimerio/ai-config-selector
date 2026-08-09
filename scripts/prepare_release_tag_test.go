package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareReleaseTagCreatesValidatedLocalTagWithoutPushing(t *testing.T) {
	repository, remote, evidence := prepareReleaseTagRepository(t)
	command := exec.Command("sh", "scripts/prepare-release-tag.sh", "v1.2.3", evidence)
	command.Dir = repository
	command.Env = append(os.Environ(), "PATH="+filepath.Join(repository, "test-bin")+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("release tag preparation failed: %v; output=%q", err, output)
	}
	if !strings.Contains(string(output), "status=local-only") || !strings.Contains(string(output), "git push origin refs/tags/v1.2.3") {
		t.Fatalf("preparation output = %q", output)
	}
	if got := gitOutput(t, repository, "cat-file", "-t", "refs/tags/v1.2.3"); got != "tag" {
		t.Fatalf("tag type = %q", got)
	}
	if got := gitOutput(t, repository, "for-each-ref", "--format=%(contents)", "refs/tags/v1.2.3"); strings.TrimSpace(got) != `{"schema_version":1}` {
		t.Fatalf("tag annotation = %q", got)
	}
	command = exec.Command("git", "--git-dir", remote, "show-ref", "--verify", "--quiet", "refs/tags/v1.2.3")
	if err := command.Run(); err == nil {
		t.Fatal("preparation pushed the release tag")
	}
}

func TestPrepareReleaseTagRejectsSourceThatDoesNotMatchOriginMain(t *testing.T) {
	repository, _, evidence := prepareReleaseTagRepository(t)
	if err := os.WriteFile(filepath.Join(repository, "later"), []byte("later\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGit(t, repository, "add", "later")
	runGit(t, repository, "commit", "--quiet", "-m", "later")

	command := exec.Command("sh", "scripts/prepare-release-tag.sh", "v1.2.3", evidence)
	command.Dir = repository
	output, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "does not match fetched origin/main") {
		t.Fatalf("unpublished source rejection = %v; output=%q", err, output)
	}
}

func prepareReleaseTagRepository(t *testing.T) (string, string, string) {
	t.Helper()
	projectRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	repository := t.TempDir()
	remote := filepath.Join(t.TempDir(), "origin.git")
	runGit(t, repository, "init", "--quiet", "--initial-branch=main")
	runGit(t, repository, "config", "user.name", "Release Test")
	runGit(t, repository, "config", "user.email", "release@example.invalid")
	if err := os.MkdirAll(filepath.Join(repository, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repository, "docs", "releases"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repository, "test-bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	copyTestFile(t, filepath.Join(projectRoot, "scripts", "prepare-release-tag.sh"), filepath.Join(repository, "scripts", "prepare-release-tag.sh"), 0o700)
	copyTestFile(t, filepath.Join(projectRoot, "scripts", "release-tag-identity.sh"), filepath.Join(repository, "scripts", "release-tag-identity.sh"), 0o700)
	writeExecutable(t, filepath.Join(repository, "scripts"), "release-candidate.sh", "#!/bin/sh\nmkdir -p dist/release-candidate\n")
	writeExecutable(t, filepath.Join(repository, "test-bin"), "go", "#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(filepath.Join(repository, ".gitignore"), []byte("dist/\n"), 0o600); err != nil {
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
	runGit(t, filepath.Dir(remote), "init", "--quiet", "--bare", remote)
	runGit(t, repository, "remote", "add", "origin", remote)
	runGit(t, repository, "push", "--quiet", "-u", "origin", "main")
	evidence := filepath.Join(t.TempDir(), "evidence.json")
	if err := os.WriteFile(evidence, []byte("{\"schema_version\":1}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return repository, remote, evidence
}

func copyTestFile(t *testing.T, source, destination string, mode os.FileMode) {
	t.Helper()
	contents, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, contents, mode); err != nil {
		t.Fatal(err)
	}
}

func gitOutput(t *testing.T, directory string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v; output=%q", arguments, err, output)
	}
	return strings.TrimSpace(string(output))
}
