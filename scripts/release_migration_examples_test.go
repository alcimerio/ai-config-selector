package scripts

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestReleaseMigrationCandidateSelectionAndRollback(t *testing.T) {
	fixture := newReleaseMigrationFixture(t)
	blocks := releaseMigrationExamples(t)

	script := blocks["inputs"] + blocks["install"] + blocks["compatibility"] + blocks["rollback"]
	output, err := fixture.run(script, nil)
	if err != nil {
		t.Fatalf("documented candidate selection and rollback failed: %v\n%s", err, output)
	}

	commands, err := os.ReadFile(fixture.log)
	if err != nil {
		t.Fatal(err)
	}
	want := "known-good version\ncandidate version\ncandidate version\ncandidate doctor\ncandidate profile list\ncandidate profile show backend-review\n" +
		"candidate profile validate backend-review\ncandidate session list\nknown-good version\n"
	if string(commands) != want {
		t.Fatalf("documented commands = %q, want %q", commands, want)
	}
	if got, err := os.ReadFile(filepath.Join(fixture.maintenance, "rollback-version.txt")); err != nil || string(got) != "acs v0.4.0\n" {
		t.Fatalf("rollback identity = %q, %v", got, err)
	}
}

func TestReleaseMigrationCompatibilityFailureStopsBeforeWrites(t *testing.T) {
	fixture := newReleaseMigrationFixture(t)
	blocks := releaseMigrationExamples(t)
	script := blocks["inputs"] + blocks["install"] + blocks["compatibility"] +
		"acs profile migrate backend-review\n"
	output, err := fixture.run(script, []string{"TEST_FAIL_VALIDATE=1"})
	if err == nil {
		t.Fatalf("nonzero compatibility check did not stop strict shell:\n%s", output)
	}
	commands, err := os.ReadFile(fixture.log)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(commands), "profile migrate") || strings.Contains(string(commands), "session list") {
		t.Fatalf("failed compatibility check reached later operations: %q", commands)
	}
	if got, err := os.ReadFile(fixture.profile); err != nil || string(got) != "legacy profile bytes\n" {
		t.Fatalf("failed check changed Profile: %q, %v", got, err)
	}
}

func TestReleaseMigrationPreviewCancellationPreservesProfile(t *testing.T) {
	fixture := newReleaseMigrationFixture(t)
	fixture.installCandidate()
	block := releaseMigrationExamples(t)["migrate"]
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", "set +e\n"+block+"status=$?\ntest \"$status\" = 130")
	command.Env = append(fixture.environment(), "PATH="+fixture.candidateBin+":/usr/bin:/bin")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("migration cancellation was not observable: %v\n%s", err, output)
	}
	if got, err := os.ReadFile(fixture.profile); err != nil || string(got) != "legacy profile bytes\n" {
		t.Fatalf("cancelled preview changed Profile: %q, %v", got, err)
	}
}

func TestReleaseMigrationPostMigrationInspectionAndExport(t *testing.T) {
	fixture := newReleaseMigrationFixture(t)
	fixture.installCandidate()
	block := releaseMigrationExamples(t)["after-migrate"]
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", "set -eu\n"+block)
	command.Dir = fixture.root
	command.Env = append(fixture.environment(), "PATH="+fixture.candidateBin+":/usr/bin:/bin")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("post-migration inspection and export failed: %v\n%s", err, output)
	}
	exported := filepath.Join(fixture.root, "backend-review.acs-profile.json")
	if got, err := os.ReadFile(exported); err != nil || string(got) != "sanitized exchange\n" {
		t.Fatalf("exported exchange = %q, %v", got, err)
	}
}

func TestReleaseMigrationRecoveryReturnsToStrictParent(t *testing.T) {
	fixture := newReleaseMigrationFixture(t)
	fixture.installCandidate()
	block := releaseMigrationExamples(t)["recovery"]
	parent := "set -eu\nexport SHELLOPTS\ncandidate_bin=\"$TEST_CANDIDATE_BIN\"\n" + releaseMigrationExamples(t)["recovery-shell"] +
		"case $- in *e*) ;; *) exit 91 ;; esac\nprintf parent-continued\n"
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", parent)
	command.Stdin = strings.NewReader(block)
	command.Env = append(fixture.environment(),
		"PATH="+fixture.candidateBin+":/usr/bin:/bin",
		"TEST_CANDIDATE_BIN="+fixture.candidateBin,
		"TEST_FAIL_SHOW=1",
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("documented recovery did not return safely: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "parent-continued") {
		t.Fatalf("strict parent did not continue: %s", output)
	}
}

type releaseMigrationFixture struct {
	t                  *testing.T
	root               string
	candidateDir       string
	candidateBin       string
	knownGood          string
	maintenance        string
	validator, log     string
	profile            string
	candidateBinarySHA string
	archiveSHA         string
	manifestSHA        string
	installerSHA       string
}

func newReleaseMigrationFixture(t *testing.T) *releaseMigrationFixture {
	t.Helper()
	root := t.TempDir()
	fixture := &releaseMigrationFixture{
		t:            t,
		root:         root,
		candidateDir: filepath.Join(root, "promoted candidate"),
		candidateBin: filepath.Join(root, "maintenance", "candidate", "bin"),
		knownGood:    filepath.Join(root, "trusted binaries", "acs"),
		maintenance:  filepath.Join(root, "maintenance"),
		validator:    filepath.Join(root, "validator"),
		log:          filepath.Join(root, "commands.log"),
		profile:      filepath.Join(root, "backend-review.json"),
	}
	for _, directory := range []string{fixture.candidateDir, filepath.Dir(fixture.knownGood)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, contents := range map[string]string{
		"acs_1.2.3_darwin_arm64.tar.gz": "candidate archive\n",
		"SHA256SUMS":                    "candidate manifest\n",
		"install.sh":                    "candidate installer\n",
	} {
		if err := os.WriteFile(filepath.Join(fixture.candidateDir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(contents)))
		switch name {
		case "acs_1.2.3_darwin_arm64.tar.gz":
			fixture.archiveSHA = digest
		case "SHA256SUMS":
			fixture.manifestSHA = digest
		case "install.sh":
			fixture.installerSHA = digest
		}
	}
	if err := os.WriteFile(fixture.profile, []byte("legacy profile bytes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	knownGood := "#!/bin/sh\nprintf 'known-good %s\\n' \"$*\" >> \"$TEST_COMMAND_LOG\"\n[ \"$*\" = version ] && printf 'acs v0.4.0\\n'\n"
	if err := os.WriteFile(fixture.knownGood, []byte(knownGood), 0o700); err != nil {
		t.Fatal(err)
	}
	candidate := `#!/bin/sh
printf 'candidate %s\n' "$*" >> "$TEST_COMMAND_LOG"
case "$*" in
  version) printf 'acs v1.2.3\n' ;;
  'profile validate backend-review') [ "${TEST_FAIL_VALIDATE:-0}" != 1 ] ;;
  'profile migrate backend-review') exit 130 ;;
  'devin create-profile --name backend-review') exit 130 ;;
  'profile show backend-review') [ "${TEST_FAIL_SHOW:-0}" != 1 ] ;;
  'profile export backend-review --file backend-review.acs-profile.json')
    [ ! -e backend-review.acs-profile.json ] || exit 1
    printf 'sanitized exchange\n' > backend-review.acs-profile.json
    ;;
esac
`
	fixture.candidateBinarySHA = fmt.Sprintf("%x", sha256.Sum256([]byte(candidate)))
	validator := `#!/bin/sh
set -eu
[ "$#" = 5 ]
[ "$1" = v1.2.3 ]
[ "$2/$3" = darwin/arm64 ]
[ "$4" = "$ACS_CANDIDATE_DIR" ]
mkdir "$5"
cp "$TEST_CANDIDATE_SOURCE" "$5/acs"
chmod 0700 "$5/acs"
`
	candidateSource := filepath.Join(root, "candidate-source")
	if err := os.WriteFile(candidateSource, []byte(candidate), 0o700); err != nil {
		t.Fatal(err)
	}
	fixture.validator = filepath.Join(root, "scripts", "validate-promoted-artifact.sh")
	if err := os.MkdirAll(filepath.Dir(fixture.validator), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.validator, []byte(validator), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_CANDIDATE_SOURCE", candidateSource)
	return fixture
}

func (fixture *releaseMigrationFixture) installCandidate() {
	fixture.t.Helper()
	if err := os.MkdirAll(fixture.candidateBin, 0o700); err != nil {
		fixture.t.Fatal(err)
	}
	contents, err := os.ReadFile(os.Getenv("TEST_CANDIDATE_SOURCE"))
	if err != nil {
		fixture.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.candidateBin, "acs"), contents, 0o700); err != nil {
		fixture.t.Fatal(err)
	}
}

func (fixture *releaseMigrationFixture) environment() []string {
	return []string{
		"HOME=" + fixture.root,
		"LC_ALL=C",
		"PATH=/usr/bin:/bin",
		"ACS_CANDIDATE_VERSION=v1.2.3",
		"ACS_CANDIDATE_DIR=" + fixture.candidateDir,
		"ACS_CANDIDATE_ARCHIVE_NAME=acs_1.2.3_darwin_arm64.tar.gz",
		"ACS_CANDIDATE_ARCHIVE_SHA256=" + fixture.archiveSHA,
		"ACS_CANDIDATE_MANIFEST_SHA256=" + fixture.manifestSHA,
		"ACS_CANDIDATE_INSTALLER_SHA256=" + fixture.installerSHA,
		"ACS_CANDIDATE_BINARY_SHA256=" + fixture.candidateBinarySHA,
		"ACS_KNOWN_GOOD_BIN=" + fixture.knownGood,
		"ACS_MAINTENANCE_ROOT=" + fixture.maintenance,
		"TEST_CANDIDATE_SOURCE=" + os.Getenv("TEST_CANDIDATE_SOURCE"),
		"TEST_COMMAND_LOG=" + fixture.log,
		"TEST_PROFILE=" + fixture.profile,
	}
}

func (fixture *releaseMigrationFixture) run(script string, extra []string) (string, error) {
	fixture.t.Helper()
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", script)
	command.Dir = fixture.root
	command.Env = append(fixture.environment(), extra...)
	output, err := command.CombinedOutput()
	return string(output), err
}

func releaseMigrationExamples(t *testing.T) map[string]string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "docs", "release-migration-guide.md"))
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`(?s)<!-- candidate-example: ([a-z-]+) -->\n` + "```sh\\n" + `(.*?)` + "```")
	blocks := make(map[string]string)
	for _, match := range pattern.FindAllStringSubmatch(string(contents), -1) {
		blocks[match[1]] = match[2]
	}
	for _, required := range []string{"inputs", "install", "compatibility", "migrate", "after-migrate", "recovery-shell", "recovery", "rollback"} {
		if blocks[required] == "" {
			t.Fatalf("missing candidate example %q", required)
		}
	}
	return blocks
}
