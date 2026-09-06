package scripts

import (
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Execute the documented shell blocks against fake release assets. Only the
// operator-supplied old path and trusted digest inputs are replaced; the shell
// operations, checks and PATH changes are the ones a reader runs.
func TestManualUpgradeExamples(t *testing.T) {
	for _, arch := range []string{"arm64", "x86_64"} {
		t.Run(arch, func(t *testing.T) {
			fixture := newManualUpgradeFixture(t, arch)
			before := fixture.protectedSnapshot()
			output, err := fixture.run("")
			if err != nil {
				t.Fatalf("manual upgrade examples: %v\n%s", err, output)
			}
			fixture.assertProtectedUnchanged(before)
			root := filepath.Join(fixture.installer.home, "ACS Maintenance v0.4.0")
			for name, expected := range map[string]string{
				"selected-version.txt": "acs v0.4.0\n",
				"resolved-version.txt": "acs v0.4.0\n",
				"rollback-version.txt": "acs v0.3.3\n",
			} {
				got, err := os.ReadFile(filepath.Join(root, name))
				if err != nil || string(got) != expected {
					t.Fatalf("%s = %q, %v; want %q", name, got, err, expected)
				}
			}
			profiles := filepath.Join(fixture.installer.home, ".acs", "profiles")
			backupDirectory, err := os.Stat(filepath.Join(root, "profiles-before-changes"))
			if err != nil || backupDirectory.Mode().Perm() != 0o700 {
				t.Fatalf("Profile backup directory is not private: %v", err)
			}
			entries, err := os.ReadDir(profiles)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if !strings.HasSuffix(entry.Name(), ".json") {
					continue
				}
				original, err := os.ReadFile(filepath.Join(profiles, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				copied := filepath.Join(root, "profiles-before-changes", entry.Name())
				backup, err := os.ReadFile(copied)
				if err != nil || string(backup) != string(original) {
					t.Fatalf("Profile backup changed bytes: %v", err)
				}
				info, err := os.Stat(copied)
				if err != nil || info.Mode().Perm() != 0o600 {
					t.Fatalf("Profile backup is not private: %v", err)
				}
			}
			urls, err := os.ReadFile(fixture.installer.urlLog)
			if err != nil {
				t.Fatal(err)
			}
			goarch := arch
			if arch == "x86_64" {
				goarch = "amd64"
			}
			wantURLs := "https://github.com/alcimerio/ai-config-selector/releases/download/v0.4.0/install.sh\n" +
				"https://github.com/alcimerio/ai-config-selector/releases/download/v0.4.0/acs_0.4.0_darwin_" + goarch + ".tar.gz\n" +
				"https://github.com/alcimerio/ai-config-selector/releases/download/v0.4.0/SHA256SUMS\n"
			if string(urls) != wantURLs {
				t.Fatalf("downloads = %q, want %q", urls, wantURLs)
			}
		})
	}
}

func TestManualUpgradeExamplesStopBeforeUnsafeSelection(t *testing.T) {
	for _, fault := range []string{"installer digest", "binary digest", "binary version", "shell function", "rollback digest", "linked Profile"} {
		t.Run(fault, func(t *testing.T) {
			fixture := newManualUpgradeFixture(t, "arm64")
			if fault == "linked Profile" {
				if err := os.Symlink(filepath.Join(fixture.installer.home, ".codex", "auth.json"), filepath.Join(fixture.installer.home, ".acs", "profiles", "linked.json")); err != nil {
					t.Fatal(err)
				}
			}
			before := fixture.protectedSnapshot()
			output, err := fixture.run(fault)
			if err == nil {
				t.Fatalf("%s did not stop the examples:\n%s", fault, output)
			}
			fixture.assertProtectedUnchanged(before)
			root := filepath.Join(fixture.installer.home, "ACS Maintenance v0.4.0")
			if fault == "installer digest" || fault == "binary digest" || fault == "binary version" || fault == "shell function" {
				if _, err := os.Lstat(filepath.Join(root, "resolved-version.txt")); !os.IsNotExist(err) {
					t.Fatalf("failed verification reached PATH-selected execution: %v", err)
				}
			}
			if fault == "rollback digest" {
				if _, err := os.Lstat(filepath.Join(root, "rollback-version.txt")); !os.IsNotExist(err) {
					t.Fatalf("failed rollback verification executed retained binary: %v", err)
				}
			}
		})
	}
}

func TestManualRecoveryExamplesRetainShellForInspection(t *testing.T) {
	blocks := manualExamples(t)
	for _, scenario := range []struct {
		name           string
		showStatus     string
		recoveryStatus string
	}{
		{name: "missing Profile", showStatus: "1"},
		{name: "recovered duplicate", showStatus: "0", recoveryStatus: "1"},
		{name: "cancelled builder", showStatus: "1", recoveryStatus: "130"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			root := realTemporaryDirectory(t)
			binary := filepath.Join(root, "source acs")
			logPath := filepath.Join(root, "commands.log")
			fake := `#!/bin/sh
printf '%s\n' "$*" >> "$TEST_COMMAND_LOG"
case "$*" in
  version) printf 'acs devel\n' ;;
  'profile list') exit 0 ;;
  'profile show backend-review') exit "$TEST_SHOW_STATUS" ;;
  'devin create-profile --name backend-review') exit "$TEST_RECOVERY_STATUS" ;;
  *) exit 99 ;;
esac
`
			if err := os.WriteFile(binary, []byte(fake), 0o700); err != nil {
				t.Fatal(err)
			}
			script := strings.ReplaceAll(blocks["recovery-inspection"], `source_bin="/absolute/path/to/compatible-source/acs"`, `source_bin="$TEST_SOURCE_BINARY"`)
			script += "test \"$?\" = \"$TEST_SHOW_STATUS\" || exit 90\n"
			if scenario.recoveryStatus != "" {
				script += blocks["profile-recovery"] + "test \"$?\" = \"$TEST_RECOVERY_STATUS\" || exit 91\n"
			}
			script += blocks["recovery-follow-up"]
			script += "test \"$?\" = \"$TEST_SHOW_STATUS\" || exit 92\n"
			script += "test \"$source_bin\" = \"$TEST_SOURCE_BINARY\" || exit 93\n"
			scriptPath := filepath.Join(root, "recovery commands.sh")
			if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
				t.Fatal(err)
			}
			// Export the strict parent's options to prove the documented child
			// explicitly disables errexit even when SHELLOPTS is inherited.
			parent := "set -eu\nexport SHELLOPTS\n" + strings.TrimSpace(blocks["recovery-shell"]) + " \"$TEST_RECOVERY_SCRIPT\"\n"
			command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", parent)
			command.Dir = root
			command.Env = []string{
				"HOME=" + root, "PATH=/usr/bin:/bin", "LC_ALL=C",
				"TEST_SOURCE_BINARY=" + binary, "TEST_COMMAND_LOG=" + logPath,
				"TEST_RECOVERY_SCRIPT=" + scriptPath, "TEST_SHOW_STATUS=" + scenario.showStatus,
				"TEST_RECOVERY_STATUS=" + scenario.recoveryStatus,
			}
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("recovery flow lost its shell or source executable: %v\n%s", err, output)
			}
			commands, err := os.ReadFile(logPath)
			if err != nil {
				t.Fatal(err)
			}
			want := "version\nprofile list\nprofile show backend-review\n"
			if scenario.recoveryStatus != "" {
				want += "devin create-profile --name backend-review\n"
			}
			want += "profile list\nprofile show backend-review\n"
			if string(commands) != want {
				t.Fatalf("follow-up inspection did not use the intended executable: %q", commands)
			}
		})
	}
}

func TestManualRecoveryExamplesReturnToStrictParent(t *testing.T) {
	blocks := manualExamples(t)
	root := realTemporaryDirectory(t)
	binary := filepath.Join(root, "source acs")
	fake := `#!/bin/sh
case "$*" in
  'profile show backend-review') printf 'missing Profile\n'; exit 1 ;;
esac
`
	if err := os.WriteFile(binary, []byte(fake), 0o700); err != nil {
		t.Fatal(err)
	}
	script := strings.ReplaceAll(blocks["recovery-inspection"], `source_bin="/absolute/path/to/compatible-source/acs"`, `source_bin="$TEST_SOURCE_BINARY"`)
	// Keep the failed final inspection immediately before the documented exit:
	// a successful status assertion here would hide bare exit's propagation.
	script += blocks["recovery-follow-up"] + blocks["recovery-exit"]
	scriptPath := filepath.Join(root, "recovery commands.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	parent := "set -eu\nexport SHELLOPTS\n" + strings.TrimSpace(blocks["recovery-shell"]) + " \"$TEST_RECOVERY_SCRIPT\"\n"
	parent += "case \"$-\" in *e*) printf 'strict maintenance parent retained\\n' ;; *) exit 94 ;; esac\n"
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", parent)
	command.Dir = root
	command.Env = []string{
		"HOME=" + root, "PATH=/usr/bin:/bin", "LC_ALL=C",
		"TEST_SOURCE_BINARY=" + binary, "TEST_RECOVERY_SCRIPT=" + scriptPath,
	}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("documented recovery exit also exited the strict parent: %v\n%s", err, output)
	}
	if want := "missing Profile\nmissing Profile\nstrict maintenance parent retained\n"; string(output) != want {
		t.Fatalf("recovery did not return to the strict parent: got %q, want %q", output, want)
	}
}

type manualUpgradeFixture struct {
	t         *testing.T
	installer *installerFixture
	blocks    map[string]string
	oldBinary string
	newBytes  string
}

func newManualUpgradeFixture(t *testing.T, arch string) *manualUpgradeFixture {
	t.Helper()
	installer := newInstallerFixture(t, "Darwin", arch)
	installer.home = filepath.Join(installer.home, "home spaces $dollar `touch unexpected-execution` $(touch unexpected-execution)")
	for _, directory := range []string{"old bin", ".acs/profiles", ".acs/sessions/retained", ".acs/sessions.leases", ".acs/locks/codex-auth", ".acs/quarantine/codex-auth", ".codex"} {
		if err := os.MkdirAll(filepath.Join(installer.home, directory), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, contents := range map[string]string{
		".acs/profiles/legacy.json":               "{\"version\":1,\"name\":\"legacy\",\"skillReferences\":[]}\n",
		".acs/profiles/future.json":               "{\"version\":99,\"name\":\"future\",\"unrecognized\":true}\n",
		".acs/profiles/.profile-transaction-lock": "",
		".acs/sessions/retained/sentinel":         "synthetic retained Session sentinel\n",
		".acs/sessions.leases/retained":           "synthetic lease sentinel\n",
		".acs/locks/codex-auth/work.lock":         "synthetic identity lock sentinel\n",
		".acs/quarantine/codex-auth/work":         "synthetic quarantine sentinel\n",
		".codex/auth.json":                        "synthetic global authentication sentinel\n",
	} {
		if err := os.WriteFile(filepath.Join(installer.home, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range []string{"sh", "cmp", "cat", "shasum"} {
		if _, err := os.Lstat(filepath.Join(installer.toolsDirectory, tool)); os.IsNotExist(err) {
			installer.linkTool(tool)
		}
	}
	// An automated fixture cannot perform the reader's manual installer inspection.
	installer.writeTool("less", "#!/bin/sh\ntest \"$1\" = install.sh\n")
	blocks := manualExamples(t)
	fixture := &manualUpgradeFixture{t: t, installer: installer, blocks: blocks, oldBinary: filepath.Join(installer.home, "old bin", "acs")}
	oldBytes := "#!/bin/sh\ntest \"$#\" -eq 1 && test \"$1\" = version || exit 1\nprintf 'acs v0.3.3\\n'\n"
	fixture.newBytes = strings.ReplaceAll(oldBytes, "v0.3.3", "v0.4.0")
	if err := os.WriteFile(fixture.oldBinary, []byte(oldBytes), 0o700); err != nil {
		t.Fatal(err)
	}
	rendered := strings.ReplaceAll(readRepositoryFile(t, ".", "install.sh.tmpl"), "__ACS_RELEASE_VERSION__", "v0.4.0")
	if err := os.WriteFile(filepath.Join(installer.releaseDirectory, "install.sh"), []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	blocks["prepare"] = strings.ReplaceAll(blocks["prepare"], `old_bin="/absolute/path/to/known-good/acs"`, `old_bin="$TEST_OLD_BINARY"`)
	blocks["prepare"] = regexp.MustCompile(`'[0-9a-f]{64}'`).ReplaceAllString(blocks["prepare"], fmt.Sprintf("'%x'", sha256.Sum256([]byte(rendered))))
	blocks["stage"] = regexp.MustCompile(`binary_sha256=[0-9a-f]{64}`).ReplaceAllString(blocks["stage"], fmt.Sprintf("binary_sha256=%x", sha256.Sum256([]byte(fixture.newBytes))))
	return fixture
}

func manualExamples(t *testing.T) map[string]string {
	t.Helper()
	blocks := make(map[string]string)
	document := readRepositoryFile(t, "..", "docs/manual-upgrade-recovery.md")
	pattern := regexp.MustCompile("(?s)<!-- example: ([a-z-]+) -->\n```sh\n(.*?)\n```")
	for _, match := range pattern.FindAllStringSubmatch(document, -1) {
		if _, duplicate := blocks[match[1]]; duplicate {
			t.Fatalf("duplicate shell example %q", match[1])
		}
		blocks[match[1]] = match[2] + "\n"
	}
	return blocks
}

func (fixture *manualUpgradeFixture) run(fault string) (string, error) {
	t := fixture.t
	t.Helper()
	newBytes := fixture.newBytes
	if fault == "binary digest" {
		newBytes += "# Different bytes with the same version.\n"
	}
	if fault == "binary version" {
		newBytes = strings.ReplaceAll(newBytes, "v0.4.0", "v9.9.9")
	}
	var manifest strings.Builder
	for _, arch := range []string{"arm64", "amd64"} {
		name := "acs_0.4.0_darwin_" + arch + ".tar.gz"
		archivePath := filepath.Join(fixture.installer.releaseDirectory, name)
		writeInstallerArchive(t, archivePath, newBytes)
		contents, err := os.ReadFile(archivePath)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&manifest, "%x  %s\n", sha256.Sum256(contents), name)
	}
	if err := os.WriteFile(filepath.Join(fixture.installer.releaseDirectory, "SHA256SUMS"), []byte(manifest.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	var script strings.Builder
	for _, name := range []string{"prepare", "stage", "switch", "rollback", "profile-backup"} {
		block, exists := fixture.blocks[name]
		if !exists {
			t.Fatalf("missing executable example %q", name)
		}
		if name == "prepare" && fault == "installer digest" {
			path := filepath.Join(fixture.installer.releaseDirectory, "install.sh")
			if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 99\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if name == "switch" {
			script.WriteString("hash -p \"$TEST_OLD_BINARY\" acs\n")
			if fault == "shell function" {
				script.WriteString("acs() { printf 'unexpected function execution\\n'; }\n")
			}
		}
		if name == "rollback" && fault == "rollback digest" {
			script.WriteString("printf '# changed\\n' >> \"$rollback_bin/acs\"\n")
		}
		script.WriteString(block)
	}
	command := exec.Command("/bin/bash", "--noprofile", "--norc", "-c", script.String())
	command.Dir = fixture.installer.home
	command.Env = []string{
		"HOME=" + fixture.installer.home,
		"PATH=" + fixture.installer.toolsDirectory + string(os.PathListSeparator) + filepath.Dir(fixture.oldBinary),
		"TMPDIR=" + fixture.installer.temporary,
		"LC_ALL=C",
		"FAKE_RELEASE_DIR=" + fixture.installer.releaseDirectory,
		"FAKE_URL_LOG=" + fixture.installer.urlLog,
		"TEST_OLD_BINARY=" + fixture.oldBinary,
	}
	returnBytes, err := command.CombinedOutput()
	return string(returnBytes), err
}

type manualProtectedEntry struct {
	info   fs.FileInfo
	digest [sha256.Size]byte
}

func (fixture *manualUpgradeFixture) protectedSnapshot() map[string]manualProtectedEntry {
	fixture.t.Helper()
	snapshot := make(map[string]manualProtectedEntry)
	for _, subtree := range []string{"old bin", ".acs", ".codex"} {
		err := filepath.WalkDir(filepath.Join(fixture.installer.home, subtree), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			contents := []byte(nil)
			if info.Mode().IsRegular() {
				contents, err = os.ReadFile(path)
				if err != nil {
					return err
				}
			} else if info.Mode()&os.ModeSymlink != 0 {
				target, err := os.Readlink(path)
				if err != nil {
					return err
				}
				contents = []byte(target)
			}
			snapshot[path] = manualProtectedEntry{info: info, digest: sha256.Sum256(contents)}
			return nil
		})
		if err != nil {
			fixture.t.Fatal(err)
		}
	}
	return snapshot
}

func (fixture *manualUpgradeFixture) assertProtectedUnchanged(before map[string]manualProtectedEntry) {
	fixture.t.Helper()
	after := fixture.protectedSnapshot()
	if len(before) != len(after) {
		fixture.t.Fatal("examples changed protected fixture entries")
	}
	for path, original := range before {
		current, exists := after[path]
		if !exists || original.digest != current.digest || original.info.Mode() != current.info.Mode() || !os.SameFile(original.info, current.info) {
			fixture.t.Fatal("examples changed original binary or protected fixture bytes, modes or inodes")
		}
	}
	if err := filepath.WalkDir(fixture.installer.home, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Name() == "unexpected-execution" {
			return fmt.Errorf("directory text was executed as shell code")
		}
		return nil
	}); err != nil {
		fixture.t.Fatal(err)
	}
}
