package scripts

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
)

func TestDevinTargetLockAndNativeProductionGate(t *testing.T) {
	lock, err := os.ReadFile("devin-test-targets.lock")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"3000.10.21|darwin|arm64|c0b97f8197bf3ce895ff14aa19257c511154b49a0a195bba4962acb5e475c68e|https://static.devin.ai/cli/3000.10.21/devin-3000.10.21-aarch64-apple-darwin.tar.gz"} {
		if !strings.Contains(string(lock), want) {
			t.Fatalf("Devin target lock omits %q", want)
		}
	}
	if output, err := exec.Command("sh", "-n", "install-devin-test-target.sh").CombinedOutput(); err != nil {
		t.Fatalf("installer shell syntax: %v %s", err, output)
	}
	for _, workflowName := range []string{"promoted-artifacts.yml", "release.yml"} {
		data, err := os.ReadFile(filepath.Join("..", ".github", "workflows", workflowName))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), "scripts/install-devin-test-target.sh") || !strings.Contains(string(data), "ACS_TEST_DEVIN_BINARY=$target_root/bin/devin") || !strings.Contains(string(data), "ACS_TEST_DEVIN_ARCHIVE=$target_root/devin-3000.10.21-darwin-arm64.tar.gz") {
			t.Errorf("%s omits checksum-locked Devin target installation", workflowName)
		}
	}
	gate, err := os.ReadFile("run-native-candidate-gates.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"TestPromotedArtifactNativeInstructionRules",
		"run_acceptance_test ./acceptance -run '^TestPromotedArtifactNativeInstructionRules$'",
		"TestNativeProductionInstructionRulesReceipts",
		"ACS_RUN_NATIVE_INSTRUCTION_RULES=1 ACS_TEST_DEVIN_BINARY=\"$devin_binary\" go test ./internal/executor",
		"TestSeatbeltCandidateMCPAmbientReadDenialWithAbsentAtPrepareAndAliases",
		"TestSeatbeltCandidateMCPRecipeWriteAndAncestorDenialsPreserveOrdinaryHome",
		"TestSeatbeltCandidatePinnedDevinUsesSelectedHomeMCPConfigOnly",
		"TestSeatbeltCandidatePinnedDevinConfigPathReplacementIsolation",
		"TestSeatbeltCandidatePinnedDevinNestedDiscoveryGrantScope",
		"TestSeatbeltCandidatePinnedDevinDirectorySymlinkRedirection",
		"TestSeatbeltCandidatePinnedDevinReservedConfigBasenames",
		"ACS_RUN_MCP_AMBIENT_FEASIBILITY=1 ACS_TEST_DEVIN_BINARY=\"$devin_binary\" go test ./internal/launch",
	} {
		if !strings.Contains(string(gate), want) {
			t.Errorf("shared native gate omits %q", want)
		}
	}
}

func TestDevinLocksMatchPublishedManifest(t *testing.T) {
	data := mustReadFile(t, "testdata/devin-3000.10.21-manifest.json")
	if fmt.Sprintf("%x", sha256.Sum256(data)) != "b070658dcb6a7a4ed753cdd9b453375118aea1bf5ed3d353dbbbabc627f2d12c" {
		t.Fatal("publisher manifest bytes changed")
	}
	var manifest struct {
		Version   string
		Platforms map[string]struct{ URL, SHA256 string }
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Version != devinruntime.LinuxAMD64Version {
		t.Fatal("published manifest version changed")
	}
	lock := strings.Split(strings.TrimSpace(string(mustReadFile(t, "devin-test-targets.lock"))), "\n")
	seen := map[string]bool{}
	for _, line := range lock {
		if strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) != 5 || fields[0] != manifest.Version {
			t.Fatalf("invalid target row: %q", line)
		}
		platform := map[string]string{"darwin/arm64": "aarch64-apple-darwin", "linux/amd64": "x86_64-unknown-linux"}[fields[1]+"/"+fields[2]]
		if platform == "" || seen[platform] {
			t.Fatalf("unqualified or duplicate platform: %q", line)
		}
		seen[platform] = true
		published := manifest.Platforms[platform]
		if fields[3] != published.SHA256 || fields[4] != published.URL {
			t.Fatal("target lock differs from the recorded publisher manifest")
		}
	}
	if len(seen) != 2 || manifest.Platforms["x86_64-unknown-linux"].SHA256 != devinruntime.LinuxAMD64ArchiveSHA256 {
		t.Fatal("target set or Linux digest changed")
	}
	want := fmt.Sprintf("%s|linux|amd64|bin/devin|%d|%s", devinruntime.LinuxAMD64Version,
		devinruntime.LinuxAMD64BinarySize, devinruntime.LinuxAMD64BinarySHA256)
	if !strings.Contains(string(mustReadFile(t, "devin-test-target-files.lock")), want+"\n") {
		t.Fatal("runtime file lock differs from the compiled qualification inputs")
	}
}

func TestLinuxDevinInstallerChecksBundleAndDefersArm64(t *testing.T) {
	for _, mode := range []string{"ok", "arm64", "missing", "duplicate", "wrong-size", "wrong-digest", "duplicate-member", "symlink-member", "traversal", "extra-runtime"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			stub := filepath.Join(root, "stub")
			out := filepath.Join(root, "bin", "devin")
			for _, dir := range []string{stub, filepath.Dir(out)} {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			arch := "x86_64"
			if mode == "arm64" {
				arch = "aarch64"
			}
			write := func(path, body string, perm os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, []byte(body), perm); err != nil {
					t.Fatal(err)
				}
			}
			write(filepath.Join(stub, "uname"), "#!/bin/sh\n[ \"$1\" = -s ] && echo Linux || echo "+arch+"\n", 0700)
			write(filepath.Join(stub, "curl"), "#!/bin/sh\nwhile [ $# -gt 0 ]; do case \"$1\" in --output) out=$2; shift 2;; *) shift;; esac; done\ncp \"$TEST_ARCHIVE\" \"$out\"\n", 0700)
			// A successful Linux install must never execute the supplied bytes.
			binary := []byte("#!/bin/sh\nexit 99\n")
			archive := filepath.Join(root, "fixture.tar.gz")
			file, err := os.Create(archive)
			if err != nil {
				t.Fatal(err)
			}
			gz := gzip.NewWriter(file)
			tw := tar.NewWriter(gz)
			members := []string{"bin/devin"}
			if mode == "duplicate-member" {
				members = append(members, "bin/devin")
			}
			if mode == "traversal" {
				members = append(members, "../escape")
			}
			for _, name := range members {
				header := &tar.Header{Name: name, Mode: 0755, Size: int64(len(binary)), Typeflag: tar.TypeReg}
				if mode == "symlink-member" {
					header.Typeflag, header.Linkname, header.Size = tar.TypeSymlink, "/bin/sh", 0
				}
				if err := tw.WriteHeader(header); err != nil {
					t.Fatal(err)
				}
				if header.Size > 0 {
					if _, err := tw.Write(binary); err != nil {
						t.Fatal(err)
					}
				}
			}
			for _, close := range []func() error{tw.Close, gz.Close, file.Close} {
				if err := close(); err != nil {
					t.Fatal(err)
				}
			}
			row := fmt.Sprintf("3000.10.21|linux|amd64|%x|https://example.invalid/devin.tar.gz\n", sha256.Sum256(mustReadFile(t, archive)))
			if mode == "missing" {
				row = "# no Linux row\n"
			} else if mode == "duplicate" {
				row += row
			}
			lock := filepath.Join(root, "targets.lock")
			write(lock, row, 0600)
			size, digest := len(binary), fmt.Sprintf("%x", sha256.Sum256(binary))
			if mode == "wrong-size" {
				size++
			}
			if mode == "wrong-digest" {
				digest = strings.Repeat("0", 64)
			}
			fileRow := fmt.Sprintf("3000.10.21|linux|amd64|bin/devin|%d|%s\n", size, digest)
			if mode == "extra-runtime" {
				fileRow += "3000.10.21|linux|amd64|bin/helper|1|" + digest + "\n"
			}
			write(filepath.Join(root, "devin-test-target-files.lock"), fileRow, 0600)
			cmd := exec.Command("sh", "install-devin-test-target.sh", lock, root, out)
			cmd.Env = append(os.Environ(), "PATH="+stub+":"+os.Getenv("PATH"), "TEST_ARCHIVE="+archive)
			output, err := cmd.CombinedOutput()
			if mode == "ok" {
				if err != nil {
					t.Fatalf("install: %v %s", err, output)
				}
				info, err := os.Lstat(out)
				if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0500 || string(mustReadFile(t, out)) != string(binary) {
					t.Fatal("installed target bytes/mode differ")
				}
			} else {
				if err == nil {
					t.Fatal("unsafe or unsupported target installed")
				}
				if _, err := os.Lstat(out); !os.IsNotExist(err) {
					t.Fatal("failure left an executable")
				}
				if _, err := os.Lstat(filepath.Join(root, "devin-3000.10.21-linux-amd64.tar.gz")); !os.IsNotExist(err) {
					t.Fatal("failure left a downloaded archive")
				}
			}
		})
	}
}

func TestInstallerRetainsVerifiedArchiveAndCleansFailures(t *testing.T) {
	root := t.TempDir()
	stub := filepath.Join(root, "stub")
	if err := os.Mkdir(stub, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) string {
		path := filepath.Join(stub, name)
		if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write("uname", "#!/bin/sh\n[ \"$1\" = -s ] && echo Darwin || echo arm64\n")
	write("curl", "#!/bin/sh\nwhile [ $# -gt 0 ]; do case \"$1\" in -o|--output) out=$2; shift 2;; *) shift;; esac; done\nif [ \"$INSTALL_MODE\" = fail-download ]; then printf partial > \"$out\"; exit 1; fi\ncp \"$TEST_ARCHIVE\" \"$out\"\nif [ \"$INSTALL_MODE\" = corrupt-download ]; then printf corrupted >> \"$out\"; fi\n")
	archiveSource := filepath.Join(root, "source.tar.gz")
	archiveTree := filepath.Join(root, "archive-tree", "bin")
	if err := os.MkdirAll(archiveTree, 0700); err != nil {
		t.Fatal(err)
	}
	devinScript := []byte("#!/bin/sh\n[ \"$INSTALL_MODE\" = bad-version ] && echo wrong || echo devin 3000.10.21\n")
	if err := os.WriteFile(filepath.Join(archiveTree, "devin"), devinScript, 0700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("tar", "-czf", archiveSource, "-C", filepath.Dir(archiveTree), "bin").CombinedOutput(); err != nil {
		t.Fatalf("create archive: %v %s", err, output)
	}
	digestOutput, err := exec.Command("shasum", "-a", "256", archiveSource).Output()
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Fields(string(digestOutput))[0]
	lock := filepath.Join(root, "lock")
	if err := os.WriteFile(lock, []byte("3000.10.21|darwin|arm64|"+digest+"|https://example.invalid/devin.tar.gz\n"), 0600); err != nil {
		t.Fatal(err)
	}
	fixture := archiveSource
	run := func(mode string, output string) (string, error) {
		cmd := exec.Command("sh", "install-devin-test-target.sh", lock, root, output)
		cmd.Dir = "."
		cmd.Env = append(os.Environ(), "PATH="+stub+":"+os.Getenv("PATH"), "TEST_ARCHIVE="+fixture, "INSTALL_MODE="+mode)
		outputBytes, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("installer %s output: %s", mode, outputBytes)
		}
		return string(outputBytes), err
	}
	successOutput := filepath.Join(root, "success", "bin", "devin")
	if err := os.MkdirAll(filepath.Dir(successOutput), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := run("ok", successOutput); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "devin-3000.10.21-darwin-arm64.tar.gz")
	if data, err := os.ReadFile(archive); err != nil || string(data) != string(mustReadFile(t, archiveSource)) {
		t.Fatalf("retained archive=(%q,%v)", data, err)
	}
	for _, mode := range []string{"bad-version", "extract-failure", "fail-download", "corrupt-download"} {
		_ = os.Remove(archive)
		out := filepath.Join(root, mode, "bin", "devin")
		if err := os.MkdirAll(filepath.Dir(out), 0700); err != nil {
			t.Fatal(err)
		}
		if mode == "extract-failure" {
			if err := os.WriteFile(filepath.Join(stub, "tar"), []byte("#!/bin/sh\ncase \"$1\" in -xzf) exit 1;; esac\nexec /usr/bin/tar \"$@\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
		}
		wantError := map[string]string{
			"bad-version":      "installed target reported an unexpected version",
			"extract-failure":  "target extraction failed",
			"fail-download":    "locked archive download failed",
			"corrupt-download": "archive digest did not match the lock",
		}[mode]
		if output, err := run(mode, out); err == nil || !strings.Contains(output, wantError) {
			t.Fatalf("%s failure=%v output=%q want=%q", mode, err, output, wantError)
		}
		temporary, err := filepath.Glob(filepath.Join(root, ".devin-target.*"))
		if err != nil || len(temporary) != 0 {
			t.Fatalf("%s retained extraction state: %v %v", mode, temporary, err)
		}
		if _, err := os.Stat(archive); !os.IsNotExist(err) {
			t.Fatalf("%s retained archive: %v", mode, err)
		}
	}
	if err := os.WriteFile(archive, []byte("caller-owned"), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := run("ok", filepath.Join(root, "refused", "devin")); err == nil || !strings.Contains(output, "archive destination already exists") {
		t.Fatalf("existing archive refusal=%v output=%q", err, output)
	}
	if data, err := os.ReadFile(archive); err != nil || string(data) != "caller-owned" {
		t.Fatalf("caller archive changed=(%q,%v)", data, err)
	}
	outputPath := filepath.Join(root, "existing", "bin", "devin")
	if err := os.MkdirAll(filepath.Dir(outputPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, []byte("caller-binary"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(archive)
	if output, err := run("ok", outputPath); err == nil || !strings.Contains(output, "output path already exists") {
		t.Fatalf("existing output refusal=%v output=%q", err, output)
	}
	if data, err := os.ReadFile(outputPath); err != nil || string(data) != "caller-binary" {
		t.Fatalf("caller output changed=(%q,%v)", data, err)
	}
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
