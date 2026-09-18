package scripts

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	run := func(mode string, output string) (error, string) {
		cmd := exec.Command("sh", "install-devin-test-target.sh", lock, root, output)
		cmd.Dir = "."
		cmd.Env = append(os.Environ(), "PATH="+stub+":"+os.Getenv("PATH"), "TEST_ARCHIVE="+fixture, "INSTALL_MODE="+mode)
		outputBytes, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("installer %s output: %s", mode, outputBytes)
		}
		return err, string(outputBytes)
	}
	successOutput := filepath.Join(root, "success", "bin", "devin")
	if err := os.MkdirAll(filepath.Dir(successOutput), 0700); err != nil {
		t.Fatal(err)
	}
	if err, _ := run("ok", successOutput); err != nil {
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
		if err, output := run(mode, out); err == nil || !strings.Contains(output, wantError) {
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
	if err, output := run("ok", filepath.Join(root, "refused", "devin")); err == nil || !strings.Contains(output, "archive destination already exists") {
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
	if err, output := run("ok", outputPath); err == nil || !strings.Contains(output, "output path already exists") {
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
