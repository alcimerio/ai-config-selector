package scripts

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCodexTargetInstallerAcceptsOnlyTheLockedNativeRegularFile(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("native target installation is macOS-only")
	}
	arch, member := nativeCodexTestTarget(t)
	bundle := t.TempDir()
	archive := filepath.Join(bundle, "codex_0.149.1_darwin_"+arch+".tar.gz")
	writeCodexTargetArchive(t, archive, member, "#!/bin/sh\nprintf 'codex-cli 0.149.1\\n'\n", tar.TypeReg)
	lock := writeCodexTargetLock(t, arch, archive)
	outputDirectory := t.TempDir()
	output := filepath.Join(outputDirectory, "codex")

	command := exec.Command("sh", "install-codex-test-target.sh", lock, bundle, arch, output)
	if result, err := command.CombinedOutput(); err != nil {
		t.Fatalf("install target: %v; output=%q", err, result)
	}
	if result, err := exec.Command(output, "--version").CombinedOutput(); err != nil || string(result) != "codex-cli 0.149.1\n" {
		t.Fatalf("installed target = (%q, %v)", result, err)
	}
}

func TestCodexTargetInstallerRejectsUnsafeArchiveContents(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("native target installation is macOS-only")
	}
	arch, _ := nativeCodexTestTarget(t)
	bundle := t.TempDir()
	archive := filepath.Join(bundle, "codex_0.149.1_darwin_"+arch+".tar.gz")
	writeCodexTargetArchive(t, archive, "../escape", "unsafe\n", tar.TypeReg)
	lock := writeCodexTargetLock(t, arch, archive)
	output := filepath.Join(t.TempDir(), "codex")

	result, err := exec.Command("sh", "install-codex-test-target.sh", lock, bundle, arch, output).CombinedOutput()
	if err == nil || !strings.Contains(string(result), "unexpected path") {
		t.Fatalf("unsafe archive result = (%q, %v)", result, err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("unsafe archive created output: %v", err)
	}
}

func TestCodexTargetLockPinsBothOfficialAppleArchives(t *testing.T) {
	contents, err := os.ReadFile("codex-test-targets.lock")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"0.149.1|darwin|arm64|ed60f475c6dda6044c2c00fd7f33273cc3f3f98900ccd1204bfdf2fe935f3405|https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-aarch64-apple-darwin.tar.gz",
		"0.149.1|darwin|amd64|85fe7a837eb739dd5e1cc59a9c95b7b682048e5aacdc261505bae768fb1288ef|https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-x86_64-apple-darwin.tar.gz",
	} {
		if !strings.Contains(string(contents), want) {
			t.Errorf("target lock omits %q", want)
		}
	}
}

func nativeCodexTestTarget(t *testing.T) (string, string) {
	t.Helper()
	switch runtime.GOARCH {
	case "arm64":
		return "arm64", "codex-aarch64-apple-darwin"
	case "amd64":
		return "amd64", "codex-x86_64-apple-darwin"
	default:
		t.Fatalf("unsupported test architecture %q", runtime.GOARCH)
		return "", ""
	}
}

func writeCodexTargetLock(t *testing.T, arch, archive string) string {
	t.Helper()
	contents, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(contents))
	url := "https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-aarch64-apple-darwin.tar.gz"
	if arch == "amd64" {
		url = "https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-x86_64-apple-darwin.tar.gz"
	}
	path := filepath.Join(t.TempDir(), "targets.lock")
	if err := os.WriteFile(path, []byte("0.149.1|darwin|"+arch+"|"+digest+"|"+url+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCodexTargetArchive(t *testing.T, path, name, contents string, kind byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o700, Size: int64(len(contents)), Typeflag: kind}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write([]byte(contents)); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
