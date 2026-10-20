package scripts

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGrokTargetLockPinsReviewedArtifacts(t *testing.T) {
	contents, err := os.ReadFile("grok-test-targets.lock")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"1.0.62|darwin|arm64|fb10cd5a381dbbb15111b020fa731642499ce20dd4d70ad9a51daa734aa80372|https://x.ai/cli/grok-1.0.62-macos-aarch64.zst",
		"1.0.62|linux|amd64|8a8697be26d2c77ea87c5dd754902228a9e766580f85f156080d96f88e9dca2a|https://x.ai/cli/grok-1.0.62-linux-x86_64.zst",
		"1.0.62|linux|arm64|a9b1cd945b1cf8da2e8962c4d7fcd27b9a8fe9d71215751dcaa67e1ecb8b3492|https://x.ai/cli/grok-1.0.62-linux-aarch64.zst",
	} {
		if !strings.Contains(string(contents), want) {
			t.Errorf("target lock omits %q", want)
		}
	}
}

func TestGrokTargetInstallerAcceptsLockedRegularFile(t *testing.T) {
	if _, err := exec.LookPath("zstd"); err != nil {
		t.Skip("zstd is unavailable")
	}
	arch := "amd64"
	hostKey := "linux|amd64"
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "linux/amd64":
	case "linux/arm64":
		arch, hostKey = "arm64", "linux|arm64"
	case "darwin/arm64":
		arch, hostKey = "arm64", "darwin|arm64"
	default:
		t.Skip("host is not a reviewed Grok target")
	}
	directory := t.TempDir()
	source := filepath.Join(directory, "grok-src")
	if err := os.WriteFile(source, []byte("#!/bin/sh\nprintf 'grok 1.0.62\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(directory, "grok.zst")
	if output, err := exec.Command("zstd", "-q", "-f", "-o", archive, source).CombinedOutput(); err != nil {
		t.Fatalf("compress fixture: %v %s", err, output)
	}
	sum, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(sum)
	lock := filepath.Join(directory, "lock")
	line := "1.0.62|" + hostKey + "|" + hex.EncodeToString(digest[:]) + "|https://example.invalid/grok.zst\n"
	if err := os.WriteFile(lock, []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(directory, "grok")
	command := exec.Command("sh", "install-grok-test-target.sh", lock, archive, arch, outputPath)
	if result, err := command.CombinedOutput(); err != nil {
		t.Fatalf("install target: %v; output=%q", err, result)
	}
	if result, err := exec.Command(outputPath, "--version").CombinedOutput(); err != nil || string(result) != "grok 1.0.62\n" {
		t.Fatalf("installed target = (%q, %v)", result, err)
	}
}
