package scripts

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func TestPromotedArtifactValidationRejectsIntelBeforeCandidateInspection(t *testing.T) {
	command := exec.Command("sh", "validate-promoted-artifact.sh", "v0.2.0", "darwin", "amd64", t.TempDir(), filepath.Join(t.TempDir(), "bin"))
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("promoted artifact validation accepted an Intel target")
	}
	want := "target=unvalidated candidate=unvalidated stage=arguments: unsupported validation target"
	if !strings.Contains(string(output), want) {
		t.Fatalf("diagnostic = %q, want %q", output, want)
	}
	if strings.Contains(string(output), "stage=candidate-identity") {
		t.Fatalf("non-native target reached candidate inspection: %q", output)
	}
}

func TestPromotedArtifactValidationEscapesUntrustedArguments(t *testing.T) {
	command := exec.Command(
		"sh", "validate-promoted-artifact.sh", "v0.2.0\x1b[31m", runtime.GOOS, runtime.GOARCH,
		t.TempDir(), filepath.Join(t.TempDir(), "bin"),
	)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("promoted artifact validation accepted a version with terminal controls")
	}
	trimmed := strings.TrimSuffix(string(output), "\n")
	if strings.ContainsAny(trimmed, "\r\n\x1b") {
		t.Fatalf("diagnostic contains raw terminal controls: %q", output)
	}
	want := "target=unvalidated candidate=unvalidated stage=arguments"
	if !strings.Contains(trimmed, want) {
		t.Fatalf("diagnostic = %q, want %q", output, want)
	}
}

func TestPromotedArtifactValidationInstallsTheExactCandidateOnTheNativeHost(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("promoted artifact validation requires a native Apple Silicon host")
	}
	candidateDirectory := realTemporaryDirectory(t)
	writePromotedCandidate(t, candidateDirectory)
	installDirectory := filepath.Join(realTemporaryDirectory(t), "custom-bin")

	command := exec.Command(
		"sh", "validate-promoted-artifact.sh", "v0.2.0", runtime.GOOS, runtime.GOARCH,
		candidateDirectory, installDirectory,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("promoted artifact validation failed: %v; output=%q", err, output)
	}
	for _, marker := range []string{
		"stage=candidate-identity status=passed",
		"stage=custom-install status=passed",
		"stage=default-install status=passed",
		"stage=complete status=passed",
	} {
		if !strings.Contains(string(output), marker) {
			t.Errorf("validation output omits %q: %q", marker, output)
		}
	}
	installed := filepath.Join(installDirectory, "acs")
	versionOutput, err := exec.Command(installed, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("installed candidate failed: %v; output=%q", err, versionOutput)
	}
	if string(versionOutput) != "acs v0.2.0\n" {
		t.Fatalf("installed candidate version = %q", versionOutput)
	}
}

func writePromotedCandidate(t *testing.T, candidateDirectory string) {
	t.Helper()
	if err := os.MkdirAll(candidateDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	var manifest strings.Builder
	linuxBinary := string(linuxAmd64ACSBinary(t))
	for _, target := range []string{"darwin_arm64", "linux_amd64"} {
		name := "acs_0.2.0_" + target + ".tar.gz"
		path := filepath.Join(candidateDirectory, name)
		body := "#!/bin/sh\nif [ \"${1:-}\" = version ]; then printf 'acs v0.2.0\\n'; exit 0; fi\nexit 2\n"
		if target == "linux_amd64" {
			body = linuxBinary
		}
		writeInstallerArchive(t, path, body)
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&manifest, "%x  %s\n", sha256.Sum256(contents), name)
	}
	if err := os.WriteFile(filepath.Join(candidateDirectory, "SHA256SUMS"), []byte(manifest.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	template, err := os.ReadFile("install.sh.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	installer := strings.ReplaceAll(string(template), "__ACS_RELEASE_VERSION__", "v0.2.0")
	if err := os.WriteFile(filepath.Join(candidateDirectory, "install.sh"), []byte(installer), 0o700); err != nil {
		t.Fatal(err)
	}
}

var (
	linuxACSOnce   sync.Once
	linuxACSBinary []byte
	linuxACSErr    error
)

func linuxAmd64ACSBinary(t *testing.T) []byte {
	t.Helper()
	linuxACSOnce.Do(func() {
		directory, err := os.MkdirTemp("", "acs-linux-fixture")
		if err != nil {
			linuxACSErr = err
			return
		}
		binaryPath := filepath.Join(directory, "acs")
		command := exec.Command("go", "build", "-buildvcs=false", "-ldflags", "-X main.releaseVersion=v0.2.0", "-o", binaryPath, "./cmd/acs")
		command.Dir = ".."
		command.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
		if output, err := command.CombinedOutput(); err != nil {
			linuxACSErr = fmt.Errorf("build linux/amd64 acs: %w\n%s", err, output)
			return
		}
		linuxACSBinary, linuxACSErr = os.ReadFile(binaryPath)
	})
	if linuxACSErr != nil {
		t.Fatal(linuxACSErr)
	}
	return linuxACSBinary
}
