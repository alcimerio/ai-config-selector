package scripts

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestPromotedArtifactValidationRejectsANonNativeTargetBeforeCandidateInspection(t *testing.T) {
	targetOS := runtime.GOOS
	targetArch := "arm64"
	if runtime.GOARCH == "arm64" {
		targetArch = "amd64"
	}

	command := exec.Command("sh", "validate-promoted-artifact.sh", "v0.2.0", targetOS, targetArch, t.TempDir(), filepath.Join(t.TempDir(), "bin"))
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("promoted artifact validation accepted a non-native target")
	}
	want := "target=" + targetOS + "/" + targetArch + " candidate=v0.2.0 stage=host-identity"
	if !strings.Contains(string(output), want) {
		t.Fatalf("diagnostic = %q, want %q", output, want)
	}
	if strings.Contains(string(output), "stage=candidate-identity") {
		t.Fatalf("non-native target reached candidate inspection: %q", output)
	}
}

func TestPromotedArtifactValidationInstallsTheExactCandidateOnTheNativeHost(t *testing.T) {
	candidateDirectory := realTemporaryDirectory(t)
	writePromotedCandidate(t, candidateDirectory)
	installDirectory := filepath.Join(realTemporaryDirectory(t), "custom-bin")

	command := exec.Command(
		"sh", "validate-promoted-artifact.sh", "v0.2.0", runtime.GOOS, runtime.GOARCH,
		candidateDirectory, installDirectory,
	)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("promoted artifact validation failed: %v\n%s", err, output)
	}
	for _, marker := range []string{
		"stage=candidate-identity status=passed",
		"stage=custom-install status=passed",
		"stage=default-install status=passed",
		"stage=complete status=passed",
	} {
		if !strings.Contains(string(output), marker) {
			t.Errorf("validation output omits %q: %s", marker, output)
		}
	}
	installed := filepath.Join(installDirectory, "acs")
	versionOutput, err := exec.Command(installed, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("installed candidate failed: %v\n%s", err, versionOutput)
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
	for _, target := range []string{"darwin_arm64", "darwin_amd64", "linux_amd64", "linux_arm64"} {
		name := "acs_0.2.0_" + target + ".tar.gz"
		path := filepath.Join(candidateDirectory, name)
		writeInstallerArchive(t, path, "#!/bin/sh\nif [ \"${1:-}\" = version ]; then printf 'acs v0.2.0\\n'; exit 0; fi\nexit 2\n")
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
