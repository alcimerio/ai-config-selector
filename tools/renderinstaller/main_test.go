package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRendererPinsExactlyOneCanonicalReleaseVersion(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "install.sh")
	command := exec.Command("go", "run", ".",
		"--template", filepath.Join("..", "..", "scripts", "install.sh.tmpl"),
		"--output", outputPath,
		"--version", "v0.2.0",
	)
	command.Dir = "."
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("renderer failed: %v\n%s", err, output)
	}
	contents, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(contents), `readonly release_version="v0.2.0"`) != 1 {
		t.Fatalf("rendered installer does not contain exactly one pinned version: %q", contents)
	}
	if strings.Contains(string(contents), "__ACS_RELEASE_VERSION__") {
		t.Fatal("rendered installer retains the version placeholder")
	}
	info, err := os.Stat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("installer mode = %o, want 755", info.Mode().Perm())
	}
}

func TestRendererAcceptsCanonicalZeroVersion(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "install.sh")
	command := exec.Command("go", "run", ".",
		"--template", filepath.Join("..", "..", "scripts", "install.sh.tmpl"),
		"--output", outputPath,
		"--version", "v0.0.0",
	)
	command.Dir = "."
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("canonical zero version was rejected: %v\n%s", err, output)
	}
}

func TestRendererRejectsMutableOrUnqualifiedVersions(t *testing.T) {
	for _, version := range []string{"", "latest", "0.2.0", "v01.2.3", "v1.2.3-rc.1", "v1.2.3+dirty"} {
		t.Run(version, func(t *testing.T) {
			outputPath := filepath.Join(t.TempDir(), "install.sh")
			command := exec.Command("go", "run", ".",
				"--template", filepath.Join("..", "..", "scripts", "install.sh.tmpl"),
				"--output", outputPath,
				"--version", version,
			)
			command.Dir = "."
			if output, err := command.CombinedOutput(); err == nil {
				t.Fatalf("invalid version accepted:\n%s", output)
			}
			if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
				t.Fatalf("invalid render left output: %v", err)
			}
		})
	}
}

func TestRendererEscapesControlCharactersInPathErrors(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "missing\x1b[31m", "install.sh")
	command := exec.Command("go", "run", ".",
		"--template", filepath.Join("..", "..", "scripts", "install.sh.tmpl"),
		"--output", outputPath,
		"--version", "v0.2.0",
	)
	command.Dir = "."
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("invalid output path was accepted")
	}
	if strings.ContainsRune(string(output), '\x1b') {
		t.Fatalf("diagnostic contains a raw terminal control character: %q", output)
	}
}

func TestRendererEscapesControlCharactersInFlagErrors(t *testing.T) {
	command := exec.Command("go", "run", ".", "--bad\x1b[31m")
	command.Dir = "."
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("unknown flag was accepted")
	}
	if strings.ContainsRune(string(output), '\x1b') {
		t.Fatalf("flag diagnostic contains a raw terminal control character: %q", output)
	}
}
