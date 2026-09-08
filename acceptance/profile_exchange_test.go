//go:build darwin || linux

package acceptance_test

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPromotedProfileExchangeRoundTripNeedsNoTargetsOrCredentials(t *testing.T) {
	binary := promotedBinary(t)
	home := realTemporaryDirectory(t)
	profiles := filepath.Join(home, ".acs", "profiles")
	if err := os.MkdirAll(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	local := `{"version":3,"name":"source","common":{"skills":{"version":1,"selection":[{"source":"shared-agents","relativePath":"review"}]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"codex":{"version":1,"authRef":"private-local-name"},"devin":{"version":1}}}`
	if err := os.WriteFile(filepath.Join(profiles, "source.json"), []byte(local), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "profile", "export", "source")
	command.Env = promotedEnvironment(home, "/nonexistent")
	var exported, report bytes.Buffer
	command.Stdout, command.Stderr = &exported, &report
	if err := command.Run(); err != nil {
		t.Fatalf("export: %v stderr=%q", err, report.String())
	}
	for _, forbidden := range []string{"shared-agents", "private-local-name", home} {
		if strings.Contains(exported.String(), forbidden) || strings.Contains(report.String(), forbidden) {
			t.Fatalf("exchange disclosed %q: stdout=%q stderr=%q", forbidden, exported.String(), report.String())
		}
	}
	if !strings.Contains(report.String(), "source availability, authentication, path identity, and runtime unchecked") {
		t.Fatalf("report=%q", report.String())
	}
	directory := realTemporaryDirectory(t)
	exchangePath := filepath.Join(directory, "exchange.json")
	bindingPath := filepath.Join(directory, "bindings.json")
	if err := os.WriteFile(exchangePath, exported.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	bindings := `{"bindingVersion":1,"sources":{"source-1":"shared-agents"},"authentications":{"authentication-1":"bound-auth"}}`
	if err := os.WriteFile(bindingPath, []byte(bindings), 0o600); err != nil {
		t.Fatal(err)
	}

	command = exec.Command(binary, "profile", "import", "validate", "--file", exchangePath, "--json")
	command.Env = promotedEnvironment(home, "/nonexistent")
	output, err := command.CombinedOutput()
	if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 2 || !bytes.Contains(output, []byte(`"status":"unresolved"`)) {
		t.Fatalf("unresolved validation: %v %s", err, output)
	}

	command = exec.Command(binary, "profile", "import", "--file", exchangePath, "--as", "imported", "--bindings", bindingPath)
	command.Env = promotedEnvironment(home, "/nonexistent")
	output, err = command.CombinedOutput()
	if err != nil || !bytes.Contains(output, []byte(`Imported Profile "imported"`)) {
		t.Fatalf("import: %v %s", err, output)
	}
	stored, err := os.ReadFile(filepath.Join(profiles, "imported.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"name": "imported"`, `"source": "shared-agents"`, `"authRef": "bound-auth"`, `"devin"`} {
		if !bytes.Contains(stored, []byte(expected)) {
			t.Fatalf("imported Profile lacks %q: %s", expected, stored)
		}
	}
}
