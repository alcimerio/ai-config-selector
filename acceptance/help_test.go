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

func TestPromotedHelpWithoutHomeOrTargets(t *testing.T) {
	binary := promotedBinary(t)
	for _, command := range []string{"", "profile", "profile list", "profile show", "profile create", "profile export", "profile import", "profile import validate", "devin", "devin create-profile", "sandbox", "codex", "codex create-profile", "codex auth", "codex auth login", "codex auth list", "codex auth status", "codex auth recover", "codex auth logout", "version"} {
		for _, args := range [][]string{strings.Fields("help " + command), strings.Fields(command + " --help")} {
			t.Run(strings.Join(args, " "), func(t *testing.T) {
				cmd := exec.Command(binary, args...)
				// An absent HOME and unusable PATH make accidental runtime setup fail.
				cmd.Env = []string{"PATH=/nonexistent", "LANG=C", "TERM=dumb"}
				var out, errOut bytes.Buffer
				cmd.Stdout = &out
				cmd.Stderr = &errOut
				if err := cmd.Run(); err != nil || errOut.Len() != 0 || !strings.Contains(out.String(), "Usage:") {
					t.Fatalf("help failed or omitted usage; error=%v stderr bytes=%d", err, errOut.Len())
				}
			})
		}
	}
}

func TestPromotedCodexDryRunReadsOnlyTheProfileAndLeavesAuthenticationUnchecked(t *testing.T) {
	binary := promotedBinary(t)
	home := realTemporaryDirectory(t)
	profiles := filepath.Join(home, ".acs", "profiles")
	if err := os.MkdirAll(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	document := `{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"codex":{"version":1,"authRef":"stored"}}}`
	if err := os.WriteFile(filepath.Join(profiles, "example.json"), []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	before := snapshotHome(t, home)
	command := exec.Command(binary, "codex", "--profile", "example", "--auth", "override", "--dry-run")
	command.Env = promotedEnvironment(home, "/nonexistent")
	var out, errOut bytes.Buffer
	command.Stdout, command.Stderr = &out, &errOut
	if err := command.Run(); err != nil || errOut.Len() != 0 {
		t.Fatalf("dry-run failed: %v stderr=%q", err, errOut.String())
	}
	for _, want := range []string{"override", "existence/status: unchecked", "No identity lock, executable probe, Session, or process was created."} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("dry-run missing %q: %s", want, out.String())
		}
	}
	after := snapshotHome(t, home)
	if strings.Join(before, "\n") != strings.Join(after, "\n") {
		t.Fatalf("dry-run changed HOME: before=%v after=%v", before, after)
	}
}

func TestPromotedDeclarativeProfileCreationNeedsNoTTYTargetOrCredentials(t *testing.T) {
	binary := promotedBinary(t)
	home := realTemporaryDirectory(t)
	inputDirectory := realTemporaryDirectory(t)
	input := filepath.Join(inputDirectory, "candidate.json")
	document := `{"version":3,"name":"declarative","common":{"skills":{"version":1,"selection":[{"source":"shared-agents","relativePath":"missing-but-valid"}]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"codex":{"version":1,"authRef":"absent-identity"},"devin":{"version":1}}}`
	if err := os.WriteFile(input, []byte(document), 0o640); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(inputDirectory, "candidate-link.json")
	if err := os.Symlink(input, alias); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(input)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "profile", "create", "--file", alias, "--dry-run")
	command.Env = promotedEnvironment(home, "/nonexistent")
	var out, errOut bytes.Buffer
	command.Stdout, command.Stderr = &out, &errOut
	if err := command.Run(); err != nil || errOut.Len() != 0 {
		t.Fatalf("dry-run failed without targets: %v stderr=%q", err, errOut.String())
	}
	for _, want := range []string{`Dry run for Profile "declarative"`, `"authRef": "absent-identity"`, "readiness was not checked", "No Profile storage"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("dry-run missing %q: %s", want, out.String())
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".acs")); !os.IsNotExist(err) {
		t.Fatalf("dry-run created ACS storage: %v", err)
	}
	command = exec.Command(binary, "profile", "create", "--file", alias)
	command.Env = promotedEnvironment(home, "/nonexistent")
	out.Reset()
	errOut.Reset()
	command.Stdout, command.Stderr = &out, &errOut
	if err := command.Run(); err != nil || errOut.Len() != 0 || out.String() != "Created Profile \"declarative\".\n" {
		t.Fatalf("create failed without targets: %v stdout=%q stderr=%q", err, out.String(), errOut.String())
	}
	stored, err := os.ReadFile(filepath.Join(home, ".acs", "profiles", "declarative.json"))
	if err != nil || !bytes.Contains(stored, []byte(`"source": "shared-agents"`)) || !bytes.Contains(stored, []byte(`"codex"`)) || !bytes.Contains(stored, []byte(`"devin"`)) {
		t.Fatalf("stored Profile is incomplete: %v %s", err, stored)
	}
	after, err := os.Stat(input)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := os.ReadFile(input)
	if err != nil || string(unchanged) != document || before.Mode() != after.Mode() {
		t.Fatal("declarative creation changed its source input")
	}
	command = exec.Command(binary, "profile", "create", "--file", input)
	command.Env = promotedEnvironment(home, "/nonexistent")
	if output, err := command.CombinedOutput(); err == nil || !strings.Contains(string(output), "occupied") {
		t.Fatalf("collision did not fail closed: %v %s", err, output)
	}
}

func snapshotHome(t *testing.T, home string) []string {
	t.Helper()
	var snapshot []string
	if err := filepath.WalkDir(home, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(home, path)
		snapshot = append(snapshot, relative+" "+info.Mode().String())
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestPromotedHelpLeavesHomeAndRecoveryStateUntouched(t *testing.T) {
	binary := promotedBinary(t)
	home := realTemporaryDirectory(t)
	marker := filepath.Join(home, ".acs", "sessions", "help-sentinel", "sentinel")
	if err := os.MkdirAll(filepath.Dir(marker), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range []string{"devin --profile example --help", "sandbox --help --profile example", "devin create-profile --name example --help", "codex auth login --name example --help", "codex auth recover --name example --help"} {
		cmd := exec.Command(binary, strings.Fields(args)...)
		cmd.Env = promotedEnvironment(home, "/nonexistent")
		var out, errOut bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &errOut
		if err := cmd.Run(); err != nil || errOut.Len() != 0 {
			t.Fatalf("help failed: %v", err)
		}
	}
	var files []string
	err := filepath.WalkDir(home, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	if err != nil || len(files) != 1 || files[0] != marker {
		t.Fatal("help changed home state")
	}
	if data, err := os.ReadFile(marker); err != nil || string(data) != "untouched" {
		t.Fatal("help modified recovery sentinel")
	}
}
