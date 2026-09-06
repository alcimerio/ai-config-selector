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
	for _, command := range []string{"", "profile", "profile list", "profile show", "devin", "devin create-profile", "sandbox", "codex", "codex create-profile", "codex auth", "codex auth login", "codex auth list", "codex auth status", "codex auth recover", "codex auth logout", "version"} {
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
