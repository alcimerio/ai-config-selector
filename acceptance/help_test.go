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
	for _, command := range []string{"", "devin", "devin create-profile", "sandbox", "codex", "codex auth", "codex auth login", "codex auth list", "codex auth status", "codex auth recover", "codex auth logout", "version"} {
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
