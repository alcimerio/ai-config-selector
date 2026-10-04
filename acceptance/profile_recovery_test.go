//go:build darwin || linux

package acceptance_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPromotedProfileRecoveryNeedsNoLaunchDependencies(t *testing.T) {
	binary := promotedBinary(t)
	home := realTemporaryDirectory(t)
	before := snapshotInspectionHome(t, home)
	for _, args := range [][]string{{"profile", "recover", "--help"}, {"help", "profile", "recover"}, {"profile", "recover"}, {"profile", "recover", "--json"}} {
		output := runProfileRecoveryCandidate(t, binary, home, args...)
		if strings.Contains(strings.Join(args, " "), "help") && !strings.Contains(output, "acs profile recover") {
			t.Fatalf("missing help: %s", output)
		}
		if !reflect.DeepEqual(before, snapshotInspectionHome(t, home)) {
			t.Fatal("missing-storage recovery bootstrapped HOME")
		}
	}
	root := filepath.Join(home, ".acs")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	// These uncertain authentication/Session fixtures must never be assembled or
	// changed by Profile recovery, even with target executables absent from PATH.
	for _, name := range []string{"sessions", "codex-auth"} {
		if err := os.Symlink("/nonexistent/private-resource", filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	before = snapshotInspectionHome(t, home)
	output := runProfileRecoveryCandidate(t, binary, home, "profile", "recover", "--json")
	var result struct {
		State            string `json:"state"`
		RecoveryRequired bool   `json:"recoveryRequired"`
	}
	if err := json.Unmarshal([]byte(output), &result); err != nil || result.State != "not_committed" || result.RecoveryRequired {
		t.Fatalf("dependencies blocked recovery: %s %v", output, err)
	}
	if !reflect.DeepEqual(before, snapshotInspectionHome(t, home)) {
		t.Fatal("Profile recovery altered unrelated uncertain resources")
	}
}

func runProfileRecoveryCandidate(t *testing.T, binary, home string, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, args...)
	command.Env = promotedEnvironment(home, "/nonexistent")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("early recovery %v: %v %s", args, err, output)
	}
	return string(output)
}
