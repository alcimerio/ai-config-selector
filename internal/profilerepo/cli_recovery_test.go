package profilerepo

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Reuse the repository's actual interruption fixtures and stationary lock with
// the public executable, rather than duplicating its journal codec in CLI tests.
func TestProfileRecoveryExecutableFixtures(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "acs")
	build := exec.Command("go", "build", "-o", binary, "../../cmd/acs")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build executable: %v %s", err, output)
	}
	for _, scenario := range []struct {
		name, point string
		state       State
		required    bool
		code        int
	}{
		{"prepared", "stage.write.after", NotCommitted, false, 0},
		{"decided", "decision.publish.after", Committed, false, 0},
		{"terminal cleanup", "complete.publish.after", Committed, false, 0},
		{"unsafe journal", "", Unknown, true, 1},
		{"busy stationary lock", "", NotCommitted, false, 1},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			original := seeded(t)
			home := t.TempDir()
			root := filepath.Join(home, ".acs")
			if err := os.Rename(original.acsHome, root); err != nil {
				t.Fatal(err)
			}
			r := New(root)
			if scenario.point != "" {
				runKilled(t, r, "apply", "create", scenario.point)
			}
			if scenario.name == "unsafe journal" {
				runKilled(t, r, "apply", "create", "decision.publish.after")
				// Change the surviving immutable decision using the existing file fixture.
				entries, err := os.ReadDir(filepath.Join(root, "profiles"))
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, entry := range entries {
					if strings.Contains(entry.Name(), "decision") {
						if err := os.WriteFile(filepath.Join(root, "profiles", entry.Name()), []byte("unknown decision"), 0600); err != nil {
							t.Fatal(err)
						}
						found = true
					}
				}
				if !found {
					t.Fatal("decision fixture not found")
				}
			}
			if scenario.name == "busy stationary lock" {
				d, err := r.open(true)
				if err != nil {
					t.Fatal(err)
				}
				defer d.close()
				if err := d.lock(); err != nil {
					t.Fatal(err)
				}
				defer d.release()
			}
			before := map[string][]byte{}
			if scenario.required {
				entries, _ := os.ReadDir(filepath.Join(root, "profiles"))
				for _, entry := range entries {
					if entry.IsDir() {
						continue
					}
					data, _ := os.ReadFile(filepath.Join(root, "profiles", entry.Name()))
					before[entry.Name()] = data
				}
			}
			command := exec.Command(binary, "profile", "recover", "--json")
			command.Env = []string{"HOME=" + home, "PATH=/nonexistent", "LANG=C"}
			output, err := command.CombinedOutput()
			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			var result struct {
				State            State                           `json:"state"`
				RecoveryRequired bool                            `json:"recoveryRequired"`
				Diagnostic       *struct{ Code, Message string } `json:"diagnostic"`
			}
			if err := json.Unmarshal(output, &result); err != nil {
				t.Fatalf("invalid JSON: %v %s", err, output)
			}
			if code != scenario.code || result.State != scenario.state || result.RecoveryRequired != scenario.required {
				t.Fatalf("wrong outcome: %d %+v %s", code, result, output)
			}
			if strings.Contains(string(output), home) || strings.Contains(string(output), "unknown decision") {
				t.Fatalf("private output: %s", output)
			}
			if scenario.name == "busy stationary lock" && (result.Diagnostic == nil || result.Diagnostic.Code != "busy" || !strings.Contains(result.Diagnostic.Message, "inspection")) {
				t.Fatalf("false inspected outcome: %s", output)
			}
			for name, data := range before {
				current, err := os.ReadFile(filepath.Join(root, "profiles", name))
				if err != nil || string(current) != string(data) {
					t.Fatal("unsafe evidence changed", name, err)
				}
			}
			if scenario.code == 0 {
				assertSettled(t, r, "create")
			}
		})
	}
	// This transaction supplies an exact history identity through the real Recover
	// result. The executable must report the identity already bound to the decision.
	t.Run("exact committed history", func(t *testing.T) {
		home := t.TempDir()
		r := New(filepath.Join(home, ".acs"))
		expected, _ := AbsentRevision("example")
		r.hook = func(point string) error {
			if point == "publish.sync.before" {
				return errors.New("interrupted publication")
			}
			return nil
		}
		if out, err := r.Apply(context.Background(), HistoryRequest{Request: CreateRequest{"example", expected, []byte("opaque bytes")}, Operation: "create"}); err == nil || out.State != Unknown {
			t.Fatalf("missing interrupted history: %+v %v", out, err)
		}
		r.hook = nil
		// Read the already prepared fixture identity, never a later history list.
		attachments, err := filepath.Glob(filepath.Join(r.acsHome, "profiles", "history", "txn_*.json"))
		if err != nil || len(attachments) != 1 {
			t.Fatalf("history fixture: %v %v", attachments, err)
		}
		data, err := os.ReadFile(attachments[0])
		if err != nil {
			t.Fatal(err)
		}
		var transaction historyTxn
		if err := json.Unmarshal(data, &transaction); err != nil {
			t.Fatal(err)
		}
		wanted := HistoryIdentity{LineageID: transaction.LineageID, EventID: transaction.EventID}

		command := exec.Command(binary, "profile", "recover", "--json")
		command.Env = []string{"HOME=" + home, "PATH=/nonexistent"}
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatal(err, string(output))
		}
		var result struct {
			State   State `json:"state"`
			History *struct {
				LineageID string `json:"lineageId"`
				EventID   string `json:"eventId"`
			} `json:"history"`
		}
		if err := json.Unmarshal(output, &result); err != nil || result.State != Committed || result.History == nil || result.History.LineageID != wanted.LineageID || result.History.EventID != wanted.EventID {
			t.Fatalf("wrong exact history: %s %v", output, err)
		}
	})
}
