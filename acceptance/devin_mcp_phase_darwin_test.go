//go:build darwin

package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type devinCapability struct {
	ID, RootName, Challenge string
	Generation              uint64
}

func devinPhaseObserver(candidate, home, tools, workspace, trampoline string, d *devinDriver) func(string, devinPhaseReceipt) error {
	var previous devinCapability
	return func(phase string, r devinPhaseReceipt) error {
		paths, e := filepath.Glob(filepath.Join(home, ".acs", "session-operations-v1", "capabilities", "*.json"))
		if e != nil || len(paths) != 1 {
			return errors.New("ambiguous live Session capability")
		}
		f, e := os.Open(paths[0])
		if e != nil {
			return e
		}
		info, e := f.Stat()
		if e != nil || !info.Mode().IsRegular() || info.Size() > 16384 {
			_ = f.Close()
			return errors.New("capability file shape")
		}
		var cap devinCapability
		e = json.NewDecoder(f).Decode(&cap)
		_ = f.Close()
		if e != nil || cap.ID == "" || cap.RootName == "" || filepath.Base(cap.RootName) != cap.RootName || cap.Generation == 0 || cap.Challenge == "" {
			return errors.New("capability identity")
		}
		if previous.ID != "" && (cap.ID != previous.ID || cap.RootName != previous.RootName || cap.Generation <= previous.Generation || cap.Challenge == previous.Challenge) {
			return errors.New("phase capability not fresh")
		}
		root := filepath.Join(home, ".acs", "sessions", cap.RootName)
		expected := filepath.Join(root, "home")
		actualInfo, e := os.Stat(r.SessionHome)
		if e != nil {
			return e
		}
		expectedInfo, e := os.Stat(expected)
		if e != nil || !os.SameFile(actualInfo, expectedInfo) {
			return errors.New("phase HOME not capability-bound")
		}
		if _, e = os.Stat(filepath.Join(root, ".acs-cleanup-proof-v1")); !os.IsNotExist(e) {
			return errors.New("live phase has cleanup proof")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		ps := exec.CommandContext(ctx, "/bin/ps", "-p", strconv.Itoa(r.PID), "-o", "comm=")
		var output bytes.Buffer
		ps.Stdout = &output
		if e = ps.Run(); e != nil || ctx.Err() != nil || output.Len() > 4096 || strings.TrimSpace(output.String()) != trampoline {
			return errors.New("phase PID is not the fixed trampoline")
		}
		recover := exec.CommandContext(ctx, candidate, "session", "recover", cap.ID, "--json")
		recover.Dir = workspace
		recover.Env = []string{"HOME=" + home, "PATH=" + tools + ":/usr/bin:/bin"}
		data, e := recover.Output()
		var outcome struct {
			Outcome string `json:"outcome"`
		}
		if e == nil || len(data) > 65536 || json.Unmarshal(data, &outcome) != nil || (outcome.Outcome != "active" && outcome.Outcome != "busy") {
			return errors.New("public live Session proof")
		}
		d.mu.Lock()
		if d.home == "" {
			d.home = expected
		}
		same := d.home == expected
		d.mu.Unlock()
		if !same {
			return errors.New("Session HOME changed")
		}
		if previous.ID == "" {
			ambient, err := json.Marshal(map[string]any{"mcpServers": map[string]any{"acs-import-windsurf": map[string]any{"command": filepath.Join(workspace, "ambient-server.sh"), "args": []string{}, "env": map[string]string{}}}})
			if err != nil {
				return err
			}
			directory := filepath.Join(expected, ".codeium", "windsurf")
			if err = os.MkdirAll(directory, 0700); err != nil {
				return err
			}
			file, err := os.OpenFile(filepath.Join(directory, "mcp_config.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			_, err = file.Write(ambient)
			closeErr := file.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		}
		if e = devinInspectGenerated(expected, candidate); e != nil {
			return e
		}
		previous = cap
		return nil
	}
}

func verifyDevinPhaseDone(coord, phase string, readyPID int) error {
	var started devinPhaseStartedReceipt
	if e := devinReadJSON(filepath.Join(coord, phase+".started"), &started); e != nil {
		return e
	}
	var done devinPhaseDoneReceipt
	if e := devinReadJSON(filepath.Join(coord, phase+".done"), &done); e != nil {
		return e
	}
	expected := map[string][]string{"skills": {"skills", "list", "--json"}, "auth": {"auth", "status"}, "attached": {"--respect-workspace-trust", "false"}}
	if diagnostic := devinPhaseCompletionDiagnostic(phase, readyPID, started, done, expected[phase]); diagnostic != "" {
		return errors.New("phase completion evidence: " + diagnostic)
	}
	return nil
}

// The actual target has naturally exited; its contained wrapper waits for this
// acknowledgement so ACS cannot remove the Session before inspection.
func inspectDevinCompletedPhase(coord, phase, home, candidate string) error {
	if err := devinInspectGenerated(home, candidate); err != nil {
		return err
	}
	return devinRelease(filepath.Join(coord, phase+".inspected"))
}
