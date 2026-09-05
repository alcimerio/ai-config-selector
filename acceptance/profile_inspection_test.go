//go:build darwin || linux

package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type inspectionSnapshot struct {
	Mode     fs.FileMode
	Modified int64
	Bytes    string
}

func snapshotInspectionHome(t *testing.T, home string) map[string]inspectionSnapshot {
	t.Helper()
	result := map[string]inspectionSnapshot{}
	err := filepath.WalkDir(home, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := inspectionSnapshot{Mode: info.Mode(), Modified: info.ModTime().UnixNano()}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value.Bytes = string(data)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			value.Bytes, err = os.Readlink(path)
			if err != nil {
				return err
			}
		}
		relative, _ := filepath.Rel(home, path)
		result[relative] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func runInspection(t *testing.T, binary, home string, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{"HOME=" + home, "PATH=/nonexistent", "TERM=xterm", "COLORTERM=truecolor", "LANG=C", "LC_ALL=C", "LC_CTYPE=C"}
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	if ctx.Err() != nil {
		t.Fatal("inspection blocked")
	}
	if errOut.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", &errOut)
	}
	if strings.Count(out.String(), "\n") != 1 || !strings.HasSuffix(out.String(), "\n") || !json.Valid(out.Bytes()) {
		t.Fatalf("not one JSON value: %q", &out)
	}
	return out.String(), code
}
func TestPromotedProfileInspectionMixedReadOnly(t *testing.T) {
	binary := promotedBinary(t)
	home := realTemporaryDirectory(t)
	dir := filepath.Join(home, ".acs", "profiles")
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	fixtures := map[string]string{
		"zeta.json":             `{"version":2,"name":"zeta","target":"devin","categories":{"skills":{"schemaVersion":1,"selection":[{"source":"shared-agents","relativePath":"removed"}]}}}`,
		"alpha.json":            `{"version":1,"name":"alpha","target":"devin","skillReferences":[{"source":"devin-config","relativePath":"missing"}]}`,
		"broken.json":           `private-corrupt-content`,
		"future.json":           `{"version":9,"name":"future","target":"devin","secret":"private-unknown-content"}`,
		"mismatch.json":         `{"version":2,"name":"other","target":"devin","categories":{}}`,
		".profile-leftover.tmp": "temporary", "README": "ignored",
	}
	for name, body := range fixtures {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0640); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(dir, "alpha.json"), filepath.Join(dir, "link.json")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(dir, "fifo.json"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".acs", "sessions", "quarantine-sentinel"), 0700); err != nil {
		t.Fatal(err)
	}
	before := snapshotInspectionHome(t, home)
	out, code := runInspection(t, binary, home, "profile", "list", "--json")
	if code != 0 {
		t.Fatalf("list code %d", code)
	}
	var result struct {
		FormatVersion int
		Entries       []struct {
			Name          string
			Status        string
			StoredVersion *int
		}
		Checks map[string]string
	}
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatal(err)
	}
	var names, statuses []string
	for _, e := range result.Entries {
		names = append(names, e.Name)
		statuses = append(statuses, e.Status)
	}
	if result.FormatVersion != 1 || !reflect.DeepEqual(names, []string{"alpha", "broken", "fifo", "future", "link", "mismatch", "zeta"}) || !reflect.DeepEqual(statuses, []string{"valid", "invalid", "invalid", "unsupported", "invalid", "invalid", "valid"}) {
		t.Fatalf("unexpected catalog: %s", out)
	}
	if !reflect.DeepEqual(result.Checks, map[string]string{"sources": "unchecked", "auth": "unchecked", "runtime": "unchecked"}) {
		t.Fatal("missing unchecked boundary")
	}
	again, _ := runInspection(t, binary, home, "profile", "list", "--json")
	if out != again {
		t.Fatal("list output changed")
	}
	for _, name := range []string{"alpha", "zeta", "broken", "future", "mismatch", "link", "fifo", "absent", "../private-name"} {
		out, code := runInspection(t, binary, home, "profile", "show", name, "--json")
		want := 1
		if name == "alpha" || name == "zeta" {
			want = 0
		}
		if code != want {
			t.Fatalf("%s: %d", name, code)
		}
		again, againCode := runInspection(t, binary, home, "profile", "show", "--json", name)
		if out != again || code != againCode {
			t.Fatal("show reordering changed result")
		}
		if strings.Contains(out, "private-") || strings.Contains(out, home) {
			t.Fatal("private contents disclosed")
		}
		if name == "alpha" && !strings.Contains(out, `"storedVersion":1`) {
			t.Fatal("legacy version lost")
		}
	}
	after := snapshotInspectionHome(t, home)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("inspection changed bytes, modes, mtime or entries")
	}
}
func TestPromotedProfileInspectionMissingAndEmpty(t *testing.T) {
	binary := promotedBinary(t)
	home := realTemporaryDirectory(t)
	before := snapshotInspectionHome(t, home)
	out, code := runInspection(t, binary, home, "profile", "list", "--json")
	if code != 0 || !strings.Contains(out, `"storage":"missing"`) || !strings.Contains(out, `"entries":[]`) {
		t.Fatalf("missing store: %s", out)
	}
	if !reflect.DeepEqual(before, snapshotInspectionHome(t, home)) {
		t.Fatal("missing store created state")
	}
	if err := os.MkdirAll(filepath.Join(home, ".acs", "profiles"), 0700); err != nil {
		t.Fatal(err)
	}
	out, code = runInspection(t, binary, home, "profile", "list", "--json")
	if code != 0 || !strings.Contains(out, `"storage":"present"`) || !strings.Contains(out, `"entries":[]`) {
		t.Fatalf("empty store: %s", out)
	}
}
