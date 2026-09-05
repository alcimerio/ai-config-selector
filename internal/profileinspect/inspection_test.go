package profileinspect

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStructuralInspection(t *testing.T) {
	valid := `{"version":2,"name":"example","target":"devin","categories":{"skills":{"schemaVersion":1,"selection":%s}}}`
	reference := `[{"source":"shared-agents","relativePath":"missing"}]`
	for _, tc := range []struct{ name, body, code string }{
		{"valid", fmt.Sprintf(valid, reference), ""},
		{"empty categories", `{"version":2,"name":"example","target":"devin","categories":{}}`, ""},
		{"legacy", `{"version":1,"name":"example","target":"devin","skillReferences":[]}`, ""},
		{"malformed", "secret garbage", "invalid_structure"},
		{"null", "null", "invalid_structure"},
		{"array", "[]", "invalid_structure"},
		{"trailing", fmt.Sprintf(valid, reference) + ` {}`, "invalid_structure"},
		{"duplicate", `{"version":1,"version":2,"name":"example","target":"devin","categories":{}}`, "invalid_structure"},
		{"case alias", `{"version":2,"Version":2,"name":"example","target":"devin","categories":{}}`, "unsupported_content"},
		{"identity", `{"version":2,"name":"other","target":"devin","categories":{}}`, "identity_mismatch"},
		{"bad body name", `{"version":2,"name":"../secret","target":"devin","categories":{}}`, "invalid_structure"},
		{"future", `{"version":3,"secret":"do not show"}`, "unsupported_content"},
		{"target", `{"version":2,"name":"example","target":"other","categories":{}}`, "unsupported_content"},
		{"category", `{"version":2,"name":"example","target":"devin","categories":{"secret":{}}}`, "unsupported_content"},
		{"category version", `{"version":2,"name":"example","target":"devin","categories":{"skills":{"schemaVersion":3,"selection":[]}}}`, "unsupported_content"},
		{"category null", `{"version":2,"name":"example","target":"devin","categories":null}`, "invalid_structure"},
		{"category field", `{"version":2,"name":"example","target":"devin","categories":{"skills":{"schemaVersion":1,"selection":[],"secret":true}}}`, "unsupported_content"},
		{"missing version", `{"name":"example","target":"devin","categories":{}}`, "invalid_structure"},
		{"null version", `{"version":null,"name":"example","target":"devin","categories":{}}`, "invalid_structure"},
		{"selection null", fmt.Sprintf(valid, "null"), "invalid_structure"},
		{"selection object", fmt.Sprintf(valid, "{}"), "invalid_structure"},
		{"selection scalar", fmt.Sprintf(valid, `[1]`), "invalid_structure"},
		{"selection null item", fmt.Sprintf(valid, `[null]`), "invalid_structure"},
		{"selection field", fmt.Sprintf(valid, `[{"source":"shared-agents","relativePath":"x","secret":"hidden"}]`), "unsupported_content"},
		{"selection duplicate key", fmt.Sprintf(valid, `[{"source":"shared-agents","source":"devin-config","relativePath":"x"}]`), "invalid_structure"},
		{"source", fmt.Sprintf(valid, `[{"source":"private-source","relativePath":"x"}]`), "unsupported_content"},
		{"missing source", fmt.Sprintf(valid, `[{"relativePath":"x"}]`), "invalid_structure"},
		{"absolute", fmt.Sprintf(valid, `[{"source":"shared-agents","relativePath":"/private/path"}]`), "invalid_structure"},
		{"escape", fmt.Sprintf(valid, `[{"source":"shared-agents","relativePath":"a/../../private"}]`), "invalid_structure"},
		{"dot", fmt.Sprintf(valid, `[{"source":"shared-agents","relativePath":"a/.."}]`), "invalid_structure"},
		{"empty", fmt.Sprintf(valid, `[{"source":"shared-agents","relativePath":""}]`), "invalid_structure"},
		{"nul", fmt.Sprintf(valid, `[{"source":"shared-agents","relativePath":"a\u0000b"}]`), "invalid_structure"},
		{"duplicates", fmt.Sprintf(valid, `[{"source":"shared-agents","relativePath":"a"},{"source":"shared-agents","relativePath":"./a"}]`), "invalid_structure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := decode(newEntry("example"), []byte(tc.body))
			if tc.code == "" {
				if entry.Status != "valid" {
					t.Fatalf("%+v", entry)
				}
			} else {
				if entry.Diagnostic == nil || entry.Diagnostic.Code != tc.code || len(entry.Categories) != 0 || entry.Target != nil {
					t.Fatalf("%+v", entry)
				}
			}
		})
	}
}
func TestInspectionPreservesStoredSpellingsAndSorts(t *testing.T) {
	data := `{"version":1,"name":"example","target":"devin","skillReferences":[{"source":"shared-agents","relativePath":"./z\u001b[31m"},{"source":"devin-config","relativePath":"folder/../a"}]}`
	entry := decode(newEntry("example"), []byte(data))
	if entry.Status != "valid" || *entry.StoredVersion != 1 || entry.Categories[0].SchemaVersion != nil {
		t.Fatalf("%+v", entry)
	}
	refs := entry.Categories[0].Selection
	if refs[0].Source != "devin-config" || refs[0].RelativePath != "folder/../a" || refs[1].RelativePath != "./z\x1b[31m" {
		t.Fatal("changed stored references")
	}
	encoded, _ := json.Marshal(entry)
	if strings.ContainsRune(string(encoded), '\x1b') {
		t.Fatal("unescaped control")
	}
}
func makeStore(t *testing.T) (Store, string) {
	t.Helper()
	home := t.TempDir()
	dir := filepath.Join(home, ".acs", "profiles")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return Store{Home: home}, dir
}
func TestInspectionFileBoundaries(t *testing.T) {
	store, dir := makeStore(t)
	for _, tc := range []struct {
		name, code string
		setup      func(string) error
	}{
		{"directory", "non_regular", func(p string) error { return os.Mkdir(p, 0700) }},
		{"fifo", "non_regular", func(p string) error { return unix.Mkfifo(p, 0600) }},
		{"link", "non_regular", func(p string) error { return os.Symlink("/unrelated/private/path", p) }},
		{"large", "too_large", func(p string) error { return os.WriteFile(p, []byte(strings.Repeat(" ", maxProfileBytes+1)), 0600) }},
		{"bounded", "invalid_structure", func(p string) error { return os.WriteFile(p, []byte(strings.Repeat(" ", maxProfileBytes)), 0600) }},
		{"removed", "missing", func(p string) error { return nil }},
	} {
		if err := tc.setup(filepath.Join(dir, tc.name+".json")); err != nil {
			t.Fatal(err)
		}
		result := store.Show(tc.name)
		if result.ExitCode() != 1 || result.Entries[0].Diagnostic.Code != tc.code {
			t.Fatalf("%s: %+v", tc.name, result)
		}
	}
	directory, missing := store.open()
	if missing || directory == nil {
		t.Fatal("open")
	}
	defer directory.Close()
	if err := os.WriteFile(filepath.Join(dir, "removed.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	names, err := directory.Readdirnames(-1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "removed.json")); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, name := range names {
		if name == "removed.json" {
			found = true
			if e := readEntry(directory, name); e.Diagnostic.Code != "missing" {
				t.Fatalf("%+v", e)
			}
		}
	}
	if !found {
		t.Fatal("did not enumerate removed entry")
	}
}
func TestInspectionStoreIndirection(t *testing.T) {
	for _, component := range []string{".acs", ".acs/profiles"} {
		t.Run(component, func(t *testing.T) {
			home := t.TempDir()
			target := t.TempDir()
			link := filepath.Join(home, component)
			if err := os.MkdirAll(filepath.Dir(link), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}
			for _, result := range []Result{(Store{Home: home}).List(), (Store{Home: home}).Show("example")} {
				if result.ExitCode() != 1 || result.Diagnostic.Code != "storage_unavailable" {
					t.Fatalf("%+v", result)
				}
			}
		})
	}
	store, dir := makeStore(t)
	directory, _ := store.open()
	defer directory.Close()
	if err := os.WriteFile(filepath.Join(dir, "example.json"), []byte(`{"version":2,"name":"example","target":"devin","categories":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir, dir+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), dir); err != nil {
		t.Fatal(err)
	}
	if e := readEntry(directory, "example.json"); e.Status != "valid" {
		t.Fatal("directory descriptor did not pin storage")
	}
}
func TestInspectionUnreadableHelper(t *testing.T) {
	home := os.Getenv("ACS_INSPECTION_PERMISSION_HELPER")
	if home == "" {
		return
	}
	result := (Store{Home: home}).List()
	if os.Getenv("ACS_INSPECTION_DENIED_DIRECTORY") == "1" {
		if result.ExitCode() != 1 || result.Diagnostic == nil || result.Diagnostic.Code != "storage_unavailable" {
			t.Fatalf("directory permission result: %+v", result)
		}
		return
	}
	if result.ExitCode() != 0 || len(result.Entries) != 2 || result.Entries[0].Status != "unreadable" || result.Entries[1].Status != "valid" {
		t.Fatalf("unexpected permission result: %+v", result)
	}
	if result := (Store{Home: home}).Show("denied"); result.ExitCode() != 1 || result.Entries[0].Diagnostic.Code != "unreadable" {
		t.Fatal("show unreadable contract")
	}
}
func TestInspectionUnreadableDoesNotHideSibling(t *testing.T) {
	// A child actually lacking permission is required, even when tests run as root.
	home, err := os.MkdirTemp("", "acs-inspection-permissions-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(home)
	for _, dir := range []string{home, filepath.Join(home, ".acs"), filepath.Join(home, ".acs", "profiles")} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"denied", "valid"} {
		mode := os.FileMode(0644)
		if name == "denied" {
			mode = 0000
		}
		body := fmt.Sprintf(`{"version":2,"name":%q,"target":"devin","categories":{}}`, name)
		if err := os.WriteFile(filepath.Join(home, ".acs", "profiles", name+".json"), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(home, "test-helper")
	if err := os.WriteFile(child, contents, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(child, 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(child, "-test.run=^TestInspectionUnreadableHelper$")
	cmd.Env = append(os.Environ(), "ACS_INSPECTION_PERMISSION_HELPER="+home)
	if os.Geteuid() == 0 {
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("permission child: %v %s", err, out)
	}
	profilesDirectory := filepath.Join(home, ".acs", "profiles")
	if err := os.Chmod(profilesDirectory, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(profilesDirectory, 0755)
	denied := exec.Command(child, "-test.run=^TestInspectionUnreadableHelper$")
	denied.Env = append(cmd.Env, "ACS_INSPECTION_DENIED_DIRECTORY=1")
	denied.SysProcAttr = cmd.SysProcAttr
	if out, err := denied.CombinedOutput(); err != nil {
		t.Fatalf("directory permission child: %v %s", err, out)
	}

}
func TestInvalidFilenameHasSafeRepairIdentifier(t *testing.T) {
	store, dir := makeStore(t)
	for _, name := range []string{"bad\nname.json", "bad\x1bname.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("private payload"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	result := store.List()
	data, _ := json.Marshal(result)
	var decoded map[string]any
	_ = json.Unmarshal(data, &decoded)
	entries := decoded["entries"].([]any)
	first := entries[0].(map[string]any)["file"]
	second := entries[1].(map[string]any)["file"]
	if first == nil || second == nil || reflect.DeepEqual(first, second) {
		t.Fatalf("invalid entries have no distinct repair identifiers: %s", data)
	}
	if strings.ContainsRune(string(data), '\x1b') || strings.Contains(string(data), "private payload") {
		t.Fatal("unsafe output")
	}
}

func TestInspectionEntryReplacementDoesNotFollowOrBlock(t *testing.T) {
	store, dir := makeStore(t)
	directory, _ := store.open()
	defer directory.Close()
	outside := filepath.Join(t.TempDir(), "secret.json")
	if err := os.WriteFile(outside, []byte(`{"version":2,"name":"example","target":"devin","categories":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, "example.json")
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			_ = os.Symlink(outside, filepath.Join(dir, "swap"))
			_ = os.Rename(filepath.Join(dir, "swap"), destination)
			_ = os.Remove(destination)
			_ = unix.Mkfifo(filepath.Join(dir, "swap"), 0600)
			_ = os.Rename(filepath.Join(dir, "swap"), destination)
			_ = os.Remove(destination)
		}
	}()
	defer func() { close(stop); <-done }()
	for i := 0; i < 300; i++ {
		entry := readEntry(directory, "example.json")
		if entry.Status == "valid" {
			t.Fatal("followed unrelated symlink")
		}
	}
}
