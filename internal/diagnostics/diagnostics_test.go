package diagnostics

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func check(t *testing.T, r Result, id, status, code string) {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			if c.Status != status || (code != "" && c.Code != code) || c.NextStep == "" {
				t.Fatalf("%s: %+v", id, c)
			}
			return
		}
	}
	t.Fatalf("missing %s", id)
}
func TestDoctorRequestedChecksAndPlatformPolicy(t *testing.T) {
	for _, tc := range []struct {
		os, arch, release string
		ok                bool
	}{{"darwin", "arm64", "26", true}, {"darwin", "amd64", "26.1.2", true}, {"darwin", "arm64", "25.6", false}, {"darwin", "arm64", "27", false}, {"darwin", "386", "26", false}, {"darwin", "arm64", "26.x", false}, {"darwin", "arm64", "26.", false}, {"linux", "amd64", "26", false}, {"windows", "amd64", "26", false}} {
		t.Run(tc.os+tc.arch+tc.release, func(t *testing.T) {
			r := doctor("", func() (launch.Platform, error) {
				return launch.Platform{OS: tc.os, Architecture: tc.arch, Release: tc.release}, nil
			}, func() bool {
				if tc.os != "darwin" {
					t.Fatal("foreign backend check")
				}
				return true
			}, func(string) bool { t.Fatal("unrequested executable lookup"); return false })
			status := "fail"
			want := 1
			if tc.ok {
				status = "pass"
				want = 0
			}
			check(t, r, "host.platform", status, "")
			check(t, r, "executable.availability", "unchecked", "not_requested")
			for _, id := range []string{"authentication", "runtime.enforcement", "executable.version", "profile.structure", "profile.sources"} {
				check(t, r, id, "unchecked", "")
			}
			if r.ExitCode() != want {
				t.Fatal(r)
			}
		})
	}
	for target, name := range map[string]string{"devin": "devin", "sandbox": "/bin/zsh", "codex-auth": "codex"} {
		for _, available := range []bool{false, true} {
			calls := 0
			r := doctor(target, func() (launch.Platform, error) {
				return launch.Platform{OS: "darwin", Architecture: "arm64", Release: "26"}, nil
			}, func() bool { return true }, func(got string) bool {
				calls++
				if got != name {
					t.Fatalf("wrong executable %s", got)
				}
				return available
			})
			status := "fail"
			if available {
				status = "pass"
			}
			check(t, r, "executable.availability", status, "")
			if calls != 1 {
				t.Fatal(calls)
			}
		}
	}
	r := doctor("", func() (launch.Platform, error) { return launch.Platform{}, errors.New("private details") }, func() bool { t.Fatal("backend after failed host metadata"); return false }, nil)
	check(t, r, "host.platform", "fail", "platform_unavailable")
	data, _ := json.Marshal(r)
	if strings.Contains(string(data), "private") {
		t.Fatal(string(data))
	}
	r = doctor("", func() (launch.Platform, error) {
		return launch.Platform{OS: "darwin", Architecture: "arm64", Release: "26"}, nil
	}, func() bool { return false }, nil)
	check(t, r, "backend.file", "fail", "backend_unavailable")
}
func writeProfile(t *testing.T, home, body string) {
	t.Helper()
	dir := filepath.Join(home, ".acs", "profiles")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "example.json"), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestValidateStructureAndSelectedSources(t *testing.T) {
	for _, tc := range []struct{ name, body, status, code string }{
		{"empty v1", `{"version":1,"name":"example","target":"devin","skillReferences":[]}`, "pass", "valid_structure"},
		{"empty v2", `{"version":2,"name":"example","target":"devin","categories":{}}`, "pass", "valid_structure"},
		{"corrupt", `secret`, "fail", "invalid_structure"},
		{"unsupported", `{"version":99}`, "fail", "unsupported_content"},
		{"malformed reference", `{"version":1,"name":"example","target":"devin","skillReferences":[{"source":"shared-agents","relativePath":"../private"}]}`, "fail", "invalid_structure"},
		{"removed", `{"version":1,"name":"example","target":"devin","skillReferences":[{"source":"shared-agents","relativePath":"removed"}]}`, "pass", "valid_structure"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			writeProfile(t, home, tc.body)
			r := Validate("example", func() (string, error) { return home, nil })
			check(t, r, "profile.structure", tc.status, tc.code)
			for _, id := range []string{"host.platform", "backend.file", "executable.availability", "executable.version", "authentication", "runtime.enforcement"} {
				check(t, r, id, "unchecked", "")
			}
			if tc.status == "fail" {
				check(t, r, "profile.sources", "unchecked", "structure_required")
			} else if tc.name == "removed" {
				check(t, r, "profile.sources", "fail", "selected_sources_unresolved")
			} else {
				check(t, r, "profile.sources", "pass", "selected_sources_resolved")
			}
		})
	}
	home := t.TempDir()
	r := Validate("missing", func() (string, error) { return home, nil })
	check(t, r, "profile.structure", "fail", "missing")
	r = Validate("../private", func() (string, error) { t.Fatal("home for invalid name"); return "", nil })
	check(t, r, "profile.structure", "fail", "invalid_name")
	r = Validate("example", func() (string, error) { return "", errors.New("private home") })
	check(t, r, "profile.structure", "fail", "storage_unavailable")
}
func TestSelectedDiscoveryPreservesRulesAndIgnoresUnselected(t *testing.T) {
	home := t.TempDir()
	source := filepath.Join(home, ".agents", "skills")
	bundle := filepath.Join(source, "selected")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	// Malformed unselected entries never become mandatory selected bundles.
	if err := os.Mkdir(filepath.Join(source, "unselected"), 0700); err != nil {
		t.Fatal(err)
	}
	// Unselected source is a file, so enumerating it would fail.
	if err := os.MkdirAll(filepath.Join(home, ".config", "devin"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".config", "devin", "skills"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	writeProfile(t, home, `{"version":1,"name":"example","target":"devin","skillReferences":[{"source":"shared-agents","relativePath":"selected"}]}`)
	get := func() Result { return Validate("example", func() (string, error) { return home, nil }) }
	check(t, get(), "profile.sources", "fail", "selected_sources_unresolved")
	if err := os.Mkdir(filepath.Join(bundle, "SKILL.md"), 0700); err != nil {
		t.Fatal(err)
	}
	check(t, get(), "profile.sources", "fail", "selected_sources_unresolved")
	if err := os.Remove(filepath.Join(bundle, "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	// Existing discovery tests regular-file metadata, not manifest text grammar.
	if err := os.WriteFile(filepath.Join(bundle, "SKILL.md"), []byte("arbitrary content"), 0600); err != nil {
		t.Fatal(err)
	}
	first := get()
	check(t, first, "profile.sources", "pass", "selected_sources_resolved")
	if !reflect.DeepEqual(first, get()) {
		t.Fatal("unstable result")
	}
	writeProfile(t, home, `{"version":1,"name":"example","target":"devin","skillReferences":[{"source":"shared-agents","relativePath":"./selected"}]}`)
	check(t, get(), "profile.sources", "fail", "selected_sources_unresolved") // strict identity; no rebinding
	ref := skills.SkillReference{Source: "shared-agents", RelativePath: "selected"}
	r := resolveSources(result("profile.validate", ""), []skills.SkillReference{ref}, []skills.SkillBundle{{Reference: ref}, {Reference: ref}})
	check(t, r, "profile.sources", "fail", "selected_sources_unresolved")
}
func TestExecutableLookupDoesNotRunAndRejectsUnsafeKinds(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PATH", home)
	file := filepath.Join(home, "devin")
	sentinel := filepath.Join(home, "executed")
	if err := os.WriteFile(file, []byte("#!/bin/sh\ntouch "+sentinel+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if !executableAvailable("devin") {
		t.Fatal("missing executable")
	}
	if _, err := os.Stat(sentinel); !os.IsNotExist(err) {
		t.Fatal("executable ran")
	}
	if err := os.Chmod(file, 0600); err != nil {
		t.Fatal(err)
	}
	if executableAvailable("devin") {
		t.Fatal("non-executable accepted")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(file, 0700); err != nil {
		t.Fatal(err)
	}
	if executableAvailable("devin") {
		t.Fatal("directory accepted")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("absent", file); err != nil {
		t.Fatal(err)
	}
	if executableAvailable("devin") {
		t.Fatal("dangling link accepted")
	}
	t.Setenv("PATH", ".:relative:")
	if executableAvailable("devin") {
		t.Fatal("relative lookup accepted")
	}
}
