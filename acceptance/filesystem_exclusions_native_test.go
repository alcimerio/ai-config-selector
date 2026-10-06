//go:build darwin

package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func exclusionCandidateHome(t *testing.T, binary, workspace, access string, paths []map[string]any, grants ...map[string]any) string {
	t.Helper()
	home := realTemporaryDirectory(t)
	common := map[string]any{"skills": map[string]any{"version": 1, "selection": []any{}}, "workspace": map[string]any{"version": 1, "selection": map[string]string{"access": access}}, "exclusions": map[string]any{"version": 1, "selection": map[string]any{"entries": paths}}}

	if len(grants) > 0 {
		common["paths"] = map[string]any{"version": 1, "selection": map[string]any{"entries": grants}}
	}

	document, _ := json.Marshal(map[string]any{"version": 3, "name": "exclusions", "common": common, "overlays": map[string]any{"devin": map[string]int{"version": 1}}})
	file := filepath.Join(home, "profile.json")
	if err := os.WriteFile(file, document, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "profile", "create", "--file", file)
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, os.Getenv("PATH"), map[string]string{"COLORTERM": "truecolor"})
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("candidate declarative creation: %v %s", err, output)
	}
	return home
}
func exclusionEntry(id, kind, path string) map[string]any {
	return map[string]any{"id": id, "type": kind, "reference": map[string]string{"kind": "workspace-relative", "path": path}}
}
func exclusionCandidateCommand(t *testing.T, binary, home, workspace string, arguments ...string) *exec.Cmd {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	args := append([]string{"run", "--profile", "exclusions", "--"}, arguments...)
	command := exec.CommandContext(ctx, binary, args...)
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, os.Getenv("PATH"), map[string]string{"COLORTERM": "truecolor"})
	return command
}

// These commands traverse the supplied candidate's Profile codec, authority
// resolution, Session, shared executor and production native policy.
func TestPromotedArtifactNativeFilesystemExclusions(t *testing.T) {
	binary := promotedBinary(t)
	for _, access := range []string{"read-only", "read-write"} {
		t.Run(access, func(t *testing.T) {

			ownerHome, err := os.UserHomeDir()
			if err != nil {
				t.Fatal(err)
			}
			workspace, err := os.MkdirTemp(ownerHome, ".acs-exclusions-native-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(workspace) })
			workspace, err = filepath.EvalSymlinks(workspace)
			if err != nil {
				t.Fatal(err)
			}
			hidden := filepath.Join(workspace, "container", "skills")
			if err := os.MkdirAll(hidden, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(hidden, "SKILL.md"), []byte("fixture-secret"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(workspace, "neighbor"), []byte("ordinary"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(workspace, "file-secret"), []byte("file-fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(hidden, "SKILL.md"), filepath.Join(workspace, "alias")); err != nil {
				t.Fatal(err)
			}
			home := exclusionCandidateHome(t, binary, workspace, access, []map[string]any{exclusionEntry("skills", "directory", "container/skills"), exclusionEntry("file", "file", "file-secret"), exclusionEntry("absent", "file", "absent")}, map[string]any{"id": "parent", "type": "directory", "access": "read-write", "reference": map[string]string{"kind": "workspace-relative", "path": "container"}})
			cases := map[string]string{
				"read":                   "/bin/cat container/skills/SKILL.md",
				"list":                   "/bin/ls container/skills",
				"write":                  "printf changed > container/skills/SKILL.md",
				"unlink":                 "/bin/rm container/skills/SKILL.md",
				"create-child":           "printf child > container/skills/new",
				"rename-root":            "/bin/mv container/skills moved",
				"rename-parent":          "/bin/mv container moved",
				"replace-parent":         "/bin/rm -rf container",
				"symlink":                "/bin/cat alias",
				"child":                  "/bin/sh -c '/bin/cat container/skills/SKILL.md'",
				"file":                   "/bin/cat file-secret",
				"absent-create":          "printf late > absent",
				"file-replace-directory": "/bin/rm file-secret && /bin/mkdir file-secret && printf leaked > file-secret/child",
			}
			for name, operation := range cases {
				t.Run(name, func(t *testing.T) {
					script := "if (" + operation + ") >/dev/null 2>&1; then printf 'EXPOSED'; exit 91; else printf 'DENIED'; fi"
					output, err := exclusionCandidateCommand(t, binary, home, workspace, "/bin/sh", "-c", script).CombinedOutput()
					if err != nil || string(output) != "DENIED" {
						t.Fatalf("%s: %v %s", name, err, output)
					}
				})
			}
			output, err := exclusionCandidateCommand(t, binary, home, workspace, "/bin/cat", "neighbor").CombinedOutput()
			if err != nil || string(output) != "ordinary" {
				t.Fatalf("neighbor read=%s %v", output, err)
			}
			output, err = exclusionCandidateCommand(t, binary, home, workspace, "/bin/sh", "-c", "printf changed > neighbor").CombinedOutput()
			if (err == nil) != (access == "read-write") {
				t.Fatalf("neighbor write=%v %s", err, output)
			}

			output, err = exclusionCandidateCommand(t, binary, home, workspace, "/bin/sh", "-c", "printf neighbor > container/neighbor").CombinedOutput()
			if err != nil {
				t.Fatalf("granted sibling write=%v %s", err, output)
			}
			// Parent-name visibility is deliberately outside the path-access guarantee.
			output, err = exclusionCandidateCommand(t, binary, home, workspace, "/bin/ls", "container").CombinedOutput()
			if err != nil || !bytes.Contains(output, []byte("skills")) {
				t.Fatalf("parent listing=%s %v", output, err)
			}
		})
	}
}

func fixtureSkill(t *testing.T, root, name string) {
	t.Helper()
	folder := filepath.Join(root, name)
	if err := os.MkdirAll(folder, 0700); err != nil {
		t.Fatal(err)
	}
	contents := fmt.Sprintf("---\nname: %s\ndescription: A synthetic exclusion fixture.\n---\nFixture only.\n", name)
	if err := os.WriteFile(filepath.Join(folder, "SKILL.md"), []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestPromotedArtifactNativeFilesystemExclusionCatalogs(t *testing.T) {
	binary := promotedBinary(t)
	devin := os.Getenv("ACS_TEST_DEVIN_BINARY")
	if devin == "" {
		t.Fatal("checksum-locked runtime targets are required")
	}
	for _, scenario := range []string{"baseline", "bundle", "root"} {
		t.Run(scenario, func(t *testing.T) {
			workspace := realTemporaryDirectory(t)
			if err := os.Mkdir(filepath.Join(workspace, ".git"), 0700); err != nil {
				t.Fatal(err)
			}
			fixtureSkill(t, filepath.Join(workspace, ".agents", "skills"), "excluded_fixture")
			fixtureSkill(t, filepath.Join(workspace, ".agents", "skills"), "permitted_fixture")
			fixtureSkill(t, filepath.Join(workspace, ".devin", "skills"), "native_fixture")
			entries := []map[string]any{}
			if scenario == "bundle" {
				entries = append(entries, exclusionEntry("bundle", "directory", ".agents/skills/excluded_fixture"))
			}
			if scenario == "root" {
				entries = append(entries, exclusionEntry("common", "directory", ".agents/skills"), exclusionEntry("native", "directory", ".devin/skills"))
			}
			home := exclusionCandidateHome(t, binary, workspace, "read-only", entries)
			got := []string{}
			want := []string{"excluded_fixture", "permitted_fixture"}
			if scenario == "bundle" {
				want = []string{"permitted_fixture"}
			}
			if scenario == "root" {
				want = []string{}
			}
			output, err := exclusionCandidateCommand(t, binary, home, workspace, devin, "skills", "list", "--json").Output()
			if err != nil {
				t.Fatalf("companion catalog: %v", err)
			}
			var rows []struct {
				Name string `json:"name"`
			}
			if err := json.Unmarshal(output, &rows); err != nil {
				t.Fatalf("catalog JSON: %v %s", err, output)
			}
			got = nil
			for _, row := range rows {
				if strings.HasSuffix(row.Name, "_fixture") {
					got = append(got, row.Name)
				}
			}
			sort.Strings(got)
			if scenario != "root" {
				want = append(append([]string(nil), want...), "native_fixture")
				sort.Strings(want)
			}
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("companion catalog=%v want=%v", got, want)
			}
		})
	}
}
