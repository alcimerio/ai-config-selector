package acceptance_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestDevinProtocolSecretSerialization(t *testing.T) {
	d := nativeDevinTestDriver(t)
	nativeDevinPhase(t, d, "skills", "list", "--json")
	w := nativeDevinPOST(d, devinModel, "application/connect+proto", []byte(devinSelectedSecret))
	if w.Code != 409 || d.failure == nil || strings.Contains(w.Body.String(), devinSelectedSecret) {
		t.Fatal("request secret not safely refused")
	}
}
func TestDevinProtocolInspectState(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "state.log")
	if e := os.WriteFile(p, []byte("ordinary state"), 0600); e != nil {
		t.Fatal(e)
	}
	if got, e := devinInspectState(root); e != nil || got.Files != 1 {
		t.Fatal("ordinary state", got, e)
	}
	if e := os.WriteFile(p, []byte(devinSelectedSecret), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := devinInspectState(root); e == nil || strings.Contains(e.Error(), devinSelectedSecret) {
		t.Fatal("leak not safely refused")
	}
	if e := os.Remove(p); e != nil {
		t.Fatal(e)
	}
	external := filepath.Join(t.TempDir(), "outside")
	if e := os.WriteFile(external, []byte(devinSelectedSecret), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink(external, p); e != nil {
		t.Fatal(e)
	}
	if got, e := devinInspectState(root); e != nil || got.Files != 0 || got.Links != 1 {
		t.Fatal("followed external link", got, e)
	}
	if e := os.Remove(p); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, make([]byte, (4<<20)+1), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := devinInspectState(root); e == nil {
		t.Fatal("oversized state accepted")
	}
}
func TestDevinProtocolTripwireLiteral(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "space ' quote $(false) `false` $HOME")
	script := "set -eu\n(set -C; : > " + devinShellLiteral(p) + ")\n"
	if out, e := exec.Command("/bin/sh", "-c", script).CombinedOutput(); e != nil {
		t.Fatalf("literal command failed: %v (%d bytes)", e, len(out))
	}
	if _, e := os.Stat(p); e != nil {
		t.Fatal("literal marker absent")
	}
	if exec.Command("/bin/sh", "-c", script).Run() == nil {
		t.Fatal("exclusive marker overwritten")
	}
}

func TestDevinProtocolSecretStream(t *testing.T) {
	for i := 0; i <= len(devinSelectedSecret); i++ {
		var s devinSecretStream
		a := s.feed([]byte(devinSelectedSecret[:i]))
		b := s.feed([]byte(devinSelectedSecret[i:]))
		if a == nil && b == nil {
			t.Fatal("split secret accepted")
		}
	}
}
func TestDevinProtocolInspectStateBounds(t *testing.T) {
	t.Run("filename", func(t *testing.T) {
		r := t.TempDir()
		if e := os.WriteFile(filepath.Join(r, devinSelectedSecret), nil, 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := devinInspectState(r); e == nil {
			t.Fatal("secret filename accepted")
		}
	})
	t.Run("file-count", func(t *testing.T) {
		r := t.TempDir()
		for i := 0; i < 1025; i++ {
			if e := os.WriteFile(filepath.Join(r, fmt.Sprint(i)), nil, 0600); e != nil {
				t.Fatal(e)
			}
		}
		if _, e := devinInspectState(r); e == nil {
			t.Fatal("file cap accepted")
		}
	})
	t.Run("missing-generated", func(t *testing.T) {
		if e := devinInspectGenerated(t.TempDir()); e == nil {
			t.Fatal("missing config accepted")
		}
	})
}

func TestDevinProtocolRequestMetadataSecrecy(t *testing.T) {
	for _, location := range []string{"url", "header"} {
		t.Run(location, func(t *testing.T) {
			d := nativeDevinTestDriver(t)
			r := httptest.NewRequest("POST", "http://localhost/test", nil)
			if location == "url" {
				r.URL.RawQuery = "q=" + url.QueryEscape(devinSelectedSecret)
			} else {
				r.Header.Set("X-Fixture", devinSelectedSecret)
			}
			w := httptest.NewRecorder()
			d.ServeHTTP(w, r)
			if w.Code != 409 || d.failure == nil || strings.Contains(w.Body.String(), devinSelectedSecret) {
				t.Fatal("metadata leak not safely refused")
			}
		})
	}
}
func TestDevinProtocolGeneratedSemantics(t *testing.T) {
	root := t.TempDir()
	files := map[string]any{
		".config/devin/config.json":     map[string]any{"version": 1, "shell": map[string]bool{"setup_complete": true}, "theme_mode": "dark", "read_config_from": map[string]bool{"cursor": false, "windsurf": false, "claude": false, "opencode": false, "zed": false}},
		".config/devin/mcp_config.json": map[string]any{"mcpServers": map[string]any{"fixture": map[string]any{"command": "/fixed/acs", "type": "stdio", "args": []string{"--acs-mcp-launch", root, "fixture"}, "disabledTools": []string{"acs_blocked_echo"}}}},
		".acs/mcp/recipes.json":         []any{map[string]any{"id": "fixture", "sessionHome": root, "environmentNames": []string{"PROFILE_MCP_ARGUMENT", "PROFILE_MCP_SECRET"}, "disabledTools": []string{"acs_blocked_echo"}, "arguments": []any{map[string]string{"kind": "environment", "value": "PROFILE_MCP_ARGUMENT"}, map[string]string{"kind": "path", "value": "/selected/input"}}}},
	}
	for rel, v := range files {
		p := filepath.Join(root, rel)
		if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			t.Fatal(e)
		}
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(p, b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := devinInspectGenerated(root); e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(root, ".config/devin/config.json")
	good, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(p, []byte(`{"read_config_from":{"cursor":false}}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e = devinInspectGenerated(root); e == nil {
		t.Fatal("partial controls accepted")
	}
	if e = os.WriteFile(p, good, 0600); e != nil {
		t.Fatal(e)
	}
	p = filepath.Join(root, ".acs/mcp/recipes.json")
	good, e = os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(p, bytes.ReplaceAll(good, []byte("PROFILE_MCP_SECRET"), []byte("wrong-reference")), 0600); e != nil {
		t.Fatal(e)
	}
	if e = devinInspectGenerated(root); e == nil {
		t.Fatal("wrong recipe binding accepted")
	}
}
func TestDevinProtocolPersistedHistorySecrecy(t *testing.T) {
	r := t.TempDir()
	p := filepath.Join(r, "history", "lineage", "event.json")
	if e := os.MkdirAll(filepath.Dir(p), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(p, []byte(devinSelectedSecret), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := devinInspectState(r); e == nil {
		t.Fatal("nested history leak accepted")
	}
}
func TestDevinProtocolProjectImporterShapes(t *testing.T) {
	r := t.TempDir()
	if e := devinSeedProjectImports(r, "/fixture/server"); e != nil {
		t.Fatal(e)
	}
	for rel, key := range map[string]string{".cursor/mcp.json": "mcpServers", ".mcp.json": "mcpServers", "opencode.json": "mcp", ".zed/settings.json": "context_servers"} {
		b, e := os.ReadFile(filepath.Join(r, rel))
		if e != nil {
			t.Fatal(e)
		}
		var v map[string]json.RawMessage
		if json.Unmarshal(b, &v) != nil || len(v) != 1 || v[key] == nil {
			t.Fatal("wrong importer wrapper")
		}
	}
	if devinSeedProjectImports(r, "/fixture/server") == nil {
		t.Fatal("existing fixtures overwritten")
	}
}
