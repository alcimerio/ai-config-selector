package codexauthresource_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func agentCatalogBody(present, lite bool) string {
	props := map[string]any{}
	if present {
		props["agent_type"] = map[string]any{"type": "string", "description": "Choose type.\nAvailable roles:\nacs-reviewer: {\nSynthetic assessment reviewer\n}\ndefault: {\nDefault agent\n}"}
	}
	fn := map[string]any{"type": "function", "name": "spawn_agent", "parameters": map[string]any{"type": "object", "properties": props}}
	tools := []any{map[string]any{"type": "namespace", "name": "multi_agent_v1", "tools": []any{fn}}}
	request := map[string]any{"input": []any{map[string]any{"type": "message", "role": "user", "content": []any{}}}}
	if lite {
		request["input"] = []any{map[string]any{"type": "additional_tools", "role": "developer", "tools": tools}}
	} else {
		request["tools"] = tools
	}
	b, _ := json.Marshal(request)
	return string(b)
}
func TestNativeAgentCatalogShapeAndPairedAbsence(t *testing.T) {
	for _, lite := range []bool{false, true} {
		for _, present := range []bool{false, true} {
			body := agentCatalogBody(present, lite)
			if e := assertNativeAgentCatalog(body, present); e != nil {
				t.Fatal(e)
			}
			if assertNativeAgentCatalog(body, !present) == nil {
				t.Fatal("opposite expected state accepted")
			}
		}
	}
}
func TestNativeAgentCatalogRefusals(t *testing.T) {
	base := agentCatalogBody(true, false)
	for name, body := range map[string]string{
		"prefixed-role":     strings.Replace(base, "acs-reviewer", "evilacs-reviewer", 1),
		"description-decoy": strings.Replace(base, "agent_type", "other_argument", 1),
		"deferred":          strings.Replace(base, `"name":"spawn_agent"`, `"name":"spawn_agent","defer_loading":true`, 1),
		"duplicate-member":  strings.Replace(base, `"name":"spawn_agent"`, `"name":"spawn_agent","name":"spawn_agent"`, 1),
		"unknown-namespace": strings.Replace(base, "multi_agent_v1", "unestablished", 1),
		"wrong-role-type":   strings.Replace(base, `"type":"string"`, `"type":"object"`, 1),
		"no-spawn":          strings.Replace(base, "spawn_agent", "list_agents", 1),
		"wrong-description": strings.Replace(base, "Synthetic assessment reviewer", "different", 1),
		"two-entries":       strings.Replace(base, `Available roles:\n`, `Available roles:\nacs-reviewer: {\nSynthetic assessment reviewer\n}\n`, 1),
		"mixed-envelopes":   strings.Replace(agentCatalogBody(true, true), `{"input":`, `{"tools":[],"input":`, 1),
		"oversize":          strings.Repeat(" ", 2<<20) + base,
	} {
		t.Run(name, func(t *testing.T) {
			if assertNativeAgentCatalog(body, true) == nil {
				t.Fatal("ambiguous or unestablished catalog accepted")
			}
		})
	}
	if assertNativeAgentCatalog(`{"tools":[],"input":[{"type":"message","content":"Available roles:\nacs-reviewer: {\nSynthetic assessment reviewer\n}"}]}`, true) == nil {
		t.Fatal("prompt echo accepted")
	}
}

func TestNativeAgentCatalogNestedNamespaceRejected(t *testing.T) {
	var request map[string]any
	if e := json.Unmarshal([]byte(agentCatalogBody(true, false)), &request); e != nil {
		t.Fatal(e)
	}
	request["tools"] = []any{map[string]any{"type": "namespace", "name": "unestablished", "tools": request["tools"]}}
	body, e := json.Marshal(request)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = nativeAgentCatalogJSON(string(body)); e != nil {
		t.Fatal("reproduction must be valid JSON", e)
	}
	if assertNativeAgentCatalog(string(body), true) == nil {
		t.Fatal("nested spoof namespace accepted")
	}
}

func TestNativeAgentCatalogSeedDoesNotRewriteConfig(t *testing.T) {
	for _, present := range []bool{true, false} {
		home, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(home, ".codex")
		if e := os.Mkdir(dir, 0700); e != nil {
			t.Fatal(e)
		}
		cfg := filepath.Join(dir, "config.toml")
		original := []byte("# protected fixture config\n")
		if e := os.WriteFile(cfg, original, 0600); e != nil {
			t.Fatal(e)
		}
		if e := seedNativeAgentRole(home, present); e != nil {
			t.Fatal(e)
		}
		got, e := os.ReadFile(cfg)
		if e != nil || !bytes.Equal(got, original) {
			t.Fatal("generated config changed")
		}
		role := filepath.Join(dir, "agents", "acs-reviewer.toml")
		b, e := os.ReadFile(role)
		if present {
			if e != nil || string(b) != nativeAgentRoleDefinition {
				t.Fatal("role seed mismatch")
			}
			if seedNativeAgentRole(home, true) == nil {
				t.Fatal("existing definition overwritten")
			}
		} else if !os.IsNotExist(e) {
			t.Fatal("negative created definition")
		}
	}
}

func TestNativeAgentCatalogSeedRejectsAliases(t *testing.T) {
	for _, present := range []bool{false, true} {
		for _, level := range []string{"home", "codex", "agents", "leaf", "dangling-leaf"} {
			t.Run(fmt.Sprintf("%s/present=%t", level, present), func(t *testing.T) {
				root, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				home := filepath.Join(root, "home")
				outside := filepath.Join(root, "outside")
				for _, d := range []string{home, outside} {
					if err := os.Mkdir(d, 0700); err != nil {
						t.Fatal(err)
					}
				}
				target := filepath.Join(outside, "acs-reviewer.toml")
				sentinel := []byte("outside sentinel\n")
				if level == "leaf" {
					if err := os.WriteFile(target, sentinel, 0600); err != nil {
						t.Fatal(err)
					}
				}
				config := filepath.Join(outside, "config.toml")
				if err := os.WriteFile(config, sentinel, 0600); err != nil {
					t.Fatal(err)
				}
				switch level {
				case "home":
					alias := filepath.Join(root, "home-alias")
					if err := os.Symlink(home, alias); err != nil {
						t.Fatal(err)
					}
					home = alias
				case "codex":
					if err := os.Symlink(outside, filepath.Join(home, ".codex")); err != nil {
						t.Fatal(err)
					}
				case "agents":
					if err := os.Mkdir(filepath.Join(home, ".codex"), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(outside, filepath.Join(home, ".codex", "agents")); err != nil {
						t.Fatal(err)
					}
				default:
					dir := filepath.Join(home, ".codex", "agents")
					if err := os.MkdirAll(dir, 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, filepath.Join(dir, "acs-reviewer.toml")); err != nil {
						t.Fatal(err)
					}
				}
				if seedNativeAgentRole(home, present) == nil {
					t.Fatal("unsafe alias accepted")
				}
				if level != "leaf" {
					if _, err := os.Lstat(target); !os.IsNotExist(err) {
						t.Fatal("outside leaf created")
					}
				} else {
					got, err := os.ReadFile(target)
					if err != nil || !bytes.Equal(got, sentinel) {
						t.Fatal("outside file changed")
					}
				}
				got, err := os.ReadFile(config)
				if err != nil || !bytes.Equal(got, sentinel) {
					t.Fatal("outside config changed")
				}
				if _, err := os.Lstat(filepath.Join(outside, "agents")); !os.IsNotExist(err) {
					t.Fatal("outside directory created")
				}
			})
		}
	}
}
