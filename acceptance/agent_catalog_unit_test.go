package acceptance_test

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func devinObservedCatalogBody(t *testing.T, present bool) []byte {
	t.Helper()
	b, e := os.ReadFile("testdata/devin-agent-catalog-observed.json")
	if e != nil {
		t.Fatal(e)
	}
	var v struct {
		Catalog    string          `json:"catalog"`
		ToolSchema json.RawMessage `json:"toolSchema"`
	}
	if json.Unmarshal(b, &v) != nil {
		t.Fatal("fixture shape")
	}
	catalog := v.Catalog
	if present {
		catalog += "\n- `acs-reviewer`: Synthetic assessment reviewer"
	}
	return devinAgentBody(catalog, string(v.ToolSchema))
}
func devinAgentBody(catalog, schema string) []byte {
	payload := devinBytes(2, []byte("Instructions\n\n"+catalog+"\n\nEnd."))
	tool := devinBytes(1, []byte("run_subagent"))
	tool = append(tool, devinBytes(3, []byte(schema))...)
	payload = append(payload, devinBytes(10, tool)...)
	frame := make([]byte, 5)
	binary.BigEndian.PutUint32(frame[1:], uint32(len(payload)))
	return append(frame, payload...)
}
func TestDevinProtocolAgentCatalogObservedBaseline(t *testing.T) {
	for _, present := range []bool{false, true} {
		b := devinObservedCatalogBody(t, present)
		if e := assertDevinAgentCatalog(b, present); e != nil {
			t.Fatal(e)
		}
		if assertDevinAgentCatalog(b, !present) == nil {
			t.Fatal("opposite state accepted")
		}
	}
}
func TestDevinProtocolAgentCatalogRefusals(t *testing.T) {
	b := devinObservedCatalogBody(t, true)
	fs, e := devinWire(b[5:])
	if e != nil {
		t.Fatal(e)
	}
	system, _ := devinOne(fs, 2, 2)
	text := string(system.data)
	text = strings.TrimSuffix(strings.TrimPrefix(text, "Instructions\n\n"), "\n\nEnd.")
	schema := `{"type":"object","properties":{"profile":{"type":"string"}}}`
	for name, catalog := range map[string]string{"heading-missing": strings.Replace(text, devinProfileCatalogHeading, "Other heading", 1), "duplicate-profile": text + "\n- `acs-reviewer`: Synthetic assessment reviewer", "echo-only": strings.Split(text, "\n- `acs-reviewer`")[0] + "\n\nEcho acs-reviewer: Synthetic assessment reviewer", "wrong-description": strings.Replace(text, devinAssessmentDescription, "different", 1), "unknown-layout": text + "\nunknown line"} {
		t.Run(name, func(t *testing.T) {
			if assertDevinAgentCatalog(devinAgentBody(catalog, schema), true) == nil {
				t.Fatal("invalid catalog accepted")
			}
		})
	}
	if assertDevinAgentCatalog(devinAgentBody(text, `{"properties":{"profile":{"type":"string","type":"object"}}}`), true) == nil {
		t.Fatal("ambiguous schema accepted")
	}
	for _, schema := range []string{`{"properties":{"profile":{"type":"string"}}}`, `{"type":"object","properties":{"profile":{"type":"string","enum":["other"]}}}`, `{"type":"object","properties":{"profile":{"type":"string","const":"other"}}}`} {
		if assertDevinAgentCatalog(devinAgentBody(text, schema), true) == nil {
			t.Fatal("unestablished constrained schema accepted")
		}
	}
	if assertDevinAgentCatalog(append(b, 0), true) == nil {
		t.Fatal("bad frame accepted")
	}
}

func TestDevinProtocolAgentCatalogSeedPair(t *testing.T) {
	for _, present := range []bool{true, false} {
		work := t.TempDir()
		if e := seedDevinAgentDefinition(work, present); e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(work, ".devin", "agents", "acs-reviewer.md")
		b, e := os.ReadFile(path)
		if present {
			if e != nil || string(b) != devinAssessmentDefinition {
				t.Fatal("project definition mismatch")
			}
			if seedDevinAgentDefinition(work, true) == nil {
				t.Fatal("existing project definition overwritten")
			}
		} else if !os.IsNotExist(e) {
			t.Fatal("negative created project definition")
		}
	}
}
