package acceptance_test

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const devinAssessmentAgent = "acs-reviewer"
const devinAssessmentDescription = "Synthetic assessment reviewer"
const devinAssessmentDefinition = "---\nname: acs-reviewer\ndescription: Synthetic assessment reviewer\n---\nReturn ACS_AGENT_OK only.\n"
const devinProfileCatalogHeading = "Available subagent profiles for the `run_subagent` tool. Choose the most appropriate profile based on whether the task requires write access:"

func assertDevinAgentCatalog(body []byte, present bool) error {
	if len(body) < 5 || body[0] != 0 || int(binary.BigEndian.Uint32(body[1:5])) != len(body)-5 {
		return errors.New("agent discovery Connect framing")
	}
	fs, e := devinWire(body[5:])
	if e != nil {
		return e
	}
	system, e := devinOne(fs, 2, 2)
	if e != nil || !utf8.Valid(system.data) || len(system.data) > 65536 {
		return errors.New("unique bounded system catalog text required")
	}
	text := string(system.data)
	if strings.Count(text, devinProfileCatalogHeading) != 1 {
		return errors.New("profile catalog heading absent or ambiguous")
	}
	section := strings.SplitN(text, devinProfileCatalogHeading, 2)[1]
	if !strings.HasPrefix(section, "\n") {
		return errors.New("profile catalog layout changed")
	}
	section = strings.TrimPrefix(section, "\n")
	section = strings.SplitN(section, "\n\n", 2)[0]
	seen := map[string]bool{}
	selected := 0
	for _, line := range strings.Split(section, "\n") {
		if !strings.HasPrefix(line, "- `") {
			return errors.New("unknown profile catalog line")
		}
		parts := strings.SplitN(strings.TrimPrefix(line, "- `"), "`: ", 2)
		if len(parts) != 2 || parts[0] == "" || seen[parts[0]] {
			return errors.New("ambiguous profile catalog identity")
		}
		seen[parts[0]] = true
		if parts[0] == devinAssessmentAgent {
			selected++
			if parts[1] != devinAssessmentDescription {
				return errors.New("custom profile description differs")
			}
		}
	}
	if !seen["subagent_explore"] || !seen["subagent_general"] {
		return errors.New("baseline built-in profiles missing")
	}
	if (present && selected != 1) || (!present && selected != 0) {
		return errors.New("selected/absent profile catalog mismatch")
	}
	if !present && strings.Contains(section, devinAssessmentDescription) {
		return errors.New("absent custom description in catalog")
	}
	count := 0
	for _, f := range fs {
		if f.tag != 10 {
			continue
		}
		if f.wire != 2 {
			return errors.New("tool wire mismatch")
		}
		tool, e := devinWire(f.data)
		if e != nil {
			return e
		}
		name, e := devinOne(tool, 1, 2)
		if e != nil {
			return e
		}
		if string(name.data) != "run_subagent" {
			continue
		}
		count++
		schema, e := devinOne(tool, 3, 2)
		if e != nil {
			return e
		}
		if e = validateUniqueJSON(string(schema.data)); e != nil {
			return errors.New("subagent schema malformed or ambiguous")
		}
		var v map[string]any
		if json.Unmarshal(schema.data, &v) != nil || v["type"] != "object" {
			return errors.New("subagent schema JSON")
		}
		props, ok := v["properties"].(map[string]any)
		if !ok {
			return errors.New("subagent properties missing")
		}
		profile, ok := props["profile"].(map[string]any)
		if !ok || profile["type"] != "string" {
			return errors.New("profile selection schema changed")
		}
		for key := range profile {
			if key != "type" && key != "description" {
				return errors.New("unestablished profile schema constraint")
			}
		}
	}
	if count != 1 {
		return errors.New("unique real run_subagent declaration required")
	}
	return nil
}

func seedDevinAgentDefinition(workspace string, present bool) error {
	path := filepath.Join(workspace, ".devin", "agents", "acs-reviewer.md")
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		return errors.New("project agent fixture already present or unavailable")
	}
	if !present {
		return nil
	}
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	n, e := f.WriteString(devinAssessmentDefinition)
	ce := f.Close()
	if e != nil {
		return e
	}
	if ce != nil {
		return ce
	}
	if n != len(devinAssessmentDefinition) {
		return errors.New("short agent fixture write")
	}
	return nil
}
