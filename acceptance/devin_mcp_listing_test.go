package acceptance_test

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// validateUniqueJSON rejects ambiguous duplicate keys before typed decoding.
func validateUniqueJSON(text string) error {
	if len(text) > 65536 {
		return errors.New("listing size")
	}
	d := json.NewDecoder(strings.NewReader(text))
	tokens := 0
	var value func(int) error
	value = func(depth int) error {
		tokens++
		if depth > 16 || tokens > 2048 {
			return errors.New("listing structural cap")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				key, e := d.Token()
				if e != nil {
					return e
				}
				k, ok := key.(string)
				if !ok || keys[k] {
					return errors.New("duplicate listing key")
				}
				keys[k] = true
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return errors.New("object termination")
			}
		case '[':
			for d.More() {
				if e = value(depth + 1); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return errors.New("array termination")
			}
		default:
			return errors.New("unexpected delimiter")
		}
		return nil
	}
	if e := value(0); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return errors.New("trailing listing JSON")
	}
	return nil
}
func decodeDevinListing(text string, out any) error {
	if e := validateUniqueJSON(text); e != nil {
		return e
	}
	d := json.NewDecoder(strings.NewReader(text))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

// Shapes independently observed in pinned CLI case external-mcp-listing-z3joswc1
// as correlated role4 results, not inferred from the fixture's tools/list bytes.
func verifyDevinListing(stage int, text string) error {
	if stage == 1 {
		var result struct {
			Servers []string `json:"servers"`
		}
		if e := decodeDevinListing(text, &result); e != nil {
			return e
		}
		if len(result.Servers) != 1 || result.Servers[0] != "fixture" {
			return errors.New("selected server listing mismatch")
		}
		return nil
	}
	if stage != 2 {
		return errors.New("unknown listing stage")
	}
	var result []struct {
		Server string `json:"server_name"`
		Tools  []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Schema      struct {
				Type       string                     `json:"type"`
				Properties map[string]json.RawMessage `json:"properties"`
				Additional *bool                      `json:"additionalProperties"`
			} `json:"inputSchema"`
		} `json:"tools"`
		Resources []json.RawMessage `json:"resources"`
	}
	if e := decodeDevinListing(text, &result); e != nil {
		return e
	}
	if len(result) != 1 || result[0].Server != "fixture" || len(result[0].Tools) != 1 || result[0].Resources == nil || len(result[0].Resources) != 0 {
		return errors.New("tool server/resource list mismatch")
	}
	tool := result[0].Tools[0]
	if tool.Name != "acs_allowed_echo" || tool.Description != "Write synthetic test receipt" || tool.Schema.Type != "object" || tool.Schema.Properties == nil || len(tool.Schema.Properties) != 0 || tool.Schema.Additional == nil || *tool.Schema.Additional {
		return errors.New("allowed-only tool shape mismatch")
	}
	return nil
}
func TestDevinProtocolObservedListingShape(t *testing.T) {
	servers := `{"servers":["fixture"]}`
	tools := `[{"server_name":"fixture","tools":[{"name":"acs_allowed_echo","description":"Write synthetic test receipt","inputSchema":{"type":"object","properties":{},"additionalProperties":false}}],"resources":[]}]`
	if e := verifyDevinListing(1, servers); e != nil {
		t.Fatal(e)
	}
	if e := verifyDevinListing(2, tools); e != nil {
		t.Fatal(e)
	}
	for _, text := range []string{`{"servers":["fixture","ambient-poison"]}`, `{"servers":["fixture","fixture"]}`, `{"servers":[],"servers":["fixture"]}`, `{"error":"failure","servers":["fixture"]}`, `{"servers":["fixture"]} {}`} {
		if verifyDevinListing(1, text) == nil {
			t.Fatal("accepted ambiguous/ambient listing")
		}
	}
	for _, text := range []string{strings.Replace(tools, "acs_allowed_echo", "acs_blocked_echo", 1), strings.Replace(tools, `"tools":[`, `"tools":[{"name":"acs_blocked_echo"},`, 1), strings.Replace(tools, `"resources":[]`, `"resources":null`, 1), strings.Replace(tools, `"additionalProperties":false`, `"additionalProperties":false,"additionalProperties":false`, 1)} {
		if verifyDevinListing(2, text) == nil {
			t.Fatal("accepted disabled/ambiguous tool listing")
		}
	}
}
