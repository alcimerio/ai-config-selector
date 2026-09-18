package codexauthresource_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func nativeMCPInventoryFunction(body, serverID, toolName string) (string, error) {
	entry, err := nativeMCPInventoryFunctionEntry(body, serverID, toolName)
	if err != nil {
		return "", err
	}
	name, ok := entry["name"].(string)
	if !ok || name == "" {
		return "", errors.New("Responses MCP inventory function has no name")
	}
	return name, nil
}

func nativeMCPInventoryFunctionEntry(body, serverID, toolName string) (map[string]any, error) {
	entry, found, err := nativeMCPInventoryLookup(body, serverID, toolName)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("Responses request does not contain MCP inventory function %q", "mcp__"+serverID+"__"+toolName)
	}
	return entry, nil
}

func nativeMCPInventoryContains(body, serverID, toolName string) (bool, error) {
	_, found, err := nativeMCPInventoryLookup(body, serverID, toolName)
	return found, err
}

func nativeMCPInventoryLookup(body, serverID, toolName string) (map[string]any, bool, error) {
	var request map[string]any
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		return nil, false, errors.New("Responses request is invalid JSON")
	}
	legacyTools, hasLegacyTools := request["tools"]
	hasLegacyTools = hasLegacyTools && legacyTools != nil
	tools, legacyOK := legacyTools.([]any)
	if hasLegacyTools && !legacyOK && legacyTools != nil {
		return nil, false, errors.New("Responses legacy tools inventory is malformed")
	}
	var foundEnvelope bool
	if input, inputOK := request["input"].([]any); inputOK {
		for _, raw := range input {
			item, itemOK := raw.(map[string]any)
			if !itemOK || item["type"] != "additional_tools" {
				continue
			}
			if item["role"] != "developer" {
				return nil, false, errors.New("Responses AdditionalTools inventory has an invalid role")
			}
			if foundEnvelope {
				return nil, false, errors.New("Responses request contains duplicate AdditionalTools inventories")
			}
			candidate, candidateOK := item["tools"].([]any)
			if !candidateOK {
				return nil, false, errors.New("Responses AdditionalTools inventory is malformed")
			}
			tools, foundEnvelope = candidate, true
		}
	}
	if foundEnvelope && hasLegacyTools {
		return nil, false, errors.New("Responses request mixes legacy and AdditionalTools inventories")
	}
	if !foundEnvelope && !legacyOK {
		return nil, false, errors.New("Responses request has no tools inventory")
	}
	wantName := "mcp__" + serverID + "__" + toolName
	var found map[string]any
	count := 0
	namespaceCount := 0
	var visit func([]any) error
	visit = func(items []any) error {
		for _, raw := range items {
			entry, ok := raw.(map[string]any)
			if !ok {
				return errors.New("Responses tools inventory contains a malformed entry")
			}
			if entry["type"] == "namespace" {
				if entry["name"] != "functions" {
					continue
				}
				namespaceCount++
				if namespaceCount > 1 {
					return errors.New("Responses request contains duplicate default function namespaces")
				}
				nested, nestedOK := entry["tools"].([]any)
				if !nestedOK {
					return errors.New("Responses function namespace inventory is malformed")
				}
				if err := visit(nested); err != nil {
					return err
				}
				continue
			}
			if entry["type"] != "function" || entry["name"] != wantName {
				continue
			}
			found = entry
			count++
		}
		return nil
	}
	if err := visit(tools); err != nil {
		return nil, false, err
	}
	if count > 1 {
		return nil, false, fmt.Errorf("Responses request contains %d duplicate exact MCP inventory entries for %q", count, wantName)
	}
	return found, count == 1, nil
}

func nativeMCPFunctionSchema(entry map[string]any, requiredProperties ...string) error {
	parameters, ok := entry["parameters"].(map[string]any)
	if !ok {
		return errors.New("Responses MCP function has no parameter schema")
	}
	properties, ok := parameters["properties"].(map[string]any)
	if !ok {
		return errors.New("Responses MCP function has no property schema")
	}
	for _, property := range requiredProperties {
		if _, exists := properties[property]; !exists {
			return fmt.Errorf("Responses MCP function schema is missing property %q", property)
		}
	}
	return nil
}

func TestNativeMCPInventorySeparatesIdentityFromAllowedSchema(t *testing.T) {
	allowedBody := `{"metadata":"fixture","tools":[{"type":"function","name":"mcp__fixture__allowed","parameters":{"type":"object","properties":{"value":{"type":"string"},"input":{"type":"string"}}}}]}`
	allowed, err := nativeMCPInventoryFunctionEntry(allowedBody, "fixture", "allowed")
	if err != nil {
		t.Fatalf("exact allowed inventory entry was not identified: %v", err)
	}
	if err := nativeMCPFunctionSchema(allowed, "value", "input"); err != nil {
		t.Fatalf("allowed schema was not validated: %v", err)
	}
	liteBody := `{"input":[{"type":"message","role":"user","content":[]},{"type":"additional_tools","role":"developer","tools":[{"type":"function","name":"mcp__fixture__allowed","parameters":{"type":"object","properties":{"value":{"type":"string"},"input":{"type":"string"}}}},{"type":"function","name":"mcp__fixture__blocked","parameters":{"type":"object","properties":{"value":{"type":"string"}}}}]}],"tools":null}`
	liteAllowed, err := nativeMCPInventoryFunctionEntry(liteBody, "fixture", "allowed")
	if err != nil {
		t.Fatalf("Responses Lite AdditionalTools entry was not identified: %v", err)
	}
	if err := nativeMCPFunctionSchema(liteAllowed, "value", "input"); err != nil {
		t.Fatalf("Responses Lite allowed schema was not validated: %v", err)
	}
	if present, err := nativeMCPInventoryContains(liteBody, "fixture", "blocked"); err != nil || !present {
		t.Fatalf("Responses Lite blocked-tool lookup = (%t, %v), want present for filter assertion", present, err)
	}
	namespacedBody := `{"tools":[{"type":"namespace","name":"functions","tools":[{"type":"function","name":"mcp__fixture__allowed","parameters":{"type":"object","properties":{"value":{},"input":{}}}},{"type":"function","name":"mcp__fixture__blocked","parameters":{"type":"object","properties":{"value":{}}}}]},{"type":"namespace","name":"decoy","tools":[{"type":"function","name":"mcp__fixture__allowed","parameters":{}}]}]}`
	if _, err := nativeMCPInventoryFunctionEntry(namespacedBody, "fixture", "allowed"); err != nil {
		t.Fatalf("default namespace entry was not identified: %v", err)
	}
	if present, err := nativeMCPInventoryContains(namespacedBody, "fixture", "blocked"); err != nil || !present {
		t.Fatalf("namespaced blocked lookup = (%t, %v), want present", present, err)
	}
	if present, err := nativeMCPInventoryContains(allowedBody, "fixture", "blocked"); err != nil || present {
		t.Fatalf("absent blocked tool lookup = (%t, %v), want absent", present, err)
	}

	blockedPresent := `{"tools":[{"type":"function","name":"mcp__fixture__blocked","parameters":{"type":"object","properties":{"value":{"type":"string"}}}}]}`
	entry, err := nativeMCPInventoryFunctionEntry(blockedPresent, "fixture", "blocked")
	if err != nil {
		t.Fatalf("present blocked inventory entry was not identified: %v", err)
	}
	if err := nativeMCPFunctionSchema(entry, "value", "input"); err == nil {
		t.Fatal("value-only blocked schema unexpectedly satisfied the allowed-tool schema")
	}
	if present, err := nativeMCPInventoryContains(blockedPresent, "fixture", "blocked"); err != nil || !present {
		t.Fatalf("disabled tool presence lookup = (%t, %v), want present", present, err)
	}

	for name, body := range map[string]string{
		"duplicate blocked entries":         `{"tools":[{"type":"function","name":"mcp__fixture__blocked","parameters":{"properties":{"value":{}}}},{"type":"function","name":"mcp__fixture__blocked","parameters":{"properties":{"value":{}}}}]}`,
		"server identity outside inventory": `{"metadata":"fixture","tools":[{"type":"function","name":"mcp__other__blocked","parameters":{"properties":{"value":{}}}}]}`,
		"substring tool name":               `{"tools":[{"type":"function","name":"mcp__fixture__blocked_extra","parameters":{"properties":{"value":{}}}}]}`,
		"malformed default namespace":       `{"tools":[{"type":"namespace","name":"functions","tools":{}}]}`,
		"duplicate namespace function":      `{"tools":[{"type":"namespace","name":"functions","tools":[{"type":"function","name":"mcp__fixture__blocked","parameters":{}}]},{"type":"function","name":"mcp__fixture__blocked","parameters":{}}]}`,
		"mixed legacy and lite inventory":   `{"tools":[{"type":"function","name":"mcp__fixture__blocked","parameters":{}}],"input":[{"type":"additional_tools","role":"developer","tools":[{"type":"function","name":"mcp__fixture__blocked","parameters":{}}]}]}`,
		"additional tools wrong role":       `{"input":[{"type":"additional_tools","role":"user","tools":[]}]}`,
		"additional tools malformed":        `{"input":[{"type":"additional_tools","role":"developer","tools":{}}]}`,
		"duplicate default namespaces":      `{"tools":[{"type":"namespace","name":"functions","tools":[]},{"type":"namespace","name":"functions","tools":[]}]}`,
		"nested metadata decoy":             `{"metadata":{"tools":[{"type":"function","name":"mcp__fixture__blocked"}]},"tools":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := nativeMCPInventoryFunctionEntry(body, "fixture", "blocked"); err == nil {
				t.Fatal("non-unique or non-exact inventory identity was accepted")
			}
			if name == "duplicate blocked entries" {
				if present, err := nativeMCPInventoryContains(body, "fixture", "blocked"); err == nil || present {
					t.Fatalf("duplicate disabled-tool inventory was treated as absent: present=%t err=%v", present, err)
				}
			}
		})
	}
}
