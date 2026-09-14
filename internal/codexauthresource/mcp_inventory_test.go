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
	tools, ok := request["tools"].([]any)
	if !ok {
		return nil, false, errors.New("Responses request has no tools inventory")
	}
	wantName := "mcp__" + serverID + "__" + toolName
	var found map[string]any
	count := 0
	for _, raw := range tools {
		entry, ok := raw.(map[string]any)
		if !ok {
			return nil, false, errors.New("Responses tools inventory contains a malformed entry")
		}
		if entry["type"] != "function" || entry["name"] != wantName {
			continue
		}
		found = entry
		count++
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
