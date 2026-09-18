package codexauthresource_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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

func nativeMCPExactNamespaceFunctionEntry(body, serverID, toolName string) (map[string]any, error) {
	_, entry, err := nativeMCPExactNamespaceFunction(body, serverID, toolName)
	return entry, err
}

func nativeMCPExactNamespaceFunction(body, serverID, toolName string) (string, map[string]any, error) {
	var request map[string]any
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		return "", nil, errors.New("Responses request is invalid JSON")
	}
	var inventories [][]any
	if tools, ok := request["tools"].([]any); ok {
		inventories = append(inventories, tools)
	}
	if input, ok := request["input"].([]any); ok {
		for _, raw := range input {
			item, ok := raw.(map[string]any)
			if !ok || item["type"] != "additional_tools" || item["role"] != "developer" {
				continue
			}
			tools, ok := item["tools"].([]any)
			if !ok {
				return "", nil, errors.New("Responses AdditionalTools inventory is malformed")
			}
			inventories = append(inventories, tools)
		}
	}
	allowedNamespaces := map[string]bool{"mcp__" + serverID: true, serverID: true}
	var found map[string]any
	foundNamespace := ""
	count := 0
	for _, inventory := range inventories {
		for _, raw := range inventory {
			entry, ok := raw.(map[string]any)
			namespace, _ := entry["name"].(string)
			if !ok || entry["type"] != "namespace" || !allowedNamespaces[namespace] {
				continue
			}
			nested, ok := entry["tools"].([]any)
			if !ok {
				return "", nil, errors.New("MCP namespace inventory is malformed")
			}
			for _, nestedRaw := range nested {
				function, ok := nestedRaw.(map[string]any)
				if !ok || function["type"] != "function" || function["name"] != toolName {
					continue
				}
				found = function
				foundNamespace = namespace
				count++
			}
		}
	}
	if count != 1 {
		return "", nil, fmt.Errorf("Responses request contains %d exact MCP namespace functions, want one", count)
	}
	return foundNamespace, found, nil
}

func nativeMCPInventoryContains(body, serverID, toolName string) (bool, error) {
	_, found, err := nativeMCPInventoryLookup(body, serverID, toolName)
	return found, err
}

func nativeMCPInventoryHasType(body, wantType string) (bool, error) {
	var request map[string]any
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		return false, errors.New("Responses request is invalid JSON")
	}
	legacyValue, legacyPresent := request["tools"]
	legacy, legacyOK := legacyValue.([]any)
	if legacyPresent && legacyValue != nil && !legacyOK {
		return false, errors.New("Responses legacy tools inventory is malformed")
	}
	var inventories [][]any
	if legacyOK {
		inventories = append(inventories, legacy)
	}
	foundAdditional := false
	if input, ok := request["input"].([]any); ok {
		for _, raw := range input {
			item, ok := raw.(map[string]any)
			if !ok || item["type"] != "additional_tools" {
				continue
			}
			if item["role"] != "developer" {
				return false, errors.New("Responses AdditionalTools inventory has an invalid role")
			}
			if foundAdditional || (legacyPresent && legacyValue != nil) {
				return false, errors.New("Responses request has duplicate or mixed tools inventories")
			}
			tools, ok := item["tools"].([]any)
			if !ok {
				return false, errors.New("Responses AdditionalTools inventory is malformed")
			}
			inventories = append(inventories, tools)
			foundAdditional = true
		}
	}
	count := 0
	var visit func([]any) error
	visit = func(items []any) error {
		for _, raw := range items {
			entry, ok := raw.(map[string]any)
			if !ok {
				return errors.New("Responses tools inventory contains a malformed entry")
			}
			if entry["type"] == wantType {
				if wantType == "tool_search" && entry["execution"] != "client" {
					return errors.New("tool search inventory entry is not client execution")
				}
				count++
			}
			if entry["type"] == "namespace" {
				if _, ok := entry["tools"].([]any); !ok {
					return errors.New("Responses namespace inventory is malformed")
				}
			}
		}
		return nil
	}
	for _, inventory := range inventories {
		if err := visit(inventory); err != nil {
			return false, err
		}
	}
	if count > 1 {
		return false, errors.New("Responses request contains duplicate tool search inventory entries")
	}
	return count == 1, nil
}

func nativeMCPToolSearchCall(body string) (string, string, int, error) {
	var request map[string]any
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		return "", "", 0, errors.New("Responses request is invalid JSON")
	}
	input, ok := request["input"].([]any)
	if !ok {
		return "", "", 0, errors.New("tool search call request has no input array")
	}
	var callID, query string
	limit := 0
	count := 0
	for _, raw := range input {
		item, ok := raw.(map[string]any)
		if !ok || item["type"] != "tool_search_call" {
			continue
		}
		count++
		if item["execution"] != "client" {
			return "", "", 0, errors.New("tool search call is not client execution")
		}
		callID, ok = item["call_id"].(string)
		if !ok || callID == "" {
			return "", "", 0, errors.New("tool search call has no call_id")
		}
		arguments, ok := item["arguments"].(map[string]any)
		if !ok {
			return "", "", 0, errors.New("tool search call arguments are not an object")
		}
		query, ok = arguments["query"].(string)
		if !ok || strings.TrimSpace(query) == "" {
			return "", "", 0, errors.New("tool search call query is invalid")
		}
		limitNumber, ok := arguments["limit"].(float64)
		if !ok || limitNumber <= 0 || limitNumber != float64(int(limitNumber)) {
			return "", "", 0, errors.New("tool search call limit is invalid")
		}
		limit = int(limitNumber)
	}
	if count != 1 {
		return "", "", 0, fmt.Errorf("tool search call count=%d, want one", count)
	}
	return callID, query, limit, nil
}

func nativeMCPRequireToolSearchCall(body, wantCallID, wantQuery string, wantLimit int) error {
	callID, query, limit, err := nativeMCPToolSearchCall(body)
	if err != nil || callID != wantCallID || query != wantQuery || limit != wantLimit {
		return errors.New("tool search call mismatch")
	}
	return nil
}

func nativeMCPToolSearchOutput(body, callID, serverID, allowedTool, disabledTool string) error {
	var request map[string]any
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		return errors.New("Responses request is invalid JSON")
	}
	input, ok := request["input"].([]any)
	if !ok {
		return errors.New("tool search output request has no input array")
	}
	var output map[string]any
	for _, raw := range input {
		item, ok := raw.(map[string]any)
		if ok && item["type"] == "tool_search_output" {
			if output != nil {
				return errors.New("duplicate tool search outputs")
			}
			output = item
		}
	}
	if output == nil || output["execution"] != "client" || output["call_id"] != callID || output["status"] != "completed" {
		return errors.New("tool search output lifecycle is invalid")
	}
	tools, ok := output["tools"].([]any)
	if !ok {
		return errors.New("tool search output tools are malformed")
	}
	encoded, err := json.Marshal(map[string]any{"tools": tools})
	if err != nil {
		return errors.New("tool search output could not be inspected")
	}
	allowed, err := nativeMCPExactNamespaceFunctionEntry(string(encoded), serverID, allowedTool)
	if err != nil {
		return fmt.Errorf("discovered allowed MCP tool: %w", err)
	}
	if err := nativeMCPFunctionSchema(allowed, "value", "input"); err != nil {
		return fmt.Errorf("discovered allowed MCP schema: %w", err)
	}
	present, err := nativeMCPInventoryContains(string(encoded), serverID, disabledTool)
	if err != nil {
		return fmt.Errorf("inspect discovered disabled MCP tool: %w", err)
	}
	if present {
		return errors.New("disabled MCP tool appeared in tool search output")
	}
	return nil
}

func nativeMCPToolSearchOutputNamespace(body, callID, serverID, allowedTool string) (string, error) {
	var request map[string]any
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		return "", errors.New("Responses request is invalid JSON")
	}
	input, ok := request["input"].([]any)
	if !ok {
		return "", errors.New("tool search output request has no input array")
	}
	for _, raw := range input {
		item, ok := raw.(map[string]any)
		if !ok || item["type"] != "tool_search_output" || item["call_id"] != callID {
			continue
		}
		tools, ok := item["tools"].([]any)
		if !ok {
			return "", errors.New("tool search output tools are malformed")
		}
		encoded, err := json.Marshal(map[string]any{"tools": tools})
		if err != nil {
			return "", errors.New("tool search output could not be inspected")
		}
		namespace, _, err := nativeMCPExactNamespaceFunction(string(encoded), serverID, allowedTool)
		return namespace, err
	}
	return "", errors.New("tool search output is missing")
}

func nativeMCPFunctionCallOutputEnvelope(body, callID string) error {
	var request map[string]any
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		return errors.New("Responses request is invalid JSON")
	}
	input, ok := request["input"].([]any)
	if !ok {
		return errors.New("function output request has no input array")
	}
	count := 0
	for _, raw := range input {
		item, ok := raw.(map[string]any)
		if !ok || item["type"] != "function_call_output" {
			continue
		}
		count++
		if item["call_id"] != callID {
			return errors.New("function output call_id does not match")
		}
	}
	if count != 1 {
		return fmt.Errorf("function output count=%d, want one", count)
	}
	return nil
}

// nativeMCPInventoryStructure returns only bounded structural facts needed to
// diagnose a target request. It deliberately does not serialize arbitrary JSON
// keys, values, descriptions, paths, or arguments.
func nativeMCPInventoryStructure(body, serverID, toolName string) string {
	var request map[string]any
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		return "json-invalid"
	}
	toolsValue, toolsPresent := request["tools"]
	tools, toolsOK := toolsValue.([]any)
	inputValue, inputPresent := request["input"]
	input, inputOK := inputValue.([]any)
	additional := make([][]any, 0, 1)
	if inputOK {
		for _, raw := range input {
			item, ok := raw.(map[string]any)
			if !ok || item["type"] != "additional_tools" || item["role"] != "developer" {
				continue
			}
			if candidate, ok := item["tools"].([]any); ok {
				additional = append(additional, candidate)
			}
		}
	}
	functionCount, namespaceCount, toolSearchCount, deferredCount := 0, 0, 0, 0
	allowedPresent, blockedPresent := false, false
	mcpAllowedPresent, mcpBlockedPresent := false, false
	mcpNamespacePresent := false
	namespaceCounts := map[string]int{"functions": 0, "fixture": 0, "mcp__fixture": 0, "other": 0}
	namespaceAllowed := map[string]bool{"functions": false, "fixture": false, "mcp__fixture": false, "other": false}
	namespaceBlocked := map[string]bool{"functions": false, "fixture": false, "mcp__fixture": false, "other": false}
	knownOther := map[string]bool{"shell_command": false, "apply_patch": false, "view_image": false, "exec_command": false, "tool_search": false, "code_mode": false, "unified_exec": false}
	knownNamespaces := map[string]bool{"collaboration": false, "clock": false, "web": false, "image_gen": false}
	customExec, waitDeclared := false, false
	wantAllowed := "mcp__" + serverID + "__" + toolName
	wantBlocked := "mcp__" + serverID + "__" + "blocked"
	wantNamespace := "mcp__" + serverID
	var visit func([]any, string)
	visit = func(items []any, namespace string) {
		for _, raw := range items {
			entry, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			switch entry["type"] {
			case "function":
				functionCount++
				name, _ := entry["name"].(string)
				allowedPresent = allowedPresent || name == wantAllowed
				blockedPresent = blockedPresent || name == wantBlocked
				if namespace == wantNamespace {
					mcpAllowedPresent = mcpAllowedPresent || name == toolName
					mcpBlockedPresent = mcpBlockedPresent || name == "blocked"
				}
				waitDeclared = waitDeclared || namespace == "functions" && name == "wait"
				if deferred, ok := entry["defer_loading"].(bool); ok && deferred {
					deferredCount++
				}
				class := namespace
				if _, ok := namespaceCounts[class]; !ok {
					class = "other"
				}
				namespaceAllowed[class] = namespaceAllowed[class] || name == toolName || name == wantAllowed
				namespaceBlocked[class] = namespaceBlocked[class] || name == "blocked" || name == wantBlocked
				if class == "other" {
					if _, ok := knownOther[name]; ok {
						knownOther[name] = true
					}
				}
			case "custom":
				name, _ := entry["name"].(string)
				customExec = customExec || namespace == "functions" && name == "exec"
				if deferred, ok := entry["defer_loading"].(bool); ok && deferred {
					deferredCount++
				}
			case "namespace":
				namespaceCount++
				nestedNamespace, _ := entry["name"].(string)
				if _, known := knownNamespaces[nestedNamespace]; known {
					knownNamespaces[nestedNamespace] = true
				}
				class := nestedNamespace
				if _, ok := namespaceCounts[class]; !ok {
					class = "other"
				}
				namespaceCounts[class]++
				mcpNamespacePresent = mcpNamespacePresent || nestedNamespace == wantNamespace
				if nested, ok := entry["tools"].([]any); ok {
					visit(nested, class)
				}
			case "tool_search":
				toolSearchCount++
			}
		}
	}
	if toolsOK {
		visit(tools, "")
	}
	for _, inventory := range additional {
		visit(inventory, "")
	}
	legacyState := "absent"
	if toolsPresent {
		legacyState = "malformed"
		if toolsOK {
			legacyState = "array"
		} else if toolsValue == nil {
			legacyState = "null"
		}
	}
	inputState := "absent"
	if inputPresent {
		inputState = "malformed"
		if inputOK {
			inputState = "array"
		}
	}
	modelClass := "absent"
	if model, ok := request["model"].(string); ok {
		modelClass = "other"
		for _, allowed := range []string{"gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna"} {
			if model == allowed {
				modelClass = allowed
			}
		}
	}
	return fmt.Sprintf("model=%s legacy=%s input=%s additional-developer=%d functions=%d namespaces=%d tool-search=%d deferred=%d custom-exec=%t wait=%t legacy-allowed=%t legacy-blocked=%t mcp-namespace=%t mcp-allowed=%t mcp-blocked=%t ns-functions=%d/%t/%t ns-fixture=%d/%t/%t ns-mcp-fixture=%d/%t/%t ns-other=%d/%t/%t known-ns=collaboration:%t,clock:%t,web:%t,image_gen:%t known-other=shell:%t,patch:%t,view:%t,exec:%t,search:%t,code:%t,unified:%t", modelClass, legacyState, inputState, len(additional), functionCount, namespaceCount, toolSearchCount, deferredCount, customExec, waitDeclared, allowedPresent, blockedPresent, mcpNamespacePresent, mcpAllowedPresent, mcpBlockedPresent, namespaceCounts["functions"], namespaceAllowed["functions"], namespaceBlocked["functions"], namespaceCounts["fixture"], namespaceAllowed["fixture"], namespaceBlocked["fixture"], namespaceCounts["mcp__fixture"], namespaceAllowed["mcp__fixture"], namespaceBlocked["mcp__fixture"], namespaceCounts["other"], namespaceAllowed["other"], namespaceBlocked["other"], knownNamespaces["collaboration"], knownNamespaces["clock"], knownNamespaces["web"], knownNamespaces["image_gen"], knownOther["shell_command"], knownOther["apply_patch"], knownOther["view_image"], knownOther["exec_command"], knownOther["tool_search"], knownOther["code_mode"], knownOther["unified_exec"])
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
	wantNamespace := "mcp__" + serverID
	allowedNamespaces := map[string]bool{wantNamespace: true, serverID: true}
	var found map[string]any
	count := 0
	namespaceCount := 0
	namespaceVisits := map[string]int{}
	var visit func([]any, string) error
	visit = func(items []any, namespace string) error {
		for _, raw := range items {
			entry, ok := raw.(map[string]any)
			if !ok {
				return errors.New("Responses tools inventory contains a malformed entry")
			}
			if entry["type"] == "namespace" {
				nestedNamespace, _ := entry["name"].(string)
				if nestedNamespace != "functions" && !allowedNamespaces[nestedNamespace] {
					continue
				}
				namespaceCount++
				namespaceVisits[nestedNamespace]++
				if namespaceVisits[nestedNamespace] > 1 {
					return errors.New("Responses request contains duplicate default function namespaces")
				}
				nested, nestedOK := entry["tools"].([]any)
				if !nestedOK {
					return errors.New("Responses function namespace inventory is malformed")
				}
				if err := visit(nested, nestedNamespace); err != nil {
					return err
				}
				continue
			}
			name, _ := entry["name"].(string)
			matchesLegacy := (namespace == "" || namespace == "functions") && name == wantName
			matchesMCP := allowedNamespaces[namespace] && name == toolName
			if entry["type"] != "function" || (!matchesLegacy && !matchesMCP) {
				continue
			}
			found = entry
			count++
		}
		return nil
	}
	if err := visit(tools, ""); err != nil {
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
	customNamespaceBody := `{"tools":[{"type":"namespace","name":"functions","tools":[{"type":"function","name":"mcp__fixture__other","parameters":{"type":"object","properties":{"value":{},"input":{}}}}]},{"type":"namespace","name":"mcp__fixture","tools":[{"type":"function","name":"allowed","defer_loading":true,"parameters":{"type":"object","properties":{"value":{},"input":{}}}},{"type":"function","name":"blocked","parameters":{"type":"object","properties":{"value":{}}}}]}]}`
	customAllowed, err := nativeMCPInventoryFunctionEntry(customNamespaceBody, "fixture", "allowed")
	if err != nil {
		t.Fatalf("custom MCP namespace entry was not identified: %v", err)
	}
	if err := nativeMCPFunctionSchema(customAllowed, "value", "input"); err != nil {
		t.Fatalf("custom MCP namespace schema was not validated: %v", err)
	}
	if present, err := nativeMCPInventoryContains(customNamespaceBody, "fixture", "blocked"); err != nil || !present {
		t.Fatalf("custom namespace blocked lookup = (%t, %v), want present", present, err)
	}
	unprefixedBody := `{"tools":[{"type":"namespace","name":"fixture","tools":[{"type":"function","name":"allowed","parameters":{"type":"object","properties":{"value":{},"input":{}}}},{"type":"function","name":"blocked","parameters":{"type":"object","properties":{"value":{}}}}]}]}`
	if present, err := nativeMCPInventoryContains(unprefixedBody, "fixture", "blocked"); err != nil || !present {
		t.Fatalf("unprefixed namespace blocked lookup = (%t, %v), want present", present, err)
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
		"duplicate blocked entries":                        `{"tools":[{"type":"function","name":"mcp__fixture__blocked","parameters":{"properties":{"value":{}}}},{"type":"function","name":"mcp__fixture__blocked","parameters":{"properties":{"value":{}}}}]}`,
		"server identity outside inventory":                `{"metadata":"fixture","tools":[{"type":"function","name":"mcp__other__blocked","parameters":{"properties":{"value":{}}}}]}`,
		"substring tool name":                              `{"tools":[{"type":"function","name":"mcp__fixture__blocked_extra","parameters":{"properties":{"value":{}}}}]}`,
		"malformed default namespace":                      `{"tools":[{"type":"namespace","name":"functions","tools":{}}]}`,
		"duplicate namespace function":                     `{"tools":[{"type":"namespace","name":"functions","tools":[{"type":"function","name":"mcp__fixture__blocked","parameters":{}}]},{"type":"function","name":"mcp__fixture__blocked","parameters":{}}]}`,
		"mixed legacy and lite inventory":                  `{"tools":[{"type":"function","name":"mcp__fixture__blocked","parameters":{}}],"input":[{"type":"additional_tools","role":"developer","tools":[{"type":"function","name":"mcp__fixture__blocked","parameters":{}}]}]}`,
		"additional tools wrong role":                      `{"input":[{"type":"additional_tools","role":"user","tools":[]}]}`,
		"additional tools malformed":                       `{"input":[{"type":"additional_tools","role":"developer","tools":{}}]}`,
		"duplicate default namespaces":                     `{"tools":[{"type":"namespace","name":"functions","tools":[]},{"type":"namespace","name":"functions","tools":[]}]}`,
		"duplicate unprefixed MCP namespaces":              `{"tools":[{"type":"namespace","name":"fixture","tools":[{"type":"function","name":"blocked","parameters":{}}]},{"type":"namespace","name":"fixture","tools":[{"type":"function","name":"blocked","parameters":{}}]}]}`,
		"ambiguous prefixed and unprefixed MCP namespaces": `{"tools":[{"type":"namespace","name":"fixture","tools":[{"type":"function","name":"blocked","parameters":{}}]},{"type":"namespace","name":"mcp__fixture","tools":[{"type":"function","name":"blocked","parameters":{}}]}]}`,
		"nested metadata decoy":                            `{"metadata":{"tools":[{"type":"function","name":"mcp__fixture__blocked"}]},"tools":[]}`,
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

func TestNativeMCPDeferredSearchProtocolShapes(t *testing.T) {
	callBody := `{"input":[{"type":"tool_search_call","call_id":"acs-search-1","execution":"client","arguments":{"query":"fixture allowed blocked","limit":8}}]}`
	if err := nativeMCPRequireToolSearchCall(callBody, "acs-search-1", "fixture allowed blocked", 8); err != nil {
		t.Fatalf("tool search call rejected: %v", err)
	}
	outputBody := `{"input":[{"type":"tool_search_output","call_id":"acs-search-1","status":"completed","execution":"client","tools":[{"type":"namespace","name":"mcp__fixture","tools":[{"type":"function","name":"allowed","defer_loading":true,"parameters":{"type":"object","properties":{"value":{},"input":{}}}}]}]}]}`
	if err := nativeMCPToolSearchOutput(outputBody, "acs-search-1", "fixture", "allowed", "blocked"); err != nil {
		t.Fatalf("tool search output rejected: %v", err)
	}
	unprefixedOutput := `{"input":[{"type":"tool_search_output","call_id":"acs-search-1","status":"completed","execution":"client","tools":[{"type":"namespace","name":"fixture","tools":[{"type":"function","name":"allowed","parameters":{"type":"object","properties":{"value":{},"input":{}}}},{"type":"function","name":"blocked","parameters":{"type":"object","properties":{"value":{}}}}]}]}]}`
	if err := nativeMCPToolSearchOutput(unprefixedOutput, "acs-search-1", "fixture", "allowed", "blocked"); err == nil {
		t.Fatal("unprefixed disabled tool appeared to be absent from deferred output")
	}
	if err := nativeMCPFunctionCallOutputEnvelope(`{"input":[{"type":"function_call_output","call_id":"acs-call-1","output":"fixture-complete"}]}`, "acs-call-1"); err != nil {
		t.Fatalf("function output envelope rejected: %v", err)
	}
}

func TestNativeMCPDeferredGatesRejectIdentityAndLifecycleDecoys(t *testing.T) {
	legacy := `{"tools":[{"type":"function","name":"mcp__fixture__allowed","parameters":{"type":"object","properties":{"value":{},"input":{}}}}]}`
	if _, err := nativeMCPExactNamespaceFunctionEntry(legacy, "fixture", "allowed"); err == nil {
		t.Fatal("legacy flattened identity authorized a real MCP invocation")
	}
	for name, body := range map[string]string{
		"nested search":    `{"tools":[{"type":"namespace","name":"functions","tools":[{"type":"tool_search","execution":"client"}]}]}`,
		"server search":    `{"tools":[{"type":"tool_search","execution":"server"}]}`,
		"duplicate search": `{"tools":[{"type":"tool_search","execution":"client"},{"type":"tool_search","execution":"client"}]}`,
		"mixed inventory":  `{"tools":[],"input":[{"type":"additional_tools","role":"developer","tools":[{"type":"tool_search","execution":"client"}]}]}`,
		"malformed search": `{"tools":[{"type":"tool_search","execution":"client","parameters":{}}] ,"input":[{"type":"additional_tools","role":"developer","tools":{}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			found, err := nativeMCPInventoryHasType(body, "tool_search")
			if name == "server search" || name == "malformed search" {
				if err == nil || found {
					t.Fatalf("server-only search result=(%t,%v), want rejection", found, err)
				}
				return
			}
			if err == nil && found {
				t.Fatal("search decoy authorized deferred discovery")
			}
		})
	}
	for name, body := range map[string]string{
		"changed call id": `{"input":[{"type":"tool_search_call","call_id":"other","execution":"client","arguments":{"query":"fixture allowed blocked","limit":8}}]}`,
		"changed query":   `{"input":[{"type":"tool_search_call","call_id":"acs-search-1","execution":"client","arguments":{"query":"other","limit":8}}]}`,
		"changed limit":   `{"input":[{"type":"tool_search_call","call_id":"acs-search-1","execution":"client","arguments":{"query":"fixture allowed blocked","limit":7}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if !json.Valid([]byte(body)) {
				t.Fatal("semantic negative fixture is not valid JSON")
			}
			if err := nativeMCPRequireToolSearchCall(body, "acs-search-1", "fixture allowed blocked", 8); err == nil {
				t.Fatal("changed echoed search arguments were accepted")
			}
		})
	}
	validOutput := `{"input":[{"type":"tool_search_output","call_id":"acs-search-1","status":"completed","execution":"client","tools":[{"type":"namespace","name":"mcp__fixture","tools":[{"type":"function","name":"allowed","parameters":{"type":"object","properties":{"value":{},"input":{}}}}]}]}]}`
	for name, body := range map[string]string{
		"changed call id":           strings.Replace(validOutput, "acs-search-1", "other", 1),
		"incomplete status":         strings.Replace(validOutput, "completed", "in_progress", 1),
		"server execution":          strings.Replace(validOutput, "\"execution\":\"client\"", "\"execution\":\"server\"", 1),
		"missing allowed":           strings.Replace(validOutput, `{"type":"function","name":"allowed","parameters":{"type":"object","properties":{"value":{},"input":{}}}}`, `{"type":"function","name":"other","parameters":{}}`, 1),
		"disabled alternate schema": strings.Replace(validOutput, `{"type":"function","name":"allowed","parameters":{"type":"object","properties":{"value":{},"input":{}}}}`, `{"type":"function","name":"allowed","parameters":{"type":"object","properties":{"value":{},"input":{}}}},{"type":"function","name":"blocked","parameters":{"type":"object","properties":{"value":{}}}}`, 1),
		"deferred legacy namespace": strings.Replace(validOutput, `{"type":"namespace","name":"mcp__fixture","tools":[{"type":"function","name":"allowed","parameters":{"type":"object","properties":{"value":{},"input":{}}}}]}`, `{"type":"namespace","name":"functions","tools":[{"type":"function","name":"mcp__fixture__allowed","parameters":{"type":"object","properties":{"value":{},"input":{}}}}]}`, 1),
		"duplicate search output":   `{"input":[{"type":"tool_search_output","call_id":"acs-search-1","status":"completed","execution":"client","tools":[]},{"type":"tool_search_output","call_id":"acs-search-1","status":"completed","execution":"client","tools":[]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if !json.Valid([]byte(body)) {
				t.Fatal("semantic negative fixture is not valid JSON")
			}
			if err := nativeMCPToolSearchOutput(body, "acs-search-1", "fixture", "allowed", "blocked"); err == nil {
				t.Fatal("invalid deferred search output was accepted")
			}
		})
	}
}

func TestNativeMCPInventoryStructureIsBoundedAndClassifiesDiscovery(t *testing.T) {
	body := `{"input":[{"type":"additional_tools","role":"developer","tools":[{"type":"tool_search","execution":"server","description":"secret description","parameters":{}},{"type":"namespace","name":"functions","tools":[{"type":"function","name":"mcp__fixture__blocked","defer_loading":true},{"type":"function","name":"mcp__fixture__other"}]}]}],"tools":null,"metadata":{"mcp__fixture__allowed":"private value"}}`
	want := "model=absent legacy=null input=array additional-developer=1 functions=2 namespaces=1 tool-search=1 deferred=1 custom-exec=false wait=false legacy-allowed=false legacy-blocked=true mcp-namespace=false mcp-allowed=false mcp-blocked=false ns-functions=1/false/true ns-fixture=0/false/false ns-mcp-fixture=0/false/false ns-other=0/false/false known-ns=collaboration:false,clock:false,web:false,image_gen:false known-other=shell:false,patch:false,view:false,exec:false,search:false,code:false,unified:false"
	if got := nativeMCPInventoryStructure(body, "fixture", "allowed"); got != want {
		t.Fatalf("bounded inventory structure=%q, want %q", got, want)
	}
	codeMode := `{"model":"gpt-5.6-sol","input":[{"type":"additional_tools","role":"developer","tools":[{"type":"namespace","name":"functions","tools":[{"type":"custom","name":"exec"},{"type":"function","name":"wait"},{"type":"function","name":"shell_command"}]}]}]}`
	wantCodeMode := "model=gpt-5.6-sol legacy=absent input=array additional-developer=1 functions=2 namespaces=1 tool-search=0 deferred=0 custom-exec=true wait=true legacy-allowed=false legacy-blocked=false mcp-namespace=false mcp-allowed=false mcp-blocked=false ns-functions=1/false/false ns-fixture=0/false/false ns-mcp-fixture=0/false/false ns-other=0/false/false known-ns=collaboration:false,clock:false,web:false,image_gen:false known-other=shell:false,patch:false,view:false,exec:false,search:false,code:false,unified:false"
	if got := nativeMCPInventoryStructure(codeMode, "fixture", "allowed"); got != wantCodeMode {
		t.Fatalf("code-mode inventory structure=%q, want %q", got, wantCodeMode)
	}
	otherModel := strings.Replace(codeMode, "gpt-5.6-sol", "gpt-unknown", 1)
	if got := nativeMCPInventoryStructure(otherModel, "fixture", "allowed"); !strings.HasPrefix(got, "model=other ") {
		t.Fatalf("unallowlisted model classification=%q, want model=other", got)
	}
	knownNamespace := `{"input":[{"type":"additional_tools","role":"developer","tools":[{"type":"namespace","name":"collaboration","tools":[{"type":"function","name":"spawn_agent"}]},{"type":"namespace","name":"mystery","tools":[{"type":"custom","name":"exec"}]}]}]}`
	if got := nativeMCPInventoryStructure(knownNamespace, "fixture", "allowed"); !strings.Contains(got, "known-ns=collaboration:true,clock:false,web:false,image_gen:false") || !strings.Contains(got, "custom-exec=false") {
		t.Fatalf("namespace identity classification=%q", got)
	}
}
