package codexauthresource_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
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

// The grammar is pinned to Codex 0.149.1. Description text is not capability proof.
const nativeMCPExecGrammar = `start: pragma_source | plain_source
pragma_source: PRAGMA_LINE NEWLINE SOURCE
plain_source: SOURCE

PRAGMA_LINE: /[ \t]*\/\/ @exec:[^\r\n]*/
NEWLINE: /\r?\n/
SOURCE: /[\s\S]+/`

func nativeMCPHasExec(body string) (bool, error) {
	// Reuse the structural inventory validation (including duplicate/mixed forms).
	if _, err := nativeMCPInventoryHasType(body, "custom"); err != nil {
		return false, err
	}
	var request map[string]any
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		return false, errors.New("invalid exec inventory")
	}
	tools, _ := request["tools"].([]any)
	if input, ok := request["input"].([]any); ok {
		for _, raw := range input {
			if item, ok := raw.(map[string]any); ok && item["type"] == "additional_tools" {
				tools, _ = item["tools"].([]any)
			}
		}
	}
	count, namespaces := 0, 0
	for _, raw := range tools {
		entry, _ := raw.(map[string]any)
		if entry["type"] != "namespace" || entry["name"] != "functions" {
			continue
		}
		namespaces++
		members, ok := entry["tools"].([]any)
		if !ok {
			return false, errors.New("malformed functions namespace")
		}
		for _, raw := range members {
			tool, ok := raw.(map[string]any)
			if !ok {
				return false, errors.New("malformed functions member")
			}
			if tool["name"] != "exec" {
				continue
			}
			format, ok := tool["format"].(map[string]any)
			definition, _ := format["definition"].(string)
			if tool["type"] != "custom" || !ok || format["type"] != "grammar" || format["syntax"] != "lark" || strings.TrimSpace(definition) != nativeMCPExecGrammar {
				return false, errors.New("exec declaration does not match pinned grammar")
			}
			count++
		}
	}
	if namespaces > 1 || count > 1 {
		return false, errors.New("duplicate functions exec inventory")
	}
	return count == 1, nil
}

// Only these four known fixture identifiers leave the target. ALL_TOOLS has no schema.
func nativeMCPDiscoverySource() string {
	return `// @exec: {"yield_time_ms":10000,"max_output_tokens":1024}
text(Object.fromEntries(["fixture__allowed","mcp__fixture__allowed","fixture__blocked","mcp__fixture__blocked"].map(name => [name, ALL_TOOLS.filter(tool => tool.name === name).length])));`
}

func nativeMCPInvocationSource(namespace, name, arguments string) string {
	return "// @exec: {\"yield_time_ms\":10000,\"max_output_tokens\":1024}\ntext(await tools." + namespace + "__" + name + "(" + arguments + "));"
}

func nativeMCPInputItem(body, callID, kind string) (map[string]any, error) {
	var request map[string]any
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		return nil, errors.New("invalid tool request JSON")
	}
	input, ok := request["input"].([]any)
	if !ok {
		return nil, errors.New("tool request lacks input array")
	}
	var found map[string]any
	for _, raw := range input {
		item, ok := raw.(map[string]any)
		if !ok || item["type"] != kind || item["call_id"] != callID {
			continue
		}
		if found != nil {
			return nil, errors.New("duplicate pending tool item")
		}
		found = item
	}
	if found == nil {
		return nil, errors.New("pending tool item missing")
	}
	return found, nil
}

func nativeMCPRequireCustomCall(body, callID string) (string, error) {
	item, err := nativeMCPInputItem(body, callID, "custom_tool_call")
	if err != nil {
		return "", err
	}
	source, ok := item["input"].(string)
	if item["namespace"] != "functions" || item["name"] != "exec" || !ok || source != nativeMCPDiscoverySource() {
		return "", errors.New("custom discovery call mismatch")
	}
	return source, nil
}

func nativeMCPRequireObservedCustomIdentity(body, callID, namespace, name string) error {
	item, err := nativeMCPInputItem(body, callID, "custom_tool_call")
	if err != nil {
		return err
	}
	source, ok := item["input"].(string)
	if item["namespace"] != namespace || item["name"] != name || !ok || source == "" {
		return errors.New("custom invocation identity mismatch")
	}
	return nil
}

func nativeMCPRequireInvocation(body, callID, source string) error {
	if err := nativeMCPRequireObservedCustomIdentity(body, callID, "functions", "exec"); err != nil {
		return err
	}
	item, _ := nativeMCPInputItem(body, callID, "custom_tool_call")
	if item["input"] != source {
		return errors.New("custom invocation source mismatch")
	}
	return nil
}

func nativeMCPRequireCustomOutput(body, callID string) error {
	_, err := nativeMCPRequireCustomOutputText(body, callID)
	return err
}

// nativeMCPExecFailureCategory inspects only the bounded first text part from
// the correlated output. It never returns the target's path, error, or payload.
func nativeMCPExecFailureCategory(first string) string {
	if len(first) > 16384 {
		return "exec-output-invalid"
	}
	if strings.HasPrefix(first, "failed to spawn code-mode host ") {
		if strings.HasSuffix(first, ": host executable was not found") || strings.HasSuffix(first, " (os error 2)") {
			return "exec-host-missing"
		}
		return "exec-host-spawn-failed"
	}
	if first == "code-mode host is disabled" {
		return "exec-host-disabled"
	}
	line, _, _ := strings.Cut(first, "\n")
	switch {
	case strings.HasPrefix(line, "Script running with cell ID "):
		return "exec-running"
	case line == "Script failed":
		return "exec-failed"
	case line == "Script terminated":
		return "exec-terminated"
	default:
		return "exec-output-invalid"
	}
}

// Code mode prepends a status text item, not an envelope success boolean. This
// bounded fixture deliberately fails a yielded script; it never treats running
// output as completion. Native evidence will determine whether waits are needed.
func nativeMCPRequireCustomOutputText(body, callID string) (string, error) {
	item, err := nativeMCPInputItem(body, callID, "custom_tool_call_output")
	if err != nil {
		return "", err
	}
	var parts []string
	switch value := item["output"].(type) {
	case string:
		parts = []string{value}
	case []any:
		if len(value) == 0 || len(value) > 16 {
			return "", errors.New("invalid exec content count")
		}
		for _, raw := range value {
			part, ok := raw.(map[string]any)
			if !ok || part["type"] != "input_text" {
				return "", errors.New("unexpected exec content type")
			}
			text, ok := part["text"].(string)
			if !ok {
				return "", errors.New("invalid exec text")
			}
			parts = append(parts, text)
		}
	default:
		return "", errors.New("invalid exec output")
	}
	length := 0
	for _, part := range parts {
		length += len(part)
	}
	if length > 16384 {
		return "", errors.New("exec output exceeds fixture bound")
	}
	// The first text item owns the complete header. Payload cannot supply it.
	first := parts[0]
	lines := strings.SplitN(first, "\n", 4)
	if len(lines) != 4 || lines[0] != "Script completed" || lines[2] != "Output:" {
		return "", errors.New(nativeMCPExecFailureCategory(first))
	}
	if !regexp.MustCompile(`^Wall time [0-9]+\.[0-9] seconds$`).MatchString(lines[1]) {
		return "", errors.New("invalid exec wall time header")
	}
	payload := lines[3]
	for _, part := range parts[1:] {
		payload += part
	}
	if strings.TrimSpace(payload) == "" {
		return "", errors.New("exec completed without fixture result")
	}
	return payload, nil
}

// Decode JSON with duplicate-key rejection, including nested MCP result objects.
func nativeMCPUniqueJSON(payload string) (any, error) {
	decoder := json.NewDecoder(strings.NewReader(payload))
	decoder.UseNumber()
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		if depth > 16 {
			return nil, errors.New("fixture JSON nesting exceeds bound")
		}
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch token {
		case json.Delim('{'):
			object := map[string]any{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				name, ok := key.(string)
				if !ok {
					return nil, errors.New("invalid JSON key")
				}
				if _, exists := object[name]; exists {
					return nil, errors.New("duplicate JSON key")
				}
				value, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				object[name] = value
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("invalid JSON object")
			}
			return object, nil
		case json.Delim('['):
			array := []any{}
			for decoder.More() {
				value, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("invalid JSON array")
			}
			return array, nil
		default:
			return token, nil
		}
	}
	value, err := read(0)
	if err != nil {
		return nil, errors.New("invalid fixture JSON")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing fixture JSON")
	}
	return value, nil
}

func nativeMCPCustomDiscoveryIdentity(body, callID, serverID, toolName, blocked string) (string, string, error) {
	payload, err := nativeMCPRequireCustomOutputText(body, callID)
	if err != nil {
		return "", "", err
	}
	value, err := nativeMCPUniqueJSON(payload)
	if err != nil {
		return "", "", err
	}
	counts, ok := value.(map[string]any)
	if !ok || len(counts) != 4 {
		return "", "", errors.New("discovery requires exactly four counts")
	}
	keys := []string{serverID + "__" + toolName, "mcp__" + serverID + "__" + toolName, serverID + "__" + blocked, "mcp__" + serverID + "__" + blocked}
	numbers := [4]int64{}
	for index, key := range keys {
		number, ok := counts[key].(json.Number)
		if !ok {
			return "", "", errors.New("discovery count missing or nonnumeric")
		}
		count, err := number.Int64()
		if err != nil || count < 0 || count > 1 {
			return "", "", errors.New("discovery count not zero or one")
		}
		numbers[index] = count
	}
	if numbers[0]+numbers[1] != 1 || numbers[2] != 0 || numbers[3] != 0 {
		return "", "", errors.New("discovery is ambiguous or exposes disabled tool")
	}
	namespace := serverID
	if numbers[1] == 1 {
		namespace = "mcp__" + serverID
	}
	return namespace, toolName, nil
}

func nativeMCPCustomMCPResult(body, callID string) (string, error) {
	payload, err := nativeMCPRequireCustomOutputText(body, callID)
	if err != nil {
		return "", err
	}
	value, err := nativeMCPUniqueJSON(payload)
	if err != nil {
		return "", err
	}
	result, ok := value.(map[string]any)
	if !ok {
		return "", errors.New("MCP result is not an object")
	}
	if flag, present := result["isError"]; present {
		failed, ok := flag.(bool)
		if !ok || failed {
			return "", errors.New("MCP call reported an error")
		}
	}
	content, ok := result["content"].([]any)
	if !ok || len(content) != 1 {
		return "", errors.New("MCP fixture result content mismatch")
	}
	item, ok := content[0].(map[string]any)
	if !ok || item["type"] != "text" {
		return "", errors.New("MCP fixture result is not text")
	}
	text, ok := item["text"].(string)
	if !ok || !regexp.MustCompile(`^mcp-fixture-call-ok mcp-secret-environment-ok descendant-pid:[0-9]+$`).MatchString(text) {
		return "", errors.New("MCP fixture result missing exact receipts")
	}
	return text, nil
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

func nativeMCPTestOutput(value any, history ...any) string {
	input := append(history, map[string]any{"type": "custom_tool_call_output", "call_id": "pending", "output": value})
	b, _ := json.Marshal(map[string]any{"input": input})
	return string(b)
}
func nativeMCPTestParts(status, payload string) []any {
	return []any{map[string]any{"type": "input_text", "text": status + "\nWall time 0.1 seconds\nOutput:\n"}, map[string]any{"type": "input_text", "text": payload}}
}

const nativeMCPTestCounts = `{"mcp__fixture__allowed":1,"fixture__allowed":0,"mcp__fixture__blocked":0,"fixture__blocked":0}`

func TestNativeMCPCodeModeDiscoveryValidation(t *testing.T) {
	for _, tc := range []struct {
		name, payload, status string
		valid                 bool
		namespace             string
	}{
		{"prefixed", nativeMCPTestCounts, "Script completed", true, "mcp__fixture"},
		{"unprefixed", `{"mcp__fixture__allowed":0,"fixture__allowed":1,"mcp__fixture__blocked":0,"fixture__blocked":0}`, "Script completed", true, "fixture"},
		{"unprefixed_blocked", strings.Replace(nativeMCPTestCounts, `"fixture__blocked":0`, `"fixture__blocked":1`, 1), "Script completed", false, ""},
		{"omitted_keys", `{"mcp__fixture__allowed":1,"mcp__fixture__blocked":0}`, "Script completed", false, ""},
		{"unknown_key", strings.TrimSuffix(nativeMCPTestCounts, "}") + `,"unexpected":0}`, "Script completed", false, ""},
		{"fractional_unprefixed_blocked", strings.Replace(nativeMCPTestCounts, `"fixture__blocked":0`, `"fixture__blocked":0.5`, 1), "Script completed", false, ""},
		{"wrong_type_unprefixed_allowed", strings.Replace(nativeMCPTestCounts, `"fixture__allowed":0`, `"fixture__allowed":"0"`, 1), "Script completed", false, ""},
		{"duplicate_json_key", strings.TrimSuffix(nativeMCPTestCounts, "}") + `,"fixture__blocked":1}`, "Script completed", false, ""},
		{"running", nativeMCPTestCounts, "Script running with cell ID g2:1", false, ""},
		{"failed", nativeMCPTestCounts, "Script failed", false, ""},
		{"terminated", nativeMCPTestCounts, "Script terminated", false, ""},
		{"missing_header", nativeMCPTestCounts, "", false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ns, name, err := nativeMCPCustomDiscoveryIdentity(nativeMCPTestOutput(nativeMCPTestParts(tc.status, tc.payload)), "pending", "fixture", "allowed", "blocked")
			if tc.valid {
				if err != nil || ns != tc.namespace || name != "allowed" {
					t.Fatalf("valid identity rejected: %s/%s %v", ns, name, err)
				}
			} else if err == nil {
				t.Fatalf("invalid discovery accepted: %s/%s", ns, name)
			}
		})
	}
}
func TestNativeMCPCodeModeMalformedContent(t *testing.T) {
	parts := append(nativeMCPTestParts("Script completed", nativeMCPTestCounts), map[string]any{"type": "input_image", "image_url": "synthetic"})
	if _, _, err := nativeMCPCustomDiscoveryIdentity(nativeMCPTestOutput(parts), "pending", "fixture", "allowed", "blocked"); err == nil {
		t.Fatal("unexpected content ignored")
	}
}
func TestNativeMCPCodeModeHistoricalAndDuplicateCorrelation(t *testing.T) {
	old := map[string]any{"type": "custom_tool_call_output", "call_id": "older", "output": "older irrelevant"}
	valid := nativeMCPTestOutput(nativeMCPTestParts("Script completed", nativeMCPTestCounts), old, map[string]any{"type": "message", "role": "user", "content": "fixture"})
	if _, _, err := nativeMCPCustomDiscoveryIdentity(valid, "pending", "fixture", "allowed", "blocked"); err != nil {
		t.Fatalf("legitimate history rejected: %v", err)
	}
	duplicate := map[string]any{"type": "custom_tool_call_output", "call_id": "pending", "output": nativeMCPTestParts("Script completed", nativeMCPTestCounts)}
	if _, _, err := nativeMCPCustomDiscoveryIdentity(nativeMCPTestOutput(nativeMCPTestParts("Script completed", nativeMCPTestCounts), duplicate), "pending", "fixture", "allowed", "blocked"); err == nil {
		t.Fatal("duplicate pending accepted")
	}
}
func TestNativeMCPCodeModeOutputEnvelopeNotCompletion(t *testing.T) {
	for _, value := range []any{nil, 3, nativeMCPTestParts("Script failed", ""), nativeMCPTestParts("Script running with cell ID g2:1", "")} {
		if err := nativeMCPRequireCustomOutput(nativeMCPTestOutput(value), "pending"); err == nil {
			t.Errorf("incomplete or malformed output accepted: %#v", value)
		}
	}
}

func nativeMCPTestExecInventory(namespace, kind, syntax, grammar string, copies int, lite bool) string {
	members := []any{}
	for i := 0; i < copies; i++ {
		members = append(members, map[string]any{"type": kind, "name": "exec", "format": map[string]any{"type": "grammar", "syntax": syntax, "definition": grammar}})
	}
	tools := []any{map[string]any{"type": "namespace", "name": namespace, "tools": members}}
	request := map[string]any{"tools": tools}
	if lite {
		request = map[string]any{"tools": nil, "input": []any{map[string]any{"type": "additional_tools", "role": "developer", "tools": tools}}}
	}
	b, _ := json.Marshal(request)
	return string(b)
}

func TestNativeMCPCodeModeAdvertisedExec(t *testing.T) {
	for _, lite := range []bool{false, true} {
		body := nativeMCPTestExecInventory("functions", "custom", "lark", "\n"+nativeMCPExecGrammar+"\n", 1, lite)
		if found, err := nativeMCPHasExec(body); err != nil || !found {
			t.Fatalf("valid exec rejected: %v", err)
		}
	}
	for _, tc := range []struct {
		name, namespace, kind, syntax, grammar string
		copies                                 int
	}{
		{"wrong namespace", "other", "custom", "lark", nativeMCPExecGrammar, 1},
		{"wrong type", "functions", "function", "lark", nativeMCPExecGrammar, 1},
		{"wrong syntax", "functions", "custom", "regex", nativeMCPExecGrammar, 1},
		{"wrong grammar", "functions", "custom", "lark", "start: BAD", 1},
		{"duplicate exec", "functions", "custom", "lark", nativeMCPExecGrammar, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if found, err := nativeMCPHasExec(nativeMCPTestExecInventory(tc.namespace, tc.kind, tc.syntax, tc.grammar, tc.copies, false)); err == nil && found {
				t.Fatal("unadvertised/ambiguous exec accepted")
			}
		})
	}
	body := nativeMCPTestExecInventory("functions", "custom", "lark", nativeMCPExecGrammar, 1, false)
	var request map[string]any
	_ = json.Unmarshal([]byte(body), &request)
	tools := request["tools"].([]any)
	request["tools"] = append(tools, tools[0])
	b, _ := json.Marshal(request)
	if found, err := nativeMCPHasExec(string(b)); err == nil || found {
		t.Fatal("duplicate functions namespace accepted")
	}
	request["tools"] = tools
	request["input"] = []any{map[string]any{"type": "additional_tools", "role": "developer", "tools": tools}}
	b, _ = json.Marshal(request)
	if found, err := nativeMCPHasExec(string(b)); err == nil || found {
		t.Fatal("mixed inventories accepted")
	}
}

func TestNativeMCPCodeModeExactEcho(t *testing.T) {
	for _, tc := range []struct {
		callID, source string
		discovery      bool
	}{
		{"discover", nativeMCPDiscoverySource(), true},
		{"invoke", nativeMCPInvocationSource("fixture", "allowed", `{"value":"v","input":"i"}`), false},
	} {
		check := func(body string) error {
			if tc.discovery {
				_, err := nativeMCPRequireCustomCall(body, tc.callID)
				return err
			}
			return nativeMCPRequireInvocation(body, tc.callID, tc.source)
		}
		call := map[string]any{"type": "custom_tool_call", "namespace": "functions", "name": "exec", "call_id": tc.callID, "input": tc.source}
		encode := func(items ...any) string { b, _ := json.Marshal(map[string]any{"input": items}); return string(b) }
		old := map[string]any{"type": "custom_tool_call", "namespace": "functions", "name": "exec", "call_id": "old", "input": "old"}
		if err := check(encode(old, call)); err != nil {
			t.Fatalf("valid history rejected: %v", err)
		}
		if err := check(encode(call, call)); err == nil {
			t.Fatal("duplicate pending call accepted")
		}
		for key, wrong := range map[string]string{"type": "function_call", "namespace": "fixture", "name": "allowed", "call_id": "other", "input": tc.source + "\ntext('changed');"} {
			original := call[key]
			call[key] = wrong
			if err := check(encode(call)); err == nil {
				t.Errorf("changed %s accepted", key)
			}
			call[key] = original
		}
	}
}

func TestNativeMCPCodeModeResult(t *testing.T) {
	const text = "mcp-fixture-call-ok mcp-secret-environment-ok descendant-pid:4242"
	const payload = `{"content":[{"type":"text","text":"` + text + `"}]}`
	for _, output := range []any{nativeMCPTestParts("Script completed", payload), "Script completed\nWall time 0.1 seconds\nOutput:\n" + payload} {
		got, err := nativeMCPCustomMCPResult(nativeMCPTestOutput(output), "pending")
		if err != nil || got != text {
			t.Fatalf("real MCP result rejected: %q %v", got, err)
		}
	}
	for _, bad := range []string{
		`{"isError":true,"content":[{"type":"text","text":"` + text + `"}]}`,
		`{"isError":"false","content":[{"type":"text","text":"` + text + `"}]}`,
		`{"content":[],"structuredContent":{"text":"` + text + `"}}`,
		`{"content":[{"type":"image","text":"` + text + `"}]}`,
		`{"content":[{"type":"text","text":"mcp-fixture-call-ok"}]}`,
		`{"content":[{"type":"text","text":"wrong"},{"type":"text","text":"` + text + `"}]}`,
		payload + payload,
		strings.Replace(payload, `"content":`, `"content":[],"content":`, 1),
	} {
		if _, err := nativeMCPCustomMCPResult(nativeMCPTestOutput(nativeMCPTestParts("Script completed", bad)), "pending"); err == nil {
			t.Errorf("bad MCP result accepted: %s", bad)
		}
	}
}

func TestNativeMCPCodeModeOutputBoundaries(t *testing.T) {
	for _, output := range []any{
		[]any{map[string]any{"type": "input_text", "text": "Script completed\nWall time 0.1 seconds\n"}, map[string]any{"type": "input_text", "text": "Output:\n" + nativeMCPTestCounts}},
		[]any{map[string]any{"type": "input_text", "text": 1}},
		"prefix Script completed\nWall time 0.1 seconds\nOutput:\n" + nativeMCPTestCounts,
		"Script completed\nWall time invalid seconds\nOutput:\n" + nativeMCPTestCounts,
		"Script completed\nWall time 0.1 seconds\nOutput:\n" + strings.Repeat("x", 17000),
	} {
		if _, err := nativeMCPRequireCustomOutputText(nativeMCPTestOutput(output), "pending"); err == nil {
			t.Fatal("malformed/oversized output accepted")
		}
	}
	for _, payload := range []string{nativeMCPTestCounts + " trailing", "prefix " + nativeMCPTestCounts, nativeMCPTestCounts + nativeMCPTestCounts, strings.TrimSuffix(nativeMCPTestCounts, "}")} {
		if _, _, err := nativeMCPCustomDiscoveryIdentity(nativeMCPTestOutput(nativeMCPTestParts("Script completed", payload)), "pending", "fixture", "allowed", "blocked"); err == nil {
			t.Fatal("nonexact JSON payload accepted")
		}
	}
	body := nativeMCPTestOutput(nativeMCPTestParts("Script completed", nativeMCPTestCounts))
	if _, _, err := nativeMCPCustomDiscoveryIdentity(strings.Replace(body, "custom_tool_call_output", "function_call_output", 1), "pending", "fixture", "allowed", "blocked"); err == nil {
		t.Fatal("wrong result type accepted")
	}
}

func TestNativeMCPExecFailureDiagnosticsAreFixedAndCorrelated(t *testing.T) {
	for _, tc := range []struct{ output, category string }{
		{"failed to spawn code-mode host /private/secret-token/codex-code-mode-host: No such file or directory (os error 2)", "exec-host-missing"},
		{"failed to spawn code-mode host /private/secret-token/codex-code-mode-host: host executable was not found", "exec-host-missing"},
		{"failed to spawn code-mode host /private/secret-token/codex-code-mode-host: Permission denied (os error 13)", "exec-host-spawn-failed"},
		{"code-mode host is disabled", "exec-host-disabled"},
		{"Script running with cell ID secret-token\nWall time 1.0 seconds\nOutput:\n", "exec-running"},
		{"Script failed\nWall time 0.0 seconds\nOutput:\nsecret-token", "exec-failed"},
		{"Script terminated\nWall time 0.0 seconds\nOutput:\nsecret-token", "exec-terminated"},
		{"prefix failed to spawn code-mode host secret-token (os error 2)", "exec-output-invalid"},
		{"Code Mode is unavailable because secret-token", "exec-output-invalid"},
	} {
		for _, output := range []any{tc.output, []any{map[string]any{"type": "input_text", "text": tc.output}}} {
			body := nativeMCPTestOutput(output, map[string]any{"type": "custom_tool_call_output", "call_id": "old", "output": "Script failed\nsecret-token"})
			_, err := nativeMCPRequireCustomOutputText(body, "pending")
			if err == nil || err.Error() != tc.category {
				t.Fatalf("category=%v want=%s", err, tc.category)
			}
			if strings.Contains(err.Error(), "secret-token") || strings.Contains(err.Error(), "/private") {
				t.Fatal("diagnostic leaked payload")
			}
		}
	}
	// A success payload mentioning an error is never classified as a host failure.
	payload := "failed to spawn code-mode host secret-token (os error 2)"
	if got, err := nativeMCPRequireCustomOutputText(nativeMCPTestOutput(nativeMCPTestParts("Script completed", payload)), "pending"); err != nil || got != payload {
		t.Fatal("classifier searched successful payload")
	}
}
