package acceptance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func writeDevinNativeProfile(home, inputPath string) error {
	// Production ACS resolves these references; the test does not write a Devin
	// MCP config directly or launch the server outside the production launcher.
	const doc = `{"version":3,"name":"devin-native-mcp","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-write"}},"executables":{"version":1,"selection":{"entries":[{"id":"mcp-server","reference":{"kind":"workspace-relative","path":"native-mcp-server"}}]}},"paths":{"version":1,"selection":{"entries":[{"id":"mcp-input","access":"read-only","type":"file","reference":{"kind":"workspace-relative","path":"native-mcp-input.txt"}}]}},"environment":{"version":1,"selection":{"entries":[{"id":"argument","destination":"PROFILE_MCP_ARGUMENT","scope":"attached-process-tree","source":{"kind":"host-environment","name":"ACS_NATIVE_MCP_ARGUMENT"},"required":true,"classification":"non-secret"},{"id":"secret","destination":"PROFILE_MCP_SECRET","scope":"attached-process-tree","source":{"kind":"secret-reference","provider":"host-environment","reference":"ACS_NATIVE_MCP_SECRET"},"required":true,"classification":"secret"}]}},"mcp":{"version":1,"selection":{"servers":[{"id":"fixture","transport":"stdio","executableRef":"mcp-server","arguments":[{"kind":"environment","ref":"argument"},{"kind":"path","ref":"mcp-input"}],"inputRefs":["mcp-input"],"environmentRefs":["argument","secret"],"disabledTools":["acs_blocked_echo"]}]}}},"overlays":{}}`
	document := strings.Replace(doc, `"kind":"workspace-relative","path":"native-mcp-input.txt"`, `"kind":"local-absolute","path":`+strconv.Quote(inputPath), 1)
	var shape any
	if e := json.Unmarshal([]byte(document), &shape); e != nil {
		return e
	}
	dir := filepath.Join(home, ".acs", "profiles")
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(dir, "devin-native-mcp.json"), []byte(document), 0600)
}
