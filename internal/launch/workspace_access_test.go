package launch

import (
	"reflect"
	"testing"
)

func TestBubblewrapWorkspaceBindingUsesResolvedAccess(t *testing.T) {
	base := validatedProcessRequest{workspace: "/workspace", sessionDirectory: "/session", executable: "/usr/bin/tool"}
	readOnly := base
	readOnly.workspaceAccess = WorkspaceAccessReadOnly
	readWrite := base
	readWrite.workspaceAccess = WorkspaceAccessReadWrite
	if !containsArgumentTriple(bubblewrapArguments(readOnly), "--ro-bind", "/workspace", "/workspace") {
		t.Fatal("read-only plan did not compile a read-only workspace mount")
	}
	if containsArgumentTriple(bubblewrapArguments(readOnly), "--bind", "/workspace", "/workspace") {
		t.Fatal("read-only plan retained workspace write")
	}
	if !containsArgumentTriple(bubblewrapArguments(readWrite), "--bind", "/workspace", "/workspace") {
		t.Fatal("read-write plan did not compile writable workspace mount")
	}
}

func containsArgumentTriple(arguments []string, want ...string) bool {
	for index := 0; index+len(want) <= len(arguments); index++ {
		if reflect.DeepEqual(arguments[index:index+len(want)], want) {
			return true
		}
	}
	return false
}
