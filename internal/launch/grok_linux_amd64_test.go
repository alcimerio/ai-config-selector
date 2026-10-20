package launch

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxGrokAdmissionAndArguments(t *testing.T) {
	_, err := linuxCompileRecipe(linuxRecipeAdmission{}, linuxGrokRecipe, validatedProcessRequest{}, nil, false)
	assertLinuxUnsupported(t, err)
	if !linuxGrokArguments([]string{"--version"}, false) || !linuxGrokArguments(nil, true) {
		t.Fatal("reviewed Grok invocation rejected")
	}
	for _, arguments := range [][]string{nil, {"--trust"}, {"-p", "hello"}, {"login"}, {"--version", "--trust"}} {
		if linuxGrokArguments(arguments, false) {
			t.Fatalf("unreviewed non-interactive invocation accepted: %v", arguments)
		}
	}
	if linuxGrokArguments([]string{"--version"}, true) {
		t.Fatal("version probe accepted as interactive")
	}
	if _, err := linuxProductionKind(validatedProcessRequest{executable: "/opt/grok", arguments: []string{"--version"}}); err != nil {
		t.Fatal(err)
	}
	kind, err := linuxProductionKind(validatedProcessRequest{executable: "/opt/grok"})
	if err != nil || kind != linuxGrokRecipe {
		t.Fatalf("interactive Grok kind = %v, %v", kind, err)
	}
	if _, err := linuxProductionKind(validatedProcessRequest{executable: "/opt/grok", arguments: []string{"--trust"}}); err == nil {
		t.Fatal("unreviewed Grok arguments admitted")
	}
	kind, err = linuxProductionKind(validatedProcessRequest{executable: "/usr/bin/true"})
	if err != nil || kind != linuxCommandRecipe {
		t.Fatalf("ordinary command kind = %v, %v", kind, err)
	}
	if _, err := linuxGrokRuntime(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing Grok binary accepted")
	}
	unpinned := filepath.Join(t.TempDir(), "grok")
	if err := os.WriteFile(unpinned, []byte("not-grok"), 0o500); err != nil {
		t.Fatal(err)
	}
	if _, err := linuxGrokRuntime(unpinned); err == nil {
		t.Fatal("unlocked Grok binary accepted")
	}
}
