package scripts

import (
	"regexp"
	"strings"
	"testing"
)

// TestMacOSSessionBenchmarkWorkflowIsManualAndIsolated keeps the benchmark
// out of every automatic CI path: it is dispatched by hand, reads only
// repository contents, uses no secrets and never writes shared Go caches.
func TestMacOSSessionBenchmarkWorkflowIsManualAndIsolated(t *testing.T) {
	workflow := readRepositoryFile(t, "..", ".github/workflows/macos-session-benchmark.yml")
	_, triggers, found := strings.Cut(workflow, "\non:\n")
	if !found {
		t.Fatal("benchmark workflow has no trigger block")
	}
	if next := regexp.MustCompile(`(?m)^[a-z]`).FindStringIndex(triggers); next != nil {
		triggers = triggers[:next[0]]
	}
	events := regexp.MustCompile(`(?m)^  ([a-z_]+):`).FindAllStringSubmatch(triggers, -1)
	if len(events) != 1 || events[0][1] != "workflow_dispatch" {
		t.Fatalf("benchmark workflow triggers = %v, want only workflow_dispatch", events)
	}
	for _, input := range []string{"      ref:\n", "        default: main\n", "      iterations:\n", "        default: \"10\"\n", "      compare_ref:\n"} {
		if !strings.Contains(triggers, input) {
			t.Errorf("benchmark workflow omits dispatch input line %q", input)
		}
	}
	if !strings.Contains(workflow, "\npermissions:\n  contents: read\n\n") {
		t.Error("benchmark workflow must grant only contents: read")
	}
	job := nativeRequiredWorkflowJob(t, workflow, "benchmark")
	for _, required := range []string{
		"runs-on: macos-26",
		"uses: ./.github/actions/setup-go-macos",
		"persist-credentials: false",
		"go build -trimpath -o \"$bin/sessionbench\" ./tools/sessionbench",
		"--skill-files 0,20",
		">>\"$GITHUB_STEP_SUMMARY\"",
		"actions/upload-artifact@",
	} {
		if !strings.Contains(job, required) {
			t.Errorf("benchmark job omits %q", required)
		}
	}
	for _, forbidden := range []string{"secrets.", "actions/cache/save@", "actions/setup-go@", "pull_request", "schedule:", "ACS_TEST_DEVIN_BINARY", "install-devin-test-target", "install-codex-test-target"} {
		if strings.Contains(workflow, forbidden) {
			t.Errorf("benchmark workflow contains %q", forbidden)
		}
	}
	// Dispatch inputs reach shell steps only through env, never by template
	// expansion inside a run script.
	for _, block := range strings.Split(job, "\n      - name: ") {
		_, script, hasRun := strings.Cut(block, "        run: |\n")
		if hasRun && strings.Contains(script, "${{") {
			t.Errorf("run script expands a template expression directly:\n%s", block)
		}
	}
}
