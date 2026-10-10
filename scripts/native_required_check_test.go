package scripts

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func TestNativeRequiredCheckWorkflowContract(t *testing.T) {
	workflow := readRepositoryFile(t, "..", ".github/workflows/promoted-artifacts.yml")
	aggregate := nativeRequiredWorkflowJob(t, workflow, "native-required")
	for _, required := range []string{
		"    name: Native darwin/arm64\n",
		"    permissions: {}\n",
		"    needs: [candidate, native]\n",
		"    if: ${{ always() }}\n",
		"        shell: bash\n",
		"          CANDIDATE_RESULT: ${{ needs.candidate.result }}\n",
		"          NATIVE_RESULT: ${{ needs.native.result }}\n",
	} {
		if !strings.Contains(aggregate, required) {
			t.Errorf("required native check must preserve %q", required)
		}
	}
	if strings.Count(aggregate, "      - name:") != 1 ||
		regexp.MustCompile(`(?m)^        if:`).MatchString(aggregate) ||
		strings.Contains(aggregate, "    strategy:") {
		t.Fatal("required native check must have one unconditional, non-matrix gate")
	}
	native := nativeRequiredWorkflowJob(t, workflow, "native")
	for _, required := range []string{
		"    name: Native ${{ matrix.target }} target ${{ matrix.codex_version }}\n",
		"    needs: candidate\n",
		"      fail-fast: false\n",
	} {
		if !strings.Contains(native, required) {
			t.Errorf("native matrix must preserve %q", required)
		}
	}
	if regexp.MustCompile(`(?m)^    if:`).MatchString(native) {
		t.Fatal("required native matrix must not conditionally skip target rows")
	}
	for _, job := range []string{"candidate", "native", "native-required"} {
		block := nativeRequiredWorkflowJob(t, workflow, job)
		for _, forbidden := range []string{"continue-on-error:", "|| true"} {
			if strings.Contains(block, forbidden) {
				t.Errorf("%s suppresses required validation with %q", job, forbidden)
			}
		}
	}
}

func TestNativeRequiredCheckFailsClosed(t *testing.T) {
	workflow := readRepositoryFile(t, "..", ".github/workflows/promoted-artifacts.yml")
	aggregate := nativeRequiredWorkflowJob(t, workflow, "native-required")
	match := regexp.MustCompile(`(?m)^        run: \|\n((?:          [^\n]*\n|\n)+)`).FindStringSubmatch(aggregate)
	if len(match) != 2 {
		t.Fatal("required native check shell gate is unavailable")
	}
	var script strings.Builder
	for line := range strings.SplitSeq(match[1], "\n") {
		script.WriteString(strings.TrimPrefix(line, "          ") + "\n")
	}
	// Execute the workflow's actual gate, rather than reproducing its decision
	// in test code. Missing and unknown results must also reject success.
	results := []string{"success", "failure", "cancelled", "skipped", "", "unknown"}
	for _, candidate := range results {
		for _, native := range results {
			name := "candidate=" + candidate + "/native=" + native
			t.Run(name, func(t *testing.T) {
				command := exec.Command("bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script.String())
				for _, variable := range os.Environ() {
					if !strings.HasPrefix(variable, "CANDIDATE_RESULT=") && !strings.HasPrefix(variable, "NATIVE_RESULT=") {
						command.Env = append(command.Env, variable)
					}
				}
				command.Env = append(command.Env, "CANDIDATE_RESULT="+candidate, "NATIVE_RESULT="+native)
				output, err := command.CombinedOutput()
				wantExit := 1
				if candidate == "success" && native == "success" {
					wantExit = 0
				}
				gotExit := 0
				if err != nil {
					exitError, ok := err.(*exec.ExitError)
					if !ok {
						t.Fatalf("could not execute gate: %v", err)
					}
					gotExit = exitError.ExitCode()
				}
				if gotExit != wantExit {
					t.Fatalf("gate exited %d, want %d; output=%q", gotExit, wantExit, output)
				}
			})
		}
	}
}

func nativeRequiredWorkflowJob(t *testing.T, workflow, job string) string {
	t.Helper()
	_, block, found := strings.Cut(workflow, "\n  "+job+":\n")
	if !found {
		t.Fatalf("workflow job %s is unavailable", job)
	}
	if next := regexp.MustCompile(`(?m)^  [a-zA-Z0-9_-]+:\n`).FindStringIndex(block); next != nil {
		block = block[:next[0]]
	}
	return block
}
