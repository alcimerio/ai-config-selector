package scripts

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func TestMacOSVerificationBudgetPreservesBoundedGates(t *testing.T) {
	workflow := readRepositoryFile(t, "..", ".github/workflows/macos.yml")
	// The normal and race suites run as parallel jobs. Each retains its
	// per-package deadlines and its own job budget for setup and builds.
	for job, requirements := range map[string][]string{
		"verify-unit": {
			"    name: Verify unit (macOS)\n",
			"    runs-on: macos-26\n",
			"timeout-minutes: 20",
			"gofmt -l .",
			"go vet ./...",
			"go mod verify",
			"go test -v -timeout=90s ./internal/launch",
			"go test -v -timeout=5m ./...",
			"go build -o /tmp/acs ./cmd/acs",
			"scripts/release-candidate.sh v0.5.1",
		},
		"verify-race": {
			"    name: Verify race (macOS)\n",
			"    runs-on: macos-26\n",
			"timeout-minutes: 20",
			"go test -race -timeout=10m ./...",
			"-count=20 -timeout=2m",
		},
	} {
		block := nativeRequiredWorkflowJob(t, workflow, job)
		for _, required := range requirements {
			if !strings.Contains(block, required) {
				t.Errorf("%s must preserve %q", job, required)
			}
		}
		if regexp.MustCompile(`(?m)^    if:`).MatchString(block) {
			t.Errorf("%s must not be conditionally skipped", job)
		}
	}
	for _, job := range []string{"verify-unit", "verify-race", "verify"} {
		block := nativeRequiredWorkflowJob(t, workflow, job)
		for _, forbidden := range []string{"continue-on-error:", "|| true"} {
			if strings.Contains(block, forbidden) {
				t.Errorf("%s suppresses failure with %q", job, forbidden)
			}
		}
	}
	aggregate := nativeRequiredWorkflowJob(t, workflow, "verify")
	for _, required := range []string{
		"    name: Verify (macOS)\n",
		"    needs: [verify-unit, verify-race]\n",
		"    if: ${{ always() }}\n",
		"          UNIT_RESULT: ${{ needs.verify-unit.result }}\n",
		"          RACE_RESULT: ${{ needs.verify-race.result }}\n",
	} {
		if !strings.Contains(aggregate, required) {
			t.Errorf("required Verify (macOS) check must preserve %q", required)
		}
	}
	if strings.Count(aggregate, "      - name:") != 1 || strings.Contains(aggregate, "    strategy:") {
		t.Fatal("required Verify (macOS) check must have one non-matrix gate")
	}
	if strings.Count(workflow, "name: Verify (macOS)\n") != 1 {
		t.Fatal("exactly one job may report the required Verify (macOS) context")
	}
}

func TestMacOSVerificationAggregateFailsClosed(t *testing.T) {
	workflow := readRepositoryFile(t, "..", ".github/workflows/macos.yml")
	aggregate := nativeRequiredWorkflowJob(t, workflow, "verify")
	match := regexp.MustCompile(`(?m)^        run: \|\n((?:          [^\n]*\n|\n)+)`).FindStringSubmatch(aggregate)
	if len(match) != 2 {
		t.Fatal("required Verify (macOS) shell gate is unavailable")
	}
	var script strings.Builder
	for line := range strings.SplitSeq(match[1], "\n") {
		script.WriteString(strings.TrimPrefix(line, "          ") + "\n")
	}
	results := []string{"success", "failure", "cancelled", "skipped", "", "unknown"}
	for _, unit := range results {
		for _, race := range results {
			t.Run("unit="+unit+"/race="+race, func(t *testing.T) {
				command := exec.Command("bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", script.String())
				for _, variable := range os.Environ() {
					if !strings.HasPrefix(variable, "UNIT_RESULT=") && !strings.HasPrefix(variable, "RACE_RESULT=") {
						command.Env = append(command.Env, variable)
					}
				}
				command.Env = append(command.Env, "UNIT_RESULT="+unit, "RACE_RESULT="+race)
				output, err := command.CombinedOutput()
				wantSuccess := unit == "success" && race == "success"
				if (err == nil) != wantSuccess {
					t.Fatalf("gate success = %v, want %v; output=%q", err == nil, wantSuccess, output)
				}
			})
		}
	}
}

func TestMacOSGoCachesHaveOneWriterPerFamily(t *testing.T) {
	action := readRepositoryFile(t, "..", ".github/actions/setup-go-macos/action.yml")
	for _, required := range []string{"cache: false", "actions/cache/restore@", "go-version-file: go.mod"} {
		if !strings.Contains(action, required) {
			t.Errorf("macOS Go setup omits %q", required)
		}
	}
	if strings.Contains(action, "actions/cache/save@") {
		t.Fatal("the shared macOS Go setup must never save build caches")
	}
	macos := readRepositoryFile(t, "..", ".github/workflows/macos.yml")
	for _, job := range []string{"verify-unit", "verify-race"} {
		block := nativeRequiredWorkflowJob(t, macos, job)
		if strings.Count(block, "actions/cache/save@") != 1 ||
			!strings.Contains(block, "github.event_name == 'push' && github.ref == 'refs/heads/main'") {
			t.Errorf("%s must be the single main-only writer of its cache family", job)
		}
	}
	if strings.Count(macos, "actions/cache/save@") != 2 {
		t.Fatal("only verify-unit and verify-race may save macOS Go caches")
	}
	promoted := readRepositoryFile(t, "..", ".github/workflows/promoted-artifacts.yml")
	research := readRepositoryFile(t, "..", ".github/workflows/native-transport-research.yml")
	for name, block := range map[string]string{
		"native":    nativeRequiredWorkflowJob(t, promoted, "native"),
		"seatbelt":  nativeRequiredWorkflowJob(t, macos, "seatbelt-zombie-stress"),
		"transport": nativeRequiredWorkflowJob(t, research, "transport-probes"),
	} {
		if !strings.Contains(block, "uses: ./.github/actions/setup-go-macos") ||
			strings.Contains(block, "actions/setup-go@") ||
			strings.Contains(block, "actions/cache/save@") {
			t.Errorf("%s macOS job must restore shared Go caches without writing them", name)
		}
	}
}
