package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// The run command copies its own executable as the synthetic "devin";
	// under go test that executable is the test binary.
	if filepath.Base(os.Args[0]) == "devin" {
		os.Exit(fakeDevin(os.Args[1:], os.Stdout))
	}
	os.Exit(m.Run())
}

func TestParseTimingLinesSumsRepeatedPhasesInFirstSeenOrder(t *testing.T) {
	input := strings.Join([]string{
		"noise before",
		"acs timing: session.arm                                  2.5 ms",
		"acs timing: process.probe                               10.0 ms",
		"acs timing: session.arm                                  1.5 ms",
		"Devin exited",
		"acs timing: devin.total                                100.25 ms",
	}, "\n")
	phases, order, err := ParseTimingLines(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "session.arm,process.probe,devin.total" {
		t.Fatalf("order = %v", order)
	}
	if got := phases["session.arm"]; got.Milliseconds != 4 || got.Count != 2 {
		t.Fatalf("session.arm = %+v", got)
	}
	if got := phases["devin.total"]; got.Milliseconds != 100.25 || got.Count != 1 {
		t.Fatalf("devin.total = %+v", got)
	}
}

func TestParseTimingLinesRejectsMalformedTimingLines(t *testing.T) {
	for _, line := range []string{"acs timing: phase", "acs timing: phase abc ms", "acs timing: phase -1 ms", "acs timing: phase 1 s", "acs timing: phase NaN ms"} {
		if _, _, err := ParseTimingLines(strings.NewReader(line)); err == nil {
			t.Errorf("accepted %q", line)
		}
	}
}

func TestParseTargetStart(t *testing.T) {
	if value, ok := ParseTargetStart(strings.NewReader("x\nACS_BENCH_TARGET_START 1234\n")); !ok || value != 1234 {
		t.Fatalf("got %d %v", value, ok)
	}
	if _, ok := ParseTargetStart(strings.NewReader("ACS_BENCH_TARGET_START nope\n")); ok {
		t.Fatal("accepted malformed marker")
	}
}

func TestMedianAndNearestRankPercentile(t *testing.T) {
	values := []float64{9, 1, 8, 2, 7, 3, 6, 4, 5, 10}
	if got := Median(values); got != 5.5 {
		t.Fatalf("median = %v", got)
	}
	if got := Median([]float64{3, 1, 2}); got != 2 {
		t.Fatalf("odd median = %v", got)
	}
	if got := Percentile(values, 90); got != 9 {
		t.Fatalf("p90 = %v", got)
	}
	if got := Percentile([]float64{42}, 90); got != 42 {
		t.Fatalf("single p90 = %v", got)
	}
	if values[0] != 9 {
		t.Fatal("statistics mutated their input")
	}
}

func TestSummarizeGroupsColumnsAndSkipsFailedRuns(t *testing.T) {
	runs := []Run{}
	for iteration := 1; iteration <= 10; iteration++ {
		for _, label := range []string{"compare", "primary"} {
			for _, files := range []int{20, 0} {
				runs = append(runs, Run{Label: label, Ref: label + "-ref", SkillFiles: files, Iteration: iteration,
					PhaseOrder: []string{"session.materialize", "devin.total"},
					Phases: map[string]PhaseSample{
						"session.materialize": {Milliseconds: float64(iteration + files), Count: 1},
						"devin.total":         {Milliseconds: 100, Count: 1},
						phaseWall:             {Milliseconds: 200, Count: 1},
					}})
			}
		}
	}
	runs = append(runs, Run{Label: "primary", Ref: "primary-ref", SkillFiles: 0, ExitCode: 1, Phases: map[string]PhaseSample{"session.materialize": {Milliseconds: 9999, Count: 1}}})
	summary := Summarize(runs)
	want := []Column{{"primary", "primary-ref", 0}, {"primary", "primary-ref", 20}, {"compare", "compare-ref", 0}, {"compare", "compare-ref", 20}}
	if len(summary.Columns) != len(want) {
		t.Fatalf("columns = %v", summary.Columns)
	}
	for index := range want {
		if summary.Columns[index] != want[index] {
			t.Fatalf("columns = %v, want %v", summary.Columns, want)
		}
	}
	stat := summary.Stats[want[0]]["session.materialize"]
	if stat.Median != 5.5 || stat.P90 != 9 || stat.Samples != 10 || summary.Runs[want[0]] != 10 {
		t.Fatalf("primary/0 materialize = %+v runs=%d (failed run must be excluded)", stat, summary.Runs[want[0]])
	}
	if got := summary.Stats[want[1]]["session.materialize"].Median; got != 25.5 {
		t.Fatalf("primary/20 materialize median = %v", got)
	}
	if strings.Join(summary.Phases[:4], ",") != "bench.wall,bench.start-to-target,bench.target-to-exit,session.materialize" {
		t.Fatalf("phase order = %v", summary.Phases)
	}
}

func TestRenderMarkdownEscapesRefsAndOmitsAbsentPhases(t *testing.T) {
	runs := []Run{{Label: "primary", Ref: "feat|x`<b>", SkillFiles: 0, PhaseOrder: []string{"session.arm"},
		Phases: map[string]PhaseSample{"session.arm": {Milliseconds: 3, Count: 3}, phaseWall: {Milliseconds: 50, Count: 1}}}}
	var output bytes.Buffer
	if err := RenderMarkdown(&output, Summarize(runs)); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{"feat\\|x'&lt;b&gt; · 0 Skill files median (ms)", "| `session.arm` | 3 | 3.0 | 3.0 |", "| `bench.wall` | 1 | 50.0 | 50.0 |", "Runs per column:"} {
		if !strings.Contains(text, want) {
			t.Errorf("markdown omits %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, phaseStart) {
		t.Errorf("markdown lists a phase no run reported:\n%s", text)
	}
	output.Reset()
	if err := RenderMarkdown(&output, Summarize(nil)); err != nil || !strings.Contains(output.String(), "No successful") {
		t.Fatalf("empty summary = %q, %v", output.String(), err)
	}
}

func TestWriteCSVAndReadRunsRoundTrip(t *testing.T) {
	runs := []Run{{Label: "primary", Ref: "a,b", SkillFiles: 20, Iteration: 2, PhaseOrder: []string{"x"},
		Phases: map[string]PhaseSample{"x": {Milliseconds: 1.5, Count: 2}, phaseWall: {Milliseconds: 9, Count: 1}}}}
	var csv bytes.Buffer
	if err := WriteCSV(&csv, runs); err != nil {
		t.Fatal(err)
	}
	want := "label,ref,skill_files,iteration,exit_code,phase,ms,count\nprimary,\"a,b\",20,2,0,x,1.500,2\nprimary,\"a,b\",20,2,0,bench.wall,9.000,1\n"
	if csv.String() != want {
		t.Fatalf("csv =\n%s\nwant\n%s", csv.String(), want)
	}
	var lines bytes.Buffer
	if err := json.NewEncoder(&lines).Encode(runs[0]); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadRuns(&lines)
	if err != nil || len(decoded) != 1 || decoded[0].Phases["x"].Count != 2 {
		t.Fatalf("decoded = %+v, %v", decoded, err)
	}
}

func TestParseRunOptionsValidatesInputs(t *testing.T) {
	base := []string{"--primary-acs", "/a", "--primary-ref", "main", "--out", "o.jsonl"}
	options, err := parseRunOptions(base)
	if err != nil || options.iterations != 10 || len(options.skillFiles) != 2 || len(options.targets) != 1 {
		t.Fatalf("defaults = %+v, %v", options, err)
	}
	options, err = parseRunOptions(append(append([]string(nil), base...), "--compare-acs", "/b", "--compare-ref", "v1", "--iterations", " 3 "))
	if err != nil || len(options.targets) != 2 || options.targets[1].ref != "v1" || options.iterations != 3 {
		t.Fatalf("compare = %+v, %v", options, err)
	}
	for _, extra := range [][]string{
		{"--iterations", "0"}, {"--iterations", "201"}, {"--iterations", "ten"},
		{"--skill-files", "0,0"}, {"--skill-files", "-1"}, {"--compare-acs", "/b"}, {"--warmup", "9"}, {"unexpected"},
	} {
		if _, err := parseRunOptions(append(append([]string(nil), base...), extra...)); err == nil {
			t.Errorf("accepted %v", extra)
		}
	}
	if _, err := parseRunOptions([]string{"--primary-acs", "/a"}); err == nil {
		t.Error("accepted missing required flags")
	}
}

func TestFakeDevinAnswersPreflightsAndReportsInteractiveStart(t *testing.T) {
	t.Setenv("HOME", "/synthetic/home")
	var output bytes.Buffer
	if code := fakeDevin([]string{"skills", "list", "--json"}, &output); code != 0 {
		t.Fatal(code)
	}
	var catalog []map[string]string
	if err := json.Unmarshal(output.Bytes(), &catalog); err != nil || len(catalog) != 1 || catalog[0]["base_dir"] != "/synthetic/home/.config/devin/skills/review" || catalog[0]["provider"] != "Devin" {
		t.Fatalf("catalog = %s, %v", output.String(), err)
	}
	output.Reset()
	if fakeDevin([]string{"auth", "status"}, &output) != 0 || !strings.HasPrefix(output.String(), "Logged in") {
		t.Fatalf("auth = %q", output.String())
	}
	output.Reset()
	before := time.Now().UnixNano()
	if fakeDevin(nil, &output) != 0 {
		t.Fatal("interactive failed")
	}
	if value, ok := ParseTargetStart(&output); !ok || value < before {
		t.Fatalf("interactive marker = %d %v", value, ok)
	}
}

// TestRunCommandDrivesALauncherEndToEnd replaces acs with a shell script that
// emits timing lines and runs the synthetic devin found through PATH, so the
// fixture, environment, launch, parsing and output wiring are exercised
// without a sandbox.
func TestRunCommandDrivesALauncherEndToEnd(t *testing.T) {
	directory := t.TempDir()
	acs := filepath.Join(directory, "acs")
	script := `#!/bin/sh
[ "$1 $2 $3" = "devin --profile bench" ] || exit 64
[ "$ACS_DEBUG_TIMING" = 1 ] || exit 65
[ -f "$HOME/.config/devin/skills/review/SKILL.md" ] || exit 66
[ -f "$HOME/.acs/profiles/bench.json" ] || exit 67
devin skills list --json >/dev/null || exit 68
echo "acs timing: session.arm 1.0 ms" >&2
echo "acs timing: session.arm 2.0 ms" >&2
devin
echo "acs timing: devin.total 5.0 ms" >&2
`
	if err := os.WriteFile(acs, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(directory, "runs.jsonl")
	if err := runCommand([]string{"--primary-acs", acs, "--primary-ref", "main", "--compare-acs", acs, "--compare-ref", "other", "--iterations", "2", "--skill-files", "0,3", "--out", out}); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	runs, err := ReadRuns(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 8 {
		t.Fatalf("runs = %d, want 2 iterations x 2 variants x 2 refs", len(runs))
	}
	for _, run := range runs {
		if run.ExitCode != 0 || run.Phases["session.arm"].Count != 2 || run.Phases["session.arm"].Milliseconds != 3 {
			t.Fatalf("run = %+v", run)
		}
		for _, phase := range syntheticPhases {
			if _, ok := run.Phases[phase]; !ok {
				t.Fatalf("run lacks %s: %+v", phase, run)
			}
		}
	}
	var summary bytes.Buffer
	csvPath := filepath.Join(directory, "runs.csv")
	if err := summarizeCommand([]string{"--in", out, "--csv", csvPath}, &summary); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(summary.String(), "other · 3 Skill files median (ms)") {
		t.Fatalf("summary = %s", summary.String())
	}
	if data, err := os.ReadFile(csvPath); err != nil || !strings.Contains(string(data), "compare,other,3,2,0,session.arm,3.000,2") {
		t.Fatalf("csv = %s, %v", data, err)
	}
}

func TestRunCommandReportsLauncherFailure(t *testing.T) {
	directory := t.TempDir()
	acs := filepath.Join(directory, "acs")
	if err := os.WriteFile(acs, []byte("#!/bin/sh\necho 'acs: refused' >&2\nexit 3\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	err := runCommand([]string{"--primary-acs", acs, "--primary-ref", "main", "--iterations", "1", "--warmup", "0", "--skill-files", "0", "--out", filepath.Join(directory, "runs.jsonl")})
	if err == nil || !strings.Contains(err.Error(), "acs: refused") {
		t.Fatalf("err = %v", err)
	}
}
