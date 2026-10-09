package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Synthetic phases measured by the harness itself rather than reported by
// ACS_DEBUG_TIMING. They are listed first in the summary.
const (
	phaseWall  = "bench.wall"
	phaseStart = "bench.start-to-target"
	phaseExit  = "bench.target-to-exit"
)

var syntheticPhases = []string{phaseWall, phaseStart, phaseExit}

// PhaseSample is the total duration of one named phase within one run. A
// phase that runs more than once per launch (for example session.arm or
// process.probe) is summed and its occurrences counted.
type PhaseSample struct {
	Milliseconds float64 `json:"ms"`
	Count        int     `json:"count"`
}

// Run is one measured acs launch.
type Run struct {
	Label      string                 `json:"label"`
	Ref        string                 `json:"ref"`
	SkillFiles int                    `json:"skill_files"`
	Iteration  int                    `json:"iteration"`
	ExitCode   int                    `json:"exit_code"`
	PhaseOrder []string               `json:"phase_order"`
	Phases     map[string]PhaseSample `json:"phases"`
}

// ParseTimingLines extracts "acs timing: <phase> <ms> ms" lines. It returns
// per-phase totals and the order in which phases were first reported. Lines
// that are not timing lines are ignored.
func ParseTimingLines(r io.Reader) (map[string]PhaseSample, []string, error) {
	phases := map[string]PhaseSample{}
	order := []string{}
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		rest, ok := strings.CutPrefix(line, "acs timing:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) != 3 || fields[2] != "ms" {
			return nil, nil, fmt.Errorf("malformed timing line %q", line)
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil || value < 0 || math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, nil, fmt.Errorf("malformed timing value in %q", line)
		}
		sample, seen := phases[fields[0]]
		if !seen {
			order = append(order, fields[0])
		}
		sample.Milliseconds += value
		sample.Count++
		phases[fields[0]] = sample
	}
	return phases, order, scanner.Err()
}

// TargetStartMarker is printed by the fake Devin when its interactive mode
// starts, followed by the wall-clock Unix time in nanoseconds.
const TargetStartMarker = "ACS_BENCH_TARGET_START"

// ParseTargetStart returns the nanosecond timestamp printed by the fake
// target's interactive mode.
func ParseTargetStart(r io.Reader) (int64, bool) {
	scanner := bufio.NewScanner(r)
	var found int64
	ok := false
	for scanner.Scan() {
		rest, has := strings.CutPrefix(strings.TrimSpace(scanner.Text()), TargetStartMarker+" ")
		if !has {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
		if err == nil && value > 0 {
			found, ok = value, true
		}
	}
	return found, ok
}

// Median returns the median of values (mean of the two middle values for an
// even count). values must not be empty.
func Median(values []float64) float64 {
	sorted := sortedCopy(values)
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}

// Percentile returns the nearest-rank percentile (0 < p <= 100).
func Percentile(values []float64, p float64) float64 {
	sorted := sortedCopy(values)
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	if rank < 1 {
		rank = 1
	}
	if rank > len(sorted) {
		rank = len(sorted)
	}
	return sorted[rank-1]
}

func sortedCopy(values []float64) []float64 {
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	return sorted
}

// Column identifies one benchmarked configuration in the summary.
type Column struct {
	Label      string
	Ref        string
	SkillFiles int
}

// Stat is the aggregate of one phase in one column.
type Stat struct {
	Median, P90 float64
	Samples     int
	MeanCount   float64
}

// Summary aggregates runs by column and phase.
type Summary struct {
	Columns []Column
	Phases  []string
	Stats   map[Column]map[string]Stat
	Runs    map[Column]int
}

// Summarize groups successful runs by (label, skill files) and computes the
// median and p90 of every phase. A phase missing from a run counts as absent
// for that run, so Samples can be lower than the number of runs.
func Summarize(runs []Run) Summary {
	summary := Summary{Stats: map[Column]map[string]Stat{}, Runs: map[Column]int{}}
	values := map[Column]map[string][]float64{}
	counts := map[Column]map[string][]int{}
	seenPhase := map[string]bool{}
	for _, phase := range syntheticPhases {
		seenPhase[phase] = true
		summary.Phases = append(summary.Phases, phase)
	}
	for _, run := range runs {
		if run.ExitCode != 0 {
			continue
		}
		column := Column{Label: run.Label, Ref: run.Ref, SkillFiles: run.SkillFiles}
		if _, ok := values[column]; !ok {
			values[column] = map[string][]float64{}
			counts[column] = map[string][]int{}
			summary.Columns = append(summary.Columns, column)
		}
		summary.Runs[column]++
		order := append([]string(nil), run.PhaseOrder...)
		for name := range run.Phases {
			if !contains(order, name) {
				order = append(order, name)
			}
		}
		for _, name := range order {
			sample, ok := run.Phases[name]
			if !ok {
				continue
			}
			if !seenPhase[name] {
				seenPhase[name] = true
				summary.Phases = append(summary.Phases, name)
			}
			values[column][name] = append(values[column][name], sample.Milliseconds)
			counts[column][name] = append(counts[column][name], sample.Count)
		}
	}
	sort.SliceStable(summary.Columns, func(i, j int) bool {
		if summary.Columns[i].Label != summary.Columns[j].Label {
			return labelRank(summary.Columns[i].Label) < labelRank(summary.Columns[j].Label)
		}
		return summary.Columns[i].SkillFiles < summary.Columns[j].SkillFiles
	})
	for column, phases := range values {
		summary.Stats[column] = map[string]Stat{}
		for name, samples := range phases {
			total := 0
			for _, count := range counts[column][name] {
				total += count
			}
			summary.Stats[column][name] = Stat{
				Median: Median(samples), P90: Percentile(samples, 90), Samples: len(samples),
				MeanCount: float64(total) / float64(len(samples)),
			}
		}
	}
	return summary
}

func labelRank(label string) string {
	if label == "primary" {
		return "0"
	}
	return "1" + label
}

func contains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

// RenderMarkdown writes the summary as a GitHub-flavoured Markdown table.
func RenderMarkdown(w io.Writer, summary Summary) error {
	if len(summary.Columns) == 0 {
		_, err := fmt.Fprintln(w, "No successful benchmark runs.")
		return err
	}
	var builder strings.Builder
	builder.WriteString("| Phase | Runs/launch |")
	for _, column := range summary.Columns {
		fmt.Fprintf(&builder, " %s median (ms) | p90 (ms) |", columnTitle(column))
	}
	builder.WriteString("\n|---|---:|")
	for range summary.Columns {
		builder.WriteString("---:|---:|")
	}
	builder.WriteString("\n")
	for _, phase := range summary.Phases {
		present := false
		count := 0.0
		for _, column := range summary.Columns {
			if stat, ok := summary.Stats[column][phase]; ok {
				present = true
				if stat.MeanCount > count {
					count = stat.MeanCount
				}
			}
		}
		if !present {
			continue
		}
		fmt.Fprintf(&builder, "| `%s` | %s |", markdownCell(phase), formatCount(count))
		for _, column := range summary.Columns {
			stat, ok := summary.Stats[column][phase]
			if !ok {
				builder.WriteString(" – | – |")
				continue
			}
			fmt.Fprintf(&builder, " %.1f | %.1f |", stat.Median, stat.P90)
		}
		builder.WriteString("\n")
	}
	builder.WriteString("\nRuns per column: ")
	for index, column := range summary.Columns {
		if index > 0 {
			builder.WriteString(", ")
		}
		fmt.Fprintf(&builder, "%s = %d", columnTitle(column), summary.Runs[column])
	}
	builder.WriteString(".\n")
	_, err := io.WriteString(w, builder.String())
	return err
}

func formatCount(count float64) string {
	if count == math.Trunc(count) {
		return strconv.Itoa(int(count))
	}
	return strconv.FormatFloat(count, 'f', 1, 64)
}

func columnTitle(column Column) string {
	return fmt.Sprintf("%s · %d Skill files", markdownCell(column.Ref), column.SkillFiles)
}

// markdownCell neutralises characters that would break or style a table cell.
func markdownCell(value string) string {
	replacer := strings.NewReplacer("|", "\\|", "`", "'", "\n", " ", "\r", " ", "<", "&lt;", ">", "&gt;")
	return replacer.Replace(value)
}

// WriteCSV writes one row per run and phase.
func WriteCSV(w io.Writer, runs []Run) error {
	if _, err := fmt.Fprintln(w, "label,ref,skill_files,iteration,exit_code,phase,ms,count"); err != nil {
		return err
	}
	for _, run := range runs {
		order := append([]string(nil), run.PhaseOrder...)
		names := make([]string, 0, len(run.Phases))
		for name := range run.Phases {
			if !contains(order, name) {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range append(order, names...) {
			sample, ok := run.Phases[name]
			if !ok {
				continue
			}
			if _, err := fmt.Fprintf(w, "%s,%s,%d,%d,%d,%s,%.3f,%d\n", csvField(run.Label), csvField(run.Ref), run.SkillFiles, run.Iteration, run.ExitCode, csvField(name), sample.Milliseconds, sample.Count); err != nil {
				return err
			}
		}
	}
	return nil
}

func csvField(value string) string {
	if strings.ContainsAny(value, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(value, "\"", "\"\"") + "\""
	}
	return value
}

// ReadRuns decodes JSON Lines produced by the run command.
func ReadRuns(r io.Reader) ([]Run, error) {
	decoder := json.NewDecoder(r)
	runs := []Run{}
	for {
		var run Run
		if err := decoder.Decode(&run); err == io.EOF {
			return runs, nil
		} else if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
}
