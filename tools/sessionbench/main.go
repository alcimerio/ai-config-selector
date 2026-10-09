// Command sessionbench measures real ACS Devin Sessions with a synthetic
// target. It is used only by the manually dispatched macOS benchmark workflow.
//
//	sessionbench run --primary-acs PATH --primary-ref REF [--compare-acs PATH --compare-ref REF]
//	                 [--iterations N] [--skill-files 0,20] [--warmup 1] --out runs.jsonl
//	sessionbench summarize --in runs.jsonl [--csv runs.csv]
//
// When the binary is invoked as "devin" it acts as the synthetic target: it
// answers the Devin preflights ACS runs (skills list, auth status) and, in
// interactive mode, prints a start timestamp and exits immediately. It needs
// no account, credential or network access.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	maximumIterations = 200
	profileName       = "bench"
	skillName         = "review"
)

func main() {
	if filepath.Base(os.Args[0]) == "devin" {
		os.Exit(fakeDevin(os.Args[1:], os.Stdout))
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sessionbench run|summarize [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "run":
		err = runCommand(os.Args[2:])
	case "summarize":
		err = summarizeCommand(os.Args[2:], os.Stdout)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sessionbench:", err)
		os.Exit(1)
	}
}

// fakeDevin implements the synthetic target protocol.
func fakeDevin(arguments []string, stdout io.Writer) int {
	if len(arguments) > 0 {
		switch arguments[0] {
		case "skills":
			base := filepath.Join(os.Getenv("HOME"), ".config", "devin", "skills", skillName)
			encoded, err := json.Marshal([]map[string]string{{"name": skillName, "provider": "Devin", "base_dir": base}})
			if err != nil {
				return 1
			}
			fmt.Fprintf(stdout, "%s\n", encoded)
			return 0
		case "auth":
			fmt.Fprintln(stdout, "Logged in (synthetic benchmark target).")
			return 0
		}
	}
	fmt.Fprintf(stdout, "%s %d\n", TargetStartMarker, time.Now().UnixNano())
	return 0
}

type target struct {
	label, ref, acs string
}

type runOptions struct {
	targets    []target
	iterations int
	warmup     int
	skillFiles []int
	timeout    time.Duration
	out        string
	fake       string
}

func parseRunOptions(arguments []string) (runOptions, error) {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	primaryACS := flags.String("primary-acs", "", "acs binary built from the primary ref")
	primaryRef := flags.String("primary-ref", "", "primary ref name")
	compareACS := flags.String("compare-acs", "", "optional acs binary built from the compare ref")
	compareRef := flags.String("compare-ref", "", "compare ref name")
	iterations := flags.String("iterations", "10", "measured runs per configuration")
	warmup := flags.Int("warmup", 1, "unmeasured warmup runs per configuration")
	skillFiles := flags.String("skill-files", "0,20", "comma-separated Skill file counts")
	timeout := flags.Duration("timeout", 2*time.Minute, "timeout per launch")
	out := flags.String("out", "", "JSON Lines output path")
	if err := flags.Parse(arguments); err != nil {
		return runOptions{}, err
	}
	if flags.NArg() != 0 || *primaryACS == "" || *primaryRef == "" || *out == "" {
		return runOptions{}, errors.New("run requires --primary-acs, --primary-ref and --out")
	}
	if (*compareACS == "") != (*compareRef == "") {
		return runOptions{}, errors.New("--compare-acs and --compare-ref must be given together")
	}
	count, err := strconv.Atoi(strings.TrimSpace(*iterations))
	if err != nil || count < 1 || count > maximumIterations {
		return runOptions{}, fmt.Errorf("iterations must be an integer between 1 and %d", maximumIterations)
	}
	if *warmup < 0 || *warmup > 5 {
		return runOptions{}, errors.New("warmup must be between 0 and 5")
	}
	counts, err := parseSkillFiles(*skillFiles)
	if err != nil {
		return runOptions{}, err
	}
	options := runOptions{iterations: count, warmup: *warmup, skillFiles: counts, timeout: *timeout, out: *out,
		targets: []target{{label: "primary", ref: *primaryRef, acs: *primaryACS}}}
	if *compareACS != "" {
		options.targets = append(options.targets, target{label: "compare", ref: *compareRef, acs: *compareACS})
	}
	return options, nil
}

func parseSkillFiles(value string) ([]int, error) {
	counts := []int{}
	for _, field := range strings.Split(value, ",") {
		count, err := strconv.Atoi(strings.TrimSpace(field))
		if err != nil || count < 0 || count > 1000 {
			return nil, fmt.Errorf("invalid Skill file count %q", field)
		}
		for _, existing := range counts {
			if existing == count {
				return nil, fmt.Errorf("duplicate Skill file count %d", count)
			}
		}
		counts = append(counts, count)
	}
	return counts, nil
}

type fixture struct {
	home, workspace, tools string
}

func runCommand(arguments []string) error {
	options, err := parseRunOptions(arguments)
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	options.fake = self
	output, err := os.OpenFile(options.out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer output.Close()
	encoder := json.NewEncoder(output)

	fixtures := map[string]fixture{}
	key := func(t target, files int) string { return t.label + "/" + strconv.Itoa(files) }
	for _, t := range options.targets {
		for _, files := range options.skillFiles {
			created, err := createFixture(options.fake, files)
			if err != nil {
				return err
			}
			defer os.RemoveAll(filepath.Dir(created.home))
			fixtures[key(t, files)] = created
		}
	}
	// Warm up every configuration, then interleave measured runs so runner
	// drift affects every configuration alike.
	for round := 0; round < options.warmup; round++ {
		for _, files := range options.skillFiles {
			for _, t := range options.targets {
				if _, err := launch(t, fixtures[key(t, files)], files, -1, options.timeout); err != nil {
					return fmt.Errorf("warmup %s %d Skill files: %w", t.label, files, err)
				}
			}
		}
	}
	for iteration := 1; iteration <= options.iterations; iteration++ {
		for _, files := range options.skillFiles {
			for _, t := range options.targets {
				run, err := launch(t, fixtures[key(t, files)], files, iteration, options.timeout)
				if encodeErr := encoder.Encode(run); encodeErr != nil {
					return encodeErr
				}
				if err != nil {
					return fmt.Errorf("%s %d Skill files iteration %d: %w", t.label, files, iteration, err)
				}
			}
		}
		fmt.Fprintf(os.Stderr, "sessionbench: iteration %d/%d done\n", iteration, options.iterations)
	}
	return nil
}

func createFixture(fake string, files int) (fixture, error) {
	root, err := os.MkdirTemp("", "acs-sessionbench-")
	if err != nil {
		return fixture{}, err
	}
	if root, err = filepath.EvalSymlinks(root); err != nil {
		return fixture{}, err
	}
	created := fixture{home: filepath.Join(root, "home"), workspace: filepath.Join(root, "workspace"), tools: filepath.Join(root, "tools")}
	bundle := filepath.Join(created.home, ".config", "devin", "skills", skillName)
	for _, directory := range []string{created.workspace, created.tools, filepath.Join(bundle, "scripts"), filepath.Join(created.home, ".acs", "profiles"), filepath.Join(created.home, ".local", "share", "devin")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return fixture{}, err
		}
	}
	writes := map[string][]byte{
		filepath.Join(bundle, "SKILL.md"): []byte("# " + skillName + "\n\nSynthetic benchmark Skill.\n"),
		// Envelope version 3 is the one format every benchmarked ref reads:
		// binaries before the version 1 renumbering accept only 3, and later
		// ones keep 3 as a read alias.
		filepath.Join(created.home, ".acs", "profiles", profileName+".json"): []byte(`{"version":3,"name":"` + profileName + `","common":{"skills":{"version":1,"selection":[{"source":"devin-config","relativePath":"` + skillName + `"}]},"workspace":{"version":1,"selection":{"access":"read-write"}}},"overlays":{"devin":{"version":1}}}`),
		// Synthetic placeholder so the credential copy step is exercised; it
		// is not a real credential and the fake target never reads it.
		filepath.Join(created.home, ".local", "share", "devin", "credentials.toml"): []byte("synthetic-benchmark-placeholder\n"),
	}
	for index := 0; index < files; index++ {
		writes[filepath.Join(bundle, "scripts", fmt.Sprintf("file-%04d.txt", index))] = bytes.Repeat([]byte("x"), 2048)
	}
	for path, contents := range writes {
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			return fixture{}, err
		}
	}
	if err := copyExecutable(fake, filepath.Join(created.tools, "devin")); err != nil {
		return fixture{}, err
	}
	return created, nil
}

func copyExecutable(source, destination string) error {
	contents, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	return os.WriteFile(destination, contents, 0o755)
}

func launch(t target, created fixture, files, iteration int, timeout time.Duration) (Run, error) {
	run := Run{Label: t.label, Ref: t.ref, SkillFiles: files, Iteration: iteration, Phases: map[string]PhaseSample{}}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, t.acs, "devin", "--profile", profileName)
	command.Dir = created.workspace
	command.Env = []string{
		"HOME=" + created.home,
		"PATH=" + created.tools + ":/usr/bin:/bin:/usr/sbin:/sbin",
		"TERM=dumb", "NO_COLOR=1", "LANG=C",
		"ACS_DEBUG_TIMING=1",
	}
	if temporary := os.Getenv("TMPDIR"); temporary != "" {
		command.Env = append(command.Env, "TMPDIR="+temporary)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	started := time.Now()
	err := command.Run()
	finished := time.Now()
	if exitErr := (*exec.ExitError)(nil); errors.As(err, &exitErr) {
		run.ExitCode = exitErr.ExitCode()
	} else if err != nil {
		run.ExitCode = -1
	}
	phases, order, parseErr := ParseTimingLines(bytes.NewReader(stderr.Bytes()))
	if parseErr == nil {
		run.Phases, run.PhaseOrder = phases, order
	}
	run.Phases[phaseWall] = PhaseSample{Milliseconds: milliseconds(finished.Sub(started)), Count: 1}
	if targetStart, ok := ParseTargetStart(bytes.NewReader(stdout.Bytes())); ok {
		at := time.Unix(0, targetStart)
		run.Phases[phaseStart] = PhaseSample{Milliseconds: milliseconds(at.Sub(started)), Count: 1}
		run.Phases[phaseExit] = PhaseSample{Milliseconds: milliseconds(finished.Sub(at)), Count: 1}
	} else if err == nil {
		err = errors.New("synthetic target did not report its interactive start")
	}
	if err == nil && parseErr != nil {
		err = parseErr
	}
	if err != nil {
		if run.ExitCode == 0 {
			run.ExitCode = -1
		}
		return run, fmt.Errorf("%w\nstdout:\n%s\nstderr:\n%s", err, tail(stdout.String()), tail(stderr.String()))
	}
	return run, nil
}

func milliseconds(duration time.Duration) float64 {
	return float64(duration.Microseconds()) / 1000
}

func tail(value string) string {
	const limit = 4000
	if len(value) > limit {
		return "..." + value[len(value)-limit:]
	}
	return value
}

func summarizeCommand(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("summarize", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	in := flags.String("in", "", "JSON Lines input path")
	csvPath := flags.String("csv", "", "optional CSV output path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *in == "" || flags.NArg() != 0 {
		return errors.New("summarize requires --in")
	}
	input, err := os.Open(*in)
	if err != nil {
		return err
	}
	defer input.Close()
	runs, err := ReadRuns(input)
	if err != nil {
		return err
	}
	if *csvPath != "" {
		output, err := os.Create(*csvPath)
		if err != nil {
			return err
		}
		if err := WriteCSV(output, runs); err != nil {
			output.Close()
			return err
		}
		if err := output.Close(); err != nil {
			return err
		}
	}
	return RenderMarkdown(stdout, Summarize(runs))
}
