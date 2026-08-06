package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const versionPlaceholder = "__ACS_RELEASE_VERSION__"

var canonicalReleaseVersion = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

func main() {
	flags := flag.NewFlagSet("renderinstaller", flag.ContinueOnError)
	var flagOutput bytes.Buffer
	flags.SetOutput(&flagOutput)
	templatePath := flags.String("template", "", "installer template path")
	outputPath := flags.String("output", "", "rendered installer path")
	version := flags.String("version", "", "canonical release tag")
	if err := flags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "invalid arguments: %s\n", strconv.QuoteToASCII(flagOutput.String()))
		os.Exit(2)
	}
	if *templatePath == "" || *outputPath == "" || *version == "" || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: renderinstaller --template <path> --output <path> --version <vMAJOR.MINOR.PATCH>")
		os.Exit(2)
	}
	if err := render(*templatePath, *outputPath, *version); err != nil {
		fmt.Fprintf(os.Stderr, "render installer: %s\n", strconv.QuoteToASCII(err.Error()))
		os.Exit(1)
	}
}

func render(templatePath, outputPath, version string) error {
	if !canonicalReleaseVersion.MatchString(version) {
		return fmt.Errorf("version must be a canonical immutable Release tag")
	}
	template, err := os.ReadFile(templatePath)
	if err != nil {
		return fmt.Errorf("read template: %w", err)
	}
	if strings.Count(string(template), versionPlaceholder) != 1 {
		return fmt.Errorf("template must contain exactly one version placeholder")
	}
	rendered := strings.Replace(string(template), versionPlaceholder, version, 1)
	directory := filepath.Dir(outputPath)
	temporary, err := os.CreateTemp(directory, ".install.sh.")
	if err != nil {
		return fmt.Errorf("create temporary output: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if _, err := temporary.WriteString(rendered); err != nil {
		temporary.Close()
		return fmt.Errorf("write output: %w", err)
	}
	if err := temporary.Chmod(0o755); err != nil {
		temporary.Close()
		return fmt.Errorf("set output permissions: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	if err := os.Rename(temporaryPath, outputPath); err != nil {
		return fmt.Errorf("publish output: %w", err)
	}
	return nil
}
