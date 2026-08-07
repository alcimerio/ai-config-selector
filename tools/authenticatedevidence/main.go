package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/release/authenticatedevidence"
)

func main() {
	flags := flag.NewFlagSet("authenticatedevidence", flag.ContinueOnError)
	var flagOutput bytes.Buffer
	flags.SetOutput(&flagOutput)
	evidencePath := flags.String("evidence", "", "sanitized authenticated evidence JSON")
	version := flags.String("version", "", "canonical candidate version")
	sourceCommit := flags.String("source-commit", "", "candidate source commit")
	target := flags.String("target", "", "authenticated reference target")
	archiveSHA256 := flags.String("archive-sha256", "", "target archive SHA-256")
	artifactSetSHA256 := flags.String("artifact-set-sha256", "", "SHA256SUMS file SHA-256")
	earliest := flags.String("earliest-completion", "", "optional RFC3339 review-window start")
	latest := flags.String("latest-completion", "", "optional RFC3339 review-window end")
	if err := flags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "invalid authenticated-evidence arguments")
		os.Exit(2)
	}
	if *evidencePath == "" || *version == "" || *sourceCommit == "" || *target == "" || *archiveSHA256 == "" || *artifactSetSHA256 == "" || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: authenticatedevidence --evidence <file> --version <vMAJOR.MINOR.PATCH> --source-commit <sha> --target <darwin/arm64|linux/amd64> --archive-sha256 <sha256> --artifact-set-sha256 <sha256> [--earliest-completion <RFC3339>] [--latest-completion <RFC3339>]")
		os.Exit(2)
	}

	expected := authenticatedevidence.Expectations{
		Version:           *version,
		SourceCommit:      *sourceCommit,
		Target:            *target,
		ArchiveSHA256:     *archiveSHA256,
		ArtifactSetSHA256: *artifactSetSHA256,
	}
	var err error
	if *earliest != "" {
		expected.EarliestCompletion, err = time.Parse(time.RFC3339, *earliest)
		if err != nil {
			fmt.Fprintln(os.Stderr, "authenticated evidence earliest-completion is invalid")
			os.Exit(2)
		}
	}
	if *latest != "" {
		expected.LatestCompletion, err = time.Parse(time.RFC3339, *latest)
		if err != nil {
			fmt.Fprintln(os.Stderr, "authenticated evidence latest-completion is invalid")
			os.Exit(2)
		}
	}

	input, err := os.Open(*evidencePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "authenticated evidence file could not be opened")
		os.Exit(1)
	}
	defer input.Close()
	if err := authenticatedevidence.Validate(input, expected); err != nil {
		fmt.Fprintf(os.Stderr, "authenticated evidence is invalid: %s\n", strconv.QuoteToASCII(err.Error()))
		os.Exit(1)
	}
	fmt.Printf("authenticated evidence: target=%s candidate=%s source=%s status=passed\n", expected.Target, expected.Version, expected.SourceCommit)
}
