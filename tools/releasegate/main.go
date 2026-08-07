package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/release/releasegate"
)

func main() {
	flags := flag.NewFlagSet("releasegate", flag.ContinueOnError)
	var flagOutput bytes.Buffer
	flags.SetOutput(&flagOutput)
	evidencePath := flags.String("evidence", "", "annotated-tag evidence set")
	candidateDirectory := flags.String("candidate", "", "verified release candidate directory")
	version := flags.String("version", "", "canonical release version")
	sourceCommit := flags.String("source-commit", "", "tagged source commit")
	earliestText := flags.String("earliest-completion", "", "RFC3339 source boundary")
	latestText := flags.String("latest-completion", "", "RFC3339 tag boundary")
	if err := flags.Parse(os.Args[1:]); err != nil || flags.NArg() != 0 || *evidencePath == "" || *candidateDirectory == "" || *version == "" || *sourceCommit == "" || *earliestText == "" || *latestText == "" {
		fmt.Fprintln(os.Stderr, "invalid release-gate arguments")
		os.Exit(2)
	}
	earliest, err := time.Parse(time.RFC3339, *earliestText)
	if err != nil {
		fmt.Fprintln(os.Stderr, "release-gate earliest completion boundary is invalid")
		os.Exit(2)
	}
	latest, err := time.Parse(time.RFC3339, *latestText)
	if err != nil {
		fmt.Fprintln(os.Stderr, "release-gate latest completion boundary is invalid")
		os.Exit(2)
	}
	input, err := os.Open(*evidencePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "release-gate evidence could not be opened")
		os.Exit(1)
	}
	defer input.Close()
	err = releasegate.Validate(input, releasegate.Expectations{
		Version: *version, SourceCommit: *sourceCommit, CandidateDirectory: *candidateDirectory,
		EarliestCompletion: earliest, LatestCompletion: latest,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "release gate rejected the candidate: %s\n", strconv.QuoteToASCII(err.Error()))
		os.Exit(1)
	}
	fmt.Printf("release gate: candidate=%s source=%s evidence=complete status=passed\n", *version, *sourceCommit)
}
