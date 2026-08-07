package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/alcimerio/ai-config-selector/internal/release/publication"
)

func main() {
	flags := flag.NewFlagSet("releasepublish", flag.ContinueOnError)
	var flagOutput bytes.Buffer
	flags.SetOutput(&flagOutput)
	candidate := flags.String("candidate", "", "release candidate directory")
	version := flags.String("version", "", "canonical release version")
	source := flags.String("source-commit", "", "tagged source commit")
	releaseNotes := flags.String("release-notes", "", "version-controlled release notes")
	releaseJSON := flags.String("release-json", "", "optional GitHub Release response")
	if err := flags.Parse(os.Args[1:]); err != nil || flags.NArg() != 0 || *candidate == "" || *version == "" || *source == "" || *releaseNotes == "" {
		fmt.Fprintln(os.Stderr, "invalid release-publication arguments")
		os.Exit(2)
	}
	var remote *os.File
	if *releaseJSON != "" {
		var err error
		remote, err = os.Open(*releaseJSON)
		if err != nil {
			fmt.Fprintln(os.Stderr, "GitHub Release response could not be opened")
			os.Exit(1)
		}
		defer remote.Close()
	}
	notes, err := os.ReadFile(*releaseNotes)
	if err != nil {
		fmt.Fprintln(os.Stderr, "release notes could not be read")
		os.Exit(1)
	}
	plan, err := publication.Plan(*candidate, *version, *source, string(notes), remote)
	if err != nil {
		fmt.Fprintf(os.Stderr, "release publication is blocked: %s\n", strconv.QuoteToASCII(err.Error()))
		os.Exit(1)
	}
	fmt.Printf("state\t%s\nrelease-id\t%d\npublish\t%t\n", plan.State, plan.ReleaseID, plan.Publish)
	for _, asset := range plan.Upload {
		fmt.Printf("upload\t%s\n", asset)
	}
}
