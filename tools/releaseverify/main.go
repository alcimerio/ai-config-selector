package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/release/artifacts"
)

func main() {
	flags := flag.NewFlagSet("releaseverify", flag.ContinueOnError)
	var flagOutput bytes.Buffer
	flags.SetOutput(&flagOutput)
	dist := flags.String("dist", "", "directory containing the release candidate")
	version := flags.String("version", "", "canonical release tag")
	linuxCandidate := flags.Bool("linux-candidate", false, "validate the separate, non-publishable linux/amd64 candidate set")
	if err := flags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "invalid arguments: %s\n", strconv.QuoteToASCII(flagOutput.String()))
		os.Exit(2)
	}
	if *dist == "" || *version == "" || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: releaseverify --dist <directory> --version <vMAJOR.MINOR.PATCH> [--linux-candidate]")
		os.Exit(2)
	}
	binary, err := artifacts.Read(*dist, *version, *linuxCandidate)
	if err == nil {
		goos, goarch := "darwin", "arm64"
		if *linuxCandidate {
			goos, goarch = "linux", "amd64"
		}
		if goos == runtime.GOOS && goarch == runtime.GOARCH {
			err = verifyExecutable(binary, *version)
			if err == nil {
				fmt.Printf("Verified packaged executable for %s/%s.\n", goos, goarch)
			}
		} else {
			fmt.Printf("Skipped packaged executable verification for %s/%s: validation host is %s/%s.\n", goos, goarch, runtime.GOOS, runtime.GOARCH)
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "release candidate is invalid: %s\n", strconv.QuoteToASCII(err.Error()))
		os.Exit(1)
	}
}

func verifyExecutable(contents []byte, version string) error {
	temporaryDirectory, err := os.MkdirTemp("", "acs-releaseverify-")
	if err != nil {
		return fmt.Errorf("create executable workspace: %w", err)
	}
	defer os.RemoveAll(temporaryDirectory)
	path := filepath.Join(temporaryDirectory, "acs")
	if err := os.WriteFile(path, contents, 0o700); err != nil {
		return fmt.Errorf("write executable: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, path, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("execute acs version: %w", err)
	}
	want := fmt.Sprintf("acs %s\n", version)
	if string(output) != want {
		return fmt.Errorf("acs version output is %q, want %q", output, want)
	}
	return nil
}
