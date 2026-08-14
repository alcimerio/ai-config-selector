package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

var releaseVersionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\+incompatible)?$`)
var releaseVersion string

func main() {
	handled, err := launch.RunBubblewrapHelper(os.Args[1:])
	if handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "acs: sandbox helper failed")
			os.Exit(1)
		}
		return
	}
	if err := requireSupportedPlatform(launch.CurrentPlatform); err != nil {
		fmt.Fprintf(os.Stderr, "acs: %v\n", err)
		os.Exit(1)
	}
	existingHome, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "acs: resolve user home: %v\n", err)
		os.Exit(1)
	}
	adapter, err := devin.New(devin.Config{
		BinaryPath:      "devin",
		ExistingHomeDir: existingHome,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "acs: configure Devin Adapter: %v\n", err)
		os.Exit(1)
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "acs: resolve working directory: %v\n", err)
		os.Exit(1)
	}

	application := cli.App{
		Version:           buildVersion(releaseVersion, debug.ReadBuildInfo),
		Categories:        adapter.Categories(),
		Builder:           adapter,
		Planner:           adapter,
		Launcher:          adapter,
		Profiles:          profile.NewStore(filepath.Join(existingHome, ".acs"), adapter.Categories()),
		SessionsDirectory: filepath.Join(existingHome, ".acs", "sessions"),
		WorkingDirectory:  workingDirectory,
		Input:             os.Stdin,
		Output:            os.Stdout,
		ErrorOutput:       os.Stderr,
		Interactive:       cli.StandardStreamsInteractive,
	}
	os.Exit(application.Run(context.Background(), os.Args[1:]))
}

func buildVersion(builderVersion string, readBuildInfo func() (*debug.BuildInfo, bool)) string {
	if readBuildInfo == nil {
		return "devel"
	}
	info, ok := readBuildInfo()
	if !ok || info == nil {
		return "devel"
	}
	for _, setting := range info.Settings {
		if setting.Key == "vcs.modified" && setting.Value == "true" {
			return "devel"
		}
	}
	if builderVersion != "" {
		if !releaseVersionPattern.MatchString(builderVersion) || strings.HasSuffix(builderVersion, "+incompatible") {
			return "devel"
		}
		return builderVersion
	}
	version := info.Main.Version
	if !releaseVersionPattern.MatchString(version) {
		return "devel"
	}
	return version
}

func requireSupportedPlatform(probe func() (launch.Platform, error)) error {
	platform, err := probe()
	if err != nil {
		return err
	}
	return launch.ValidatePlatform(platform)
}
