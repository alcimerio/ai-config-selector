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
	"github.com/alcimerio/ai-config-selector/internal/codexauth"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/sandboxshell"
)

var releaseVersionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:\+incompatible)?$`)
var releaseVersion string

func main() {
	handled, err := launch.RunBubblewrapHelper(os.Args[1:])
	if handled {
		if err != nil {
			if exitCode, isTargetExit := launch.BubblewrapHelperExitCode(err); isTargetExit {
				os.Exit(exitCode)
			}
			fmt.Fprintln(os.Stderr, "acs: sandbox helper failed")
			os.Exit(1)
		}
		return
	}
	informational := cli.App{Version: buildVersion(releaseVersion, debug.ReadBuildInfo), Output: os.Stdout, ErrorOutput: os.Stderr}
	if handled, code := informational.RunInformational(os.Args[1:]); handled {
		os.Exit(code)
	}
	if handled, code := informational.RunProfileInspection(os.Args[1:], os.UserHomeDir); handled {
		os.Exit(code)
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
	acsHome := filepath.Join(existingHome, ".acs")
	sessionsDirectory := filepath.Join(acsHome, "sessions")
	codexAuth, err := codexauth.New(codexauth.Config{
		BinaryPath:        "codex",
		SupportedVersion:  codexauth.SupportedCodexVersion,
		ACSHome:           acsHome,
		SessionsDirectory: sessionsDirectory,
		WorkingDirectory:  workingDirectory,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "acs: configure Codex authentication: %v\n", err)
		os.Exit(1)
	}
	shellLauncher := sandboxshell.New()

	application := cli.App{
		Version:           buildVersion(releaseVersion, debug.ReadBuildInfo),
		Categories:        adapter.Categories(),
		Builder:           adapter,
		Planner:           adapter,
		Launcher:          adapter,
		SandboxPlanner:    shellLauncher,
		SandboxLauncher:   shellLauncher,
		CodexAuth:         codexAuth,
		Profiles:          profile.NewStore(acsHome, adapter.Categories()),
		SessionsDirectory: sessionsDirectory,
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
