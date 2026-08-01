package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

func main() {
	if err := requireSupportedPlatform(runtime.GOOS); err != nil {
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
		Catalog:           adapter,
		Planner:           adapter,
		Launcher:          adapter,
		Profiles:          profile.NewStore(filepath.Join(existingHome, ".acs")),
		SessionsDirectory: filepath.Join(existingHome, ".acs", "sessions"),
		WorkingDirectory:  workingDirectory,
		Input:             os.Stdin,
		Output:            os.Stdout,
		ErrorOutput:       os.Stderr,
	}
	os.Exit(application.Run(context.Background(), os.Args[1:]))
}

func requireSupportedPlatform(goos string) error {
	if goos != "darwin" {
		return fmt.Errorf("ACS supports macOS only; current platform is %s", goos)
	}
	return nil
}
