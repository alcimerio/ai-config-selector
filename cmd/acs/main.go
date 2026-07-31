package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

func main() {
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

	application := cli.App{
		Catalog:     adapter,
		Profiles:    profile.NewStore(filepath.Join(existingHome, ".acs")),
		Input:       os.Stdin,
		Output:      os.Stdout,
		ErrorOutput: os.Stderr,
	}
	os.Exit(application.Run(context.Background(), os.Args[1:]))
}
