//go:build integration && darwin

package devin_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
)

func TestRealDevinPreflightPreservesExactGlobalCatalogAndExistingLogin(t *testing.T) {
	binary, err := exec.LookPath("devin")
	if err != nil {
		t.Fatalf("real-Devin contract requires an installed devin CLI: %v", err)
	}
	existingHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("resolve existing home: %v", err)
	}

	adapter, err := devin.New(devin.Config{
		BinaryPath:      binary,
		ExistingHomeDir: existingHome,
	})
	if err != nil {
		t.Fatalf("create adapter: %v", err)
	}

	session, err := adapter.PrepareSession(t.TempDir(), t.TempDir(), []devin.SkillBundle{
		{
			Source:       devin.GlobalSourceDevinConfig,
			RelativePath: "acs-selected-devin",
			BundlePath:   filepath.Join("testdata", "selected-skill"),
		},
		{
			Source:       devin.GlobalSourceSharedAgents,
			RelativePath: "acs-selected-agents",
			BundlePath:   filepath.Join("testdata", "selected-skill"),
		},
	})
	if err != nil {
		t.Fatalf("prepare Session: %v", err)
	}

	assertPreparationCopiedOnlyAllowlistedState(t, session.HomeDir)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := adapter.Preflight(ctx, session); err != nil {
		t.Fatalf("real-Devin Adapter Preflight: %v", err)
	}
}

func assertPreparationCopiedOnlyAllowlistedState(t *testing.T, sessionHome string) {
	t.Helper()

	required := []string{
		filepath.Join(sessionHome, ".config", "devin", "skills", "acs-selected-devin", "SKILL.md"),
		filepath.Join(sessionHome, ".config", "devin", "skills", "acs-selected-devin", "references", "proof.txt"),
		filepath.Join(sessionHome, ".agents", "skills", "acs-selected-agents", "SKILL.md"),
		filepath.Join(sessionHome, ".agents", "skills", "acs-selected-agents", "references", "proof.txt"),
		filepath.Join(sessionHome, ".local", "share", "devin", "credentials.toml"),
	}
	for _, path := range required {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("required Session file %q: %v", path, err)
		}
	}

	forbidden := []string{
		filepath.Join(sessionHome, ".config", "devin", "config.json"),
		filepath.Join(sessionHome, ".config", "devin", "mcp_config.json"),
		filepath.Join(sessionHome, ".config", "devin", "hooks"),
		filepath.Join(sessionHome, ".config", "devin", "AGENTS.md"),
	}
	for _, path := range forbidden {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("unrestricted Devin state was copied to %q", path)
		}
	}
}
