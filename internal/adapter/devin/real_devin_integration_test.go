//go:build integration && (darwin || linux)

package devin_test

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/executor"
)

func TestRealDevinPreflightPreservesExactGlobalCatalogAndExistingLogin(t *testing.T) {
	if os.Getenv("ACS_REAL_DEVIN_INTEGRATION") != "I_ACKNOWLEDGE_LOCAL_CREDENTIAL_ACCESS" {
		t.Skip("real-Devin integration requires explicit local authorization")
	}
	binary, err := exec.LookPath("devin")
	if err != nil {
		t.Fatal("real-Devin contract requires an installed devin CLI")
	}
	existingHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal("real-Devin contract could not resolve the existing home")
	}

	adapter, err := devin.New(devin.Config{
		BinaryPath:      binary,
		ExistingHomeDir: existingHome,
	})
	if err != nil {
		t.Fatal("real-Devin contract could not create the Adapter")
	}

	resolved, err := adapter.Categories().Resolve(context.Background(), devin.NewSkillsProfile("authenticated-smoke", []devin.SkillReference{
		{
			Source:       devin.GlobalSourceDevinConfig,
			RelativePath: "acs-selected-devin",
		},
		{
			Source:       devin.GlobalSourceSharedAgents,
			RelativePath: "acs-selected-agents",
		},
	}))
	if err != nil {
		t.Fatal("real-Devin contract could not resolve the selected Skills")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := executor.New().VerifyDevin(ctx, executor.DevinRequest{
		SessionsDirectory: t.TempDir(), WorkingDirectory: t.TempDir(), Materializer: resolved,
		Executable: binary, ExistingHomeDirectory: existingHome, ExpectedCatalog: resolved.DevinExpectedCatalog(),
	}); err != nil {
		t.Fatalf("real-Devin protected preflight: %v", err)
	}
}
