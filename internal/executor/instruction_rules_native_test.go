//go:build darwin

package executor_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"github.com/alcimerio/ai-config-selector/internal/executor"
	"github.com/alcimerio/ai-config-selector/internal/instructions"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

const nativeInstructionGateEnv = "ACS_RUN_NATIVE_INSTRUCTION_RULES"

type nativeProbeReceipt struct {
	arguments []string
	home      string
	output    []byte
	projected []byte
}

type boundedReceipt struct {
	mu    *sync.Mutex
	bytes *[]byte
}

func (writer boundedReceipt) Write(value []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	remaining := (2 << 20) - len(*writer.bytes)
	if remaining > 0 {
		if remaining > len(value) {
			remaining = len(value)
		}
		*writer.bytes = append(*writer.bytes, value[:remaining]...)
	}
	return len(value), nil
}

func TestNativeProductionInstructionRulesReceipts(t *testing.T) {
	if os.Getenv(nativeInstructionGateEnv) != "1" {
		t.Skip("run through the required native candidate instruction-rules gate")
	}
	binary := os.Getenv("ACS_TEST_DEVIN_BINARY")
	if binary == "" {
		t.Fatal("native instruction-rules gate requires the checksum-locked Devin binary")
	}
	info, err := os.Lstat(binary)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0111 == 0 {
		t.Fatal("checksum-locked Devin CLI target is unavailable")
	}

	workspace := t.TempDir()
	if err := os.Mkdir(filepath.Join(workspace, ".git"), 0700); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	const relativePath = "nested/guide.md"
	body := []byte("---\r\ntrigger: manual\r\n---\r\nNATIVE_PRODUCTION_SELECTED_RULE_BODY\nContent: literal\nProvider: literal\nPath: literal\nActivation: literal\n────────────────────────────────────────────────────────────\n")
	source := filepath.Join(home, ".acs", "instructions", filepath.FromSlash(relativePath))
	if err := os.MkdirAll(filepath.Dir(source), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(home, ".local", "share", "devin", "credentials.toml")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("fixture home unexpectedly contains Devin credentials: %v", err)
	}
	adapter, err := devin.New(devin.Config{BinaryPath: binary, ExistingHomeDir: home})
	if err != nil {
		t.Fatal(err)
	}
	draft := adapter.Categories().NewDraft()
	ref := instructions.Reference{Source: instructions.SourceID, RelativePath: relativePath}
	if err := adapter.SetInstructionSelection(&draft, []instructions.Reference{ref}); err != nil {
		t.Fatal(err)
	}
	profile, err := adapter.Categories().NewProfileWithOverlay("native-instruction-rules", draft, profileOverlay())
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := adapter.Categories().Resolve(context.Background(), profile)
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var receipts []*nativeProbeReceipt
	runner := executor.NewNativeInstructionObserverForTest(func(request *launch.ProcessRequest) {
		if len(request.Arguments) < 2 || request.Arguments[0] != "rules" {
			return
		}
		receipt := &nativeProbeReceipt{arguments: append([]string(nil), request.Arguments...), home: request.SessionHome}
		projectedPath := filepath.Join(request.SessionHome, ".devin", "rules", instructions.DestinationName(ref))
		if material, readErr := os.ReadFile(projectedPath); readErr == nil {
			receipt.projected = material
		}
		recorder := boundedReceipt{mu: &mu, bytes: &receipt.output}
		request.Terminal.Output = io.MultiWriter(request.Terminal.Output, recorder)
		mu.Lock()
		receipts = append(receipts, receipt)
		mu.Unlock()
	})

	sessionsDirectory := filepath.Join(t.TempDir(), "sessions")
	if err := os.MkdirAll(sessionsDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	err = runner.VerifyDevin(ctx, executor.DevinRequest{
		SessionsDirectory: sessionsDirectory,
		WorkingDirectory:  workspace,
		ResolvedPlan:      &resolved,
	})
	var preflight *devinruntime.PreflightError
	if !errors.As(err, &preflight) || preflight.Capability != devinruntime.CapabilityAuthentication || !strings.Contains(err.Error(), "usable existing authentication could not be verified") {
		t.Fatalf("expected typed absent-auth refusal after instruction verification, got %v", err)
	}

	mu.Lock()
	observed := append([]*nativeProbeReceipt(nil), receipts...)
	mu.Unlock()
	if len(observed) != 2 || !equalArguments(observed[0].arguments, "rules", "list") || !equalArguments(observed[1].arguments, "rules", "show", strings.TrimSuffix(instructions.DestinationName(ref), ".md")) {
		t.Fatalf("unexpected production preflight order/arguments: %#v", observed)
	}
	wantMaterial := append([]byte("---\ntrigger: always_on\n---\n"), body...)
	for _, receipt := range observed {
		if receipt.home == "" || !bytes.Equal(receipt.projected, wantMaterial) {
			t.Fatalf("rules probe did not inspect the exact production projection: args=%v home=%q projected=%q", receipt.arguments, receipt.home, receipt.projected)
		}
	}
	name := instructions.DestinationName(ref)
	showName := strings.TrimSuffix(name, ".md")
	if !bytes.Contains(observed[0].output, []byte(showName+" [Devin] always-on")) {
		t.Fatalf("actual pinned rules list receipt omitted selected always-on rule: %q", observed[0].output)
	}
	showOutput := observed[1].output
	for _, field := range [][]byte{
		[]byte("Rule: " + showName),
		[]byte("Path: " + strconv.Quote(filepath.Join(observed[1].home, ".devin", "rules", name))),
		[]byte("Provider: Devin"), []byte("Activation: always-on"),
		[]byte("NATIVE_PRODUCTION_SELECTED_RULE_BODY"), []byte("Provider: literal"),
	} {
		if !bytes.Contains(showOutput, field) {
			t.Fatalf("actual pinned rules show receipt omitted %q: %q", field, showOutput)
		}
	}
	entries, err := os.ReadDir(sessionsDirectory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("VerifyDevin retained its Session after rules/auth probes: entries=%v err=%v", entries, err)
	}
}

func profileOverlay() profile.OverlayPayload { return profile.OverlayPayload{Version: 1} }

func equalArguments(actual []string, expected ...string) bool {
	if len(actual) != len(expected) {
		return false
	}
	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}
	return true
}
