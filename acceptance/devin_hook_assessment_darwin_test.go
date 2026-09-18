//go:build darwin

package acceptance_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func seedDevinSessionStartHook(home, workspace, hookPath, receiptPath string) error {
	if filepath.Dir(hookPath) != workspace || filepath.Dir(receiptPath) != workspace {
		return errors.New("hook assessment paths escaped workspace")
	}
	hooks := map[string]any{"SessionStart": []any{map[string]any{"matcher": "", "hooks": []any{map[string]any{"type": "command", "command": devinShellLiteral(hookPath), "timeout": 2}}}}}
	data, err := json.Marshal(hooks)
	if err != nil {
		return err
	}
	dir := filepath.Join(workspace, ".devin")
	if err = os.Mkdir(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "hooks.v1.json"), data, 0600)
}

func TestPromotedArtifactNativeDevinSessionStartHook(t *testing.T) {
	if os.Getenv("ACS_RUN_NATIVE_DEVIN_HOOK_ASSESSMENT") != "1" {
		if os.Getenv("ACS_RUN_NATIVE_DEVIN_HOOK_ASSESSMENT") != "" {
			t.Fatal("invalid hook assessment opt-in")
		}
		t.Skip("explicit hook assessment gate required")
	}
	receipt := ""
	diagnostic := ""
	invoked := ""
	var expected devinHookReceiptExpected
	var first devinHookReceiptSnapshot
	assembleNativeDevinProofWithOptions(t, devinNativeInput, verifyDevinListing, &devinNativeAssessmentOptions{
		seed: func(home, workspace, hookPath, path string) error {
			receipt = path
			diagnostic = path + ".diagnostic"
			invoked = path + ".invoked"
			return seedDevinSessionStartHook(home, workspace, hookPath, path)
		},
		beforeFirstInput: func() error {
			if receipt == "" {
				return errors.New("hook receipt path not initialized")
			}
			var err error
			first, err = readDevinHookReceipt(receipt, expected, nil)
			if err != nil {
				code, diagnosticErr := readHookFixedMarker(diagnostic)
				if diagnosticErr == nil {
					return fmt.Errorf("hook witness fixed failure=%s: %w", code, err)
				}
				var diagnosticMissing devinHookMarkerLeafPending
				if !errors.As(diagnosticErr, &diagnosticMissing) {
					return errors.New("hook diagnostic marker unsafe")
				}
				_, invokedErr := readHookFixedMarker(invoked)
				var invokedMissing devinHookMarkerLeafPending
				if invokedErr != nil && !errors.As(invokedErr, &invokedMissing) {
					return errors.New("hook invocation marker unsafe")
				}
				if devinHookReceiptGateDecision(err, diagnosticErr, invokedErr) == "pending" {
					return devinHookReceiptPending{}
				}
				if invokedErr == nil {
					return fmt.Errorf("hook witness invoked without receipt: %w", err)
				}
				return err
			}
			// This checks only absence of the receipt's claimed PID after a synchronous
			// hook. It is not ProcessVerified, ancestry, or natural-exit evidence.
			return waitDevinClaimedHookPIDAbsent(first.Receipt.PID)
		},
		verify: func() error {
			return verifyDevinHookReceiptUnchanged(receipt, expected, first)
		},
		onBuilt: func(hookPath, inputPath string) error {
			executableDigest, err := devinHookFileDigest(hookPath, 64<<20)
			if err != nil {
				return err
			}
			inputDigest, err := devinHookFileDigest(inputPath, 1<<20)
			if err != nil {
				return err
			}
			expected.Executable = hookPath
			expected.ExecutableSHA256 = executableDigest
			expected.InputSHA256 = inputDigest
			return nil
		},
		onPhase: func(phase string, r devinPhaseReceipt) error {
			if phase != "attached" {
				return nil
			}
			if expected.ExecutableSHA256 == "" || expected.SessionHome != "" {
				return errors.New("hook expectation phase invalid")
			}
			// Invoked only after base observer validates the actual attached Session.
			expected.SessionHome = r.SessionHome
			return nil
		},
	})
}

func waitDevinClaimedHookPIDAbsent(pid int) error {
	if pid <= 1 {
		return errors.New("hook claimed PID invalid")
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		e := syscall.Kill(pid, 0)
		if errors.Is(e, syscall.ESRCH) {
			return nil
		}
		if e != nil {
			return errors.New("hook claimed PID absence unavailable")
		}
		if time.Now().After(deadline) {
			return errors.New("hook claimed PID still present")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
