package codexauth

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

func TestStatusProjectsOneIdentityAndDiscardsUnchangedCredential(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, provider, runner, sessionsDirectory := newBindingTestRegistry(t, "work", auth)

	status, err := registry.Status(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	if status.Disposition != DiscardedProjection || status.Metadata.Name != "work" {
		t.Fatalf("status = %#v", status)
	}
	if provider.replaceCalls != 0 {
		t.Fatalf("unchanged status replaced credential %d times", provider.replaceCalls)
	}
	for _, line := range []string{
		`cli_auth_credentials_store = "file"`,
		`forced_login_method = "chatgpt"`,
		`forced_chatgpt_workspace_id = "workspace"`,
	} {
		if !strings.Contains(runner.configuration, line) {
			t.Errorf("configuration omits %q: %q", line, runner.configuration)
		}
	}
	assertNoSessionDirectories(t, sessionsDirectory)
	if _, exists, err := registry.quarantine.Inspect(context.Background(), "work"); err != nil || exists {
		t.Fatalf("quarantine after success = (%v, %v)", exists, err)
	}
}

func TestStatusFailsBeforeSessionCreationWhenIdentityOrSandboxIsUnavailable(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	t.Run("missing identity", func(t *testing.T) {
		registry, provider, runner, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
		if err := provider.Delete(context.Background(), "work"); err != nil {
			t.Fatal(err)
		}
		if _, err := registry.Status(context.Background(), "work"); !errors.Is(err, ErrIdentityNotFound) {
			t.Fatalf("status error = %v", err)
		}
		if runner.checkCalls != 0 {
			t.Fatalf("missing identity ran %d sandbox checks", runner.checkCalls)
		}
		if _, err := os.Stat(sessionsDirectory); !os.IsNotExist(err) {
			t.Fatalf("missing identity created Sessions directory: %v", err)
		}
	})
	t.Run("sandbox check", func(t *testing.T) {
		registry, _, runner, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
		runner.checkErr = ErrStatusFailed
		if _, err := registry.Status(context.Background(), "work"); !errors.Is(err, ErrStatusFailed) {
			t.Fatalf("status error = %v", err)
		}
		if runner.checkCalls != 1 {
			t.Fatalf("sandbox checks = %d", runner.checkCalls)
		}
		if _, err := os.Stat(sessionsDirectory); !os.IsNotExist(err) {
			t.Fatalf("failed sandbox check created Sessions directory: %v", err)
		}
	})
}

func TestStatusCommitsOnlySameIdentityRefresh(t *testing.T) {
	original := testChatGPTAuthJSON(t, "user", "workspace")
	refreshed := []byte(strings.Replace(
		string(original), "2026-08-29T12:34:56Z", "2026-08-29T13:34:56Z", 1,
	))
	registry, provider, runner, _ := newBindingTestRegistry(t, "work", original)
	runner.mutate = func(home string) error {
		return os.WriteFile(filepath.Join(home, ".codex", "auth.json"), refreshed, 0o600)
	}

	status, err := registry.Status(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	if status.Disposition != CommittedSameIdentityRefresh || provider.replaceCalls != 1 {
		t.Fatalf("status = %#v, replacements = %d", status, provider.replaceCalls)
	}
	if got := provider.records["work"].Auth; string(got) != string(refreshed) {
		t.Fatal("durable credential was not refreshed")
	}
}

func TestStatusRejectsIdentityChangeAndProjectedDeletion(t *testing.T) {
	original := testChatGPTAuthJSON(t, "user", "workspace")
	tests := []struct {
		name   string
		mutate func(string) error
	}{
		{
			name: "identity change",
			mutate: func(home string) error {
				return os.WriteFile(
					filepath.Join(home, ".codex", "auth.json"),
					testChatGPTAuthJSON(t, "other-user", "workspace"), 0o600,
				)
			},
		},
		{
			name: "projected deletion",
			mutate: func(home string) error {
				return os.Remove(filepath.Join(home, ".codex", "auth.json"))
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			registry, provider, runner, sessionsDirectory := newBindingTestRegistry(t, "work", original)
			runner.mutate = test.mutate
			status, err := registry.Status(context.Background(), "work")
			if !errors.Is(err, ErrProjectedAuthInvalid) || status.Disposition != DiscardedProjection {
				t.Fatalf("status = (%#v, %v)", status, err)
			}
			if provider.replaceCalls != 0 || string(provider.records["work"].Auth) != string(original) {
				t.Fatal("invalid projection changed durable credential")
			}
			assertNoSessionDirectories(t, sessionsDirectory)
		})
	}
}

func TestStatusFailureDiscardsProjectionWithoutChangingDurableCredential(t *testing.T) {
	original := testChatGPTAuthJSON(t, "user", "workspace")
	registry, provider, runner, sessionsDirectory := newBindingTestRegistry(t, "work", original)
	runner.result = statusRunResult{err: ErrStatusFailed, cleanupProven: true}

	status, err := registry.Status(context.Background(), "work")
	if !errors.Is(err, ErrStatusFailed) || status.Disposition != DiscardedProjection {
		t.Fatalf("status = (%#v, %v)", status, err)
	}
	if provider.replaceCalls != 0 || string(provider.records["work"].Auth) != string(original) {
		t.Fatal("failed status changed durable credential")
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestStatusDoesNotExposeTargetDiagnosticsOrCredentialBytes(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, _, runner, _ := newBindingTestRegistry(t, "work", auth)
	runner.result = statusRunResult{
		err: errors.New("target printed refresh-secret and access-secret"), cleanupProven: true,
	}

	_, err := registry.Status(context.Background(), "work")
	if !errors.Is(err, ErrStatusFailed) {
		t.Fatalf("status error = %v", err)
	}
	for _, secret := range []string{"refresh-secret", "access-secret"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("status error exposed %q: %v", secret, err)
		}
	}
}

func TestStatusQuarantinesReplacementFailureAndRecoveryCommitsOnce(t *testing.T) {
	original := testChatGPTAuthJSON(t, "user", "workspace")
	refreshed := []byte(strings.Replace(
		string(original), "2026-08-29T12:34:56Z", "2026-08-29T14:34:56Z", 1,
	))
	registry, provider, runner, sessionsDirectory := newBindingTestRegistry(t, "work", original)
	runner.mutate = func(home string) error {
		return os.WriteFile(filepath.Join(home, ".codex", "auth.json"), refreshed, 0o600)
	}
	provider.replaceErr = ErrProviderUnavailable

	status, err := registry.Status(context.Background(), "work")
	if !errors.Is(err, ErrBindingQuarantined) || status.Disposition != QuarantinedUncertain {
		t.Fatalf("status = (%#v, %v)", status, err)
	}
	marker, exists, err := registry.quarantine.Inspect(context.Background(), "work")
	if err != nil || !exists {
		t.Fatalf("quarantine marker = (%v, %v)", exists, err)
	}
	concurrent, err := session.Create(sessionsDirectory, registry.workingDirectory, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := concurrent.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(sessionsDirectory, marker.SessionID)); err != nil {
		t.Fatalf("startup cleanup removed quarantined Session: %v", err)
	}
	if _, err := registry.Status(context.Background(), "work"); !errors.Is(err, ErrIdentityBusy) {
		t.Fatalf("quarantined identity status error = %v", err)
	}
	provider.replaceErr = nil
	disposition, err := registry.Recover(context.Background(), "work")
	if err != nil || disposition != CommittedSameIdentityRefresh {
		t.Fatalf("recovery = (%q, %v)", disposition, err)
	}
	if provider.replaceCalls != 2 {
		t.Fatalf("replacement attempts = %d, want 2", provider.replaceCalls)
	}
	if got := provider.records["work"].Auth; string(got) != string(refreshed) {
		t.Fatal("recovery did not commit refresh")
	}
	assertNoSessionDirectories(t, sessionsDirectory)
	if _, exists, err := registry.quarantine.Inspect(context.Background(), "work"); err != nil || exists {
		t.Fatalf("quarantine after recovery = (%v, %v)", exists, err)
	}
}

func TestStatusCleanupUncertaintyWithoutSettlementProofRemainsBlocked(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, _, runner, _ := newBindingTestRegistry(t, "work", auth)
	runner.result = statusRunResult{err: ErrBindingQuarantined, cleanupProven: false}

	status, err := registry.Status(context.Background(), "work")
	if !errors.Is(err, ErrBindingQuarantined) || status.Disposition != QuarantinedUncertain {
		t.Fatalf("status = (%#v, %v)", status, err)
	}
	disposition, err := registry.Recover(context.Background(), "work")
	if !errors.Is(err, ErrIdentityBusy) || disposition != QuarantinedUncertain {
		t.Fatalf("recovery = (%q, %v)", disposition, err)
	}
	disposition, err = registry.Recover(context.Background(), "work")
	if !errors.Is(err, ErrIdentityBusy) || disposition != QuarantinedUncertain {
		t.Fatalf("repeated recovery = (%q, %v)", disposition, err)
	}
}

func TestStatusCleanupUncertaintyPreservesProjectionUntilSettlementAndRecovery(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, _, _, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	cleanupDone := make(chan struct{})
	runner := &pendingCleanupStatusRunner{cleanupDone: cleanupDone}
	registry.status = runner

	status, err := registry.Status(context.Background(), "work")
	if !errors.Is(err, ErrBindingQuarantined) || status.Disposition != QuarantinedUncertain {
		t.Fatalf("status = (%#v, %v)", status, err)
	}
	marker, exists, err := registry.quarantine.Inspect(context.Background(), "work")
	if err != nil || !exists || marker.Phase != quarantineCleanupPending {
		t.Fatalf("pending quarantine marker = (%#v, %v, %v)", marker, exists, err)
	}
	if _, err := os.Stat(runner.sessionRoot); err != nil {
		t.Fatalf("pending cleanup removed projection: %v", err)
	}
	if disposition, err := registry.Recover(context.Background(), "work"); !errors.Is(err, ErrIdentityBusy) || disposition != QuarantinedUncertain {
		t.Fatalf("pending recovery = (%q, %v)", disposition, err)
	}

	close(cleanupDone)
	deadline := time.Now().Add(time.Second)
	for {
		marker, exists, err = registry.quarantine.Inspect(context.Background(), "work")
		if err == nil && exists && marker.Phase == quarantineRecoverable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("quarantine did not become recoverable: (%#v, %v, %v)", marker, exists, err)
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := os.Stat(runner.sessionRoot); err != nil {
		t.Fatalf("settled quarantine removed projection: %v", err)
	}
	disposition, err := registry.Recover(context.Background(), "work")
	if err != nil || disposition != DiscardedProjection {
		t.Fatalf("settled recovery = (%q, %v)", disposition, err)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestAsyncCleanupCannotTransitionANewerMarkerGeneration(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, _, _, _ := newBindingTestRegistry(t, "work", auth)
	underlying := registry.locks
	gate := &asyncCleanupLockGate{
		identityLocker: underlying,
		entered:        make(chan struct{}),
		release:        make(chan struct{}),
		completed:      make(chan struct{}),
	}
	registry.locks = gate
	cleanupDone := make(chan struct{})
	registry.status = &pendingCleanupStatusRunner{cleanupDone: cleanupDone}
	registry.verifyCleanup = func(string, []byte) (bool, error) { return true, nil }

	status, err := registry.Status(context.Background(), "work")
	if !errors.Is(err, ErrBindingQuarantined) || status.Disposition != QuarantinedUncertain {
		t.Fatalf("status = (%#v, %v)", status, err)
	}
	close(cleanupDone)
	select {
	case <-gate.entered:
	case <-time.After(time.Second):
		t.Fatal("asynchronous cleanup did not reacquire the identity lock")
	}
	if disposition, err := registry.Recover(context.Background(), "work"); err != nil || disposition != DiscardedProjection {
		t.Fatalf("explicit recovery = (%q, %v)", disposition, err)
	}
	newMarker := quarantineMarker{
		Version: recordVersion, Name: "work", SessionID: "session-new-generation",
		Phase: quarantinePrepared, ProofChallenge: strings.Repeat("a", 64),
	}
	if err := registry.quarantine.Create(context.Background(), newMarker); err != nil {
		t.Fatalf("create new generation: %v", err)
	}
	close(gate.release)
	select {
	case <-gate.completed:
	case <-time.After(time.Second):
		t.Fatal("asynchronous cleanup did not finish its generation check")
	}
	marker, exists, err := registry.quarantine.Inspect(context.Background(), "work")
	if err != nil || !exists || marker != newMarker {
		t.Fatalf("new marker after old completion = (%#v, %v, %v)", marker, exists, err)
	}
}

func TestRecoveryNeverCommitsRefreshAfterFailedStatus(t *testing.T) {
	original := testChatGPTAuthJSON(t, "user", "workspace")
	refreshed := []byte(strings.Replace(
		string(original), "2026-08-29T12:34:56Z", "2026-08-29T16:34:56Z", 1,
	))
	registry, provider, _, sessionsDirectory := newBindingTestRegistry(t, "work", original)
	cleanupDone := make(chan struct{})
	runner := &pendingCleanupStatusRunner{
		cleanupDone: cleanupDone,
		mutate: func(home string) error {
			return os.WriteFile(filepath.Join(home, ".codex", "auth.json"), refreshed, 0o600)
		},
	}
	registry.status = runner

	status, err := registry.Status(context.Background(), "work")
	if !errors.Is(err, ErrBindingQuarantined) || status.Disposition != QuarantinedUncertain {
		t.Fatalf("failed status = (%#v, %v)", status, err)
	}
	marker, exists, err := registry.quarantine.Inspect(context.Background(), "work")
	if err != nil || !exists || marker.RefreshAllowed {
		t.Fatalf("failed status marker = (%#v, %v, %v)", marker, exists, err)
	}
	close(cleanupDone)
	deadline := time.Now().Add(time.Second)
	for {
		marker, exists, err = registry.quarantine.Inspect(context.Background(), "work")
		if err == nil && exists && marker.Phase == quarantineRecoverable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("failed status did not become recoverable: (%#v, %v, %v)", marker, exists, err)
		}
		time.Sleep(time.Millisecond)
	}
	disposition, err := registry.Recover(context.Background(), "work")
	if err != nil || disposition != DiscardedProjection {
		t.Fatalf("failed status recovery = (%q, %v)", disposition, err)
	}
	if provider.replaceCalls != 0 || string(provider.records["work"].Auth) != string(original) {
		t.Fatal("failed status recovery committed projected refresh")
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestStatusPublishedMarkerFailurePreservesRecoverableSession(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, _, runner, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	store := registry.quarantine
	registry.quarantine = createErrorAfterPublishQuarantine{bindingQuarantine: store}

	status, err := registry.Status(context.Background(), "work")
	if !errors.Is(err, ErrBindingQuarantined) || status.Disposition != QuarantinedUncertain {
		t.Fatalf("status = (%#v, %v)", status, err)
	}
	if runner.checkCalls != 1 {
		t.Fatalf("sandbox checks = %d", runner.checkCalls)
	}
	marker, exists, err := registry.quarantine.Inspect(context.Background(), "work")
	if err != nil || !exists || marker.Phase != quarantineRecoverable {
		t.Fatalf("recoverable marker = (%#v, %v, %v)", marker, exists, err)
	}
	disposition, err := registry.Recover(context.Background(), "work")
	if err != nil || disposition != DiscardedProjection {
		t.Fatalf("recovery = (%q, %v)", disposition, err)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestRecoveryRefusesAnActiveProtectedSession(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, _, _, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	created, err := session.Create(sessionsDirectory, registry.workingDirectory, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.ProtectForRecovery(); err != nil {
		t.Fatal(err)
	}
	if err := registry.quarantine.Create(context.Background(), quarantineMarker{
		Version: recordVersion, Name: "work", SessionID: filepath.Base(created.RootDirectory()),
		Phase: quarantineRecoverable, ProofChallenge: testCleanupProofChallenge,
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = created.Remove()
		_ = registry.quarantine.Delete(context.Background(), "work")
	})

	disposition, err := registry.Recover(context.Background(), "work")
	if !errors.Is(err, ErrIdentityBusy) || disposition != QuarantinedUncertain {
		t.Fatalf("active recovery = (%q, %v)", disposition, err)
	}
}

func TestRecoveryAcceptsSupervisorProofForInactivePendingSession(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, _, _, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	created, err := session.Create(sessionsDirectory, t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.ProtectForRecovery(); err != nil {
		t.Fatal(err)
	}
	metadata, err := validateAuthJSON("work", auth)
	if err != nil {
		t.Fatal(err)
	}
	if err := projectCredential(created.HomeDirectory(), credentialRecord{Metadata: metadata, Auth: auth}); err != nil {
		t.Fatal(err)
	}
	if err := registry.quarantine.Create(context.Background(), quarantineMarker{
		Version: recordVersion, Name: "work", SessionID: filepath.Base(created.RootDirectory()),
		Phase: quarantineCleanupPending, ProofChallenge: testCleanupProofChallenge,
	}); err != nil {
		t.Fatal(err)
	}
	if err := created.PreserveForRecovery(); err != nil {
		t.Fatal(err)
	}
	registry.verifyCleanup = func(root string, challenge []byte) (bool, error) {
		if root != created.RootDirectory() {
			t.Fatalf("proof root = %q", root)
		}
		if got := fmt.Sprintf("%x", challenge); got != testCleanupProofChallenge {
			t.Fatalf("proof challenge = %q", got)
		}
		return true, nil
	}

	disposition, err := registry.Recover(context.Background(), "work")
	if err != nil || disposition != DiscardedProjection {
		t.Fatalf("recovery = (%q, %v)", disposition, err)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestRecoveryAcceptsPreparedProofWhenCrashPrecedesFirstProcess(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, _, _, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	created, err := session.Create(sessionsDirectory, registry.workingDirectory, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.ProtectForRecovery(); err != nil {
		t.Fatal(err)
	}
	metadata, err := validateAuthJSON("work", auth)
	if err != nil {
		t.Fatal(err)
	}
	if err := projectCredential(created.HomeDirectory(), credentialRecord{Metadata: metadata, Auth: auth}); err != nil {
		t.Fatal(err)
	}
	challenge, err := hex.DecodeString(testCleanupProofChallenge)
	if err != nil {
		t.Fatal(err)
	}
	if err := launch.PrepareSessionCleanupProof(created.RootDirectory(), challenge); err != nil {
		t.Fatal(err)
	}
	if err := registry.quarantine.Create(context.Background(), quarantineMarker{
		Version: recordVersion, Name: "work", SessionID: filepath.Base(created.RootDirectory()),
		Phase: quarantineCleanupPending, ProofChallenge: testCleanupProofChallenge,
	}); err != nil {
		t.Fatal(err)
	}
	if err := created.PreserveForRecovery(); err != nil {
		t.Fatal(err)
	}

	disposition, err := registry.Recover(context.Background(), "work")
	if err != nil || disposition != DiscardedProjection {
		t.Fatalf("pre-process recovery = (%q, %v)", disposition, err)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestRecoveryDiscardsInactivePreparedSessionWithoutSupervisorProof(t *testing.T) {
	original := testChatGPTAuthJSON(t, "user", "workspace")
	refreshed := []byte(strings.Replace(
		string(original), "2026-08-29T12:34:56Z", "2026-08-29T15:34:56Z", 1,
	))
	registry, provider, _, sessionsDirectory := newBindingTestRegistry(t, "work", original)
	created, err := session.Create(sessionsDirectory, registry.workingDirectory, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.ProtectForRecovery(); err != nil {
		t.Fatal(err)
	}
	metadata, err := validateAuthJSON("work", refreshed)
	if err != nil {
		t.Fatal(err)
	}
	if err := projectCredential(created.HomeDirectory(), credentialRecord{Metadata: metadata, Auth: refreshed}); err != nil {
		t.Fatal(err)
	}
	if err := registry.quarantine.Create(context.Background(), quarantineMarker{
		Version: recordVersion, Name: "work", SessionID: filepath.Base(created.RootDirectory()),
		Phase: quarantinePrepared, ProofChallenge: testCleanupProofChallenge,
	}); err != nil {
		t.Fatal(err)
	}
	if err := created.PreserveForRecovery(); err != nil {
		t.Fatal(err)
	}
	registry.verifyCleanup = func(string, []byte) (bool, error) {
		t.Fatal("prepared recovery requested a supervisor proof")
		return false, nil
	}

	disposition, err := registry.Recover(context.Background(), "work")
	if err != nil || disposition != DiscardedProjection {
		t.Fatalf("prepared recovery = (%q, %v)", disposition, err)
	}
	if provider.replaceCalls != 0 || string(provider.records["work"].Auth) != string(original) {
		t.Fatal("prepared recovery committed projected bytes")
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestRecoveryClearsPendingMarkerAfterSessionIsAlreadyGone(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, _, _, _ := newBindingTestRegistry(t, "work", auth)
	if err := registry.quarantine.Create(context.Background(), quarantineMarker{
		Version: recordVersion, Name: "work", SessionID: "session-already-gone",
		Phase: quarantineCleanupPending, ProofChallenge: testCleanupProofChallenge,
	}); err != nil {
		t.Fatal(err)
	}

	disposition, err := registry.Recover(context.Background(), "work")
	if err != nil || disposition != DiscardedProjection {
		t.Fatalf("recovery = (%q, %v)", disposition, err)
	}
	if _, exists, err := registry.quarantine.Inspect(context.Background(), "work"); err != nil || exists {
		t.Fatalf("marker after recovery = (%v, %v)", exists, err)
	}
}

func TestRecoveryDiscardsAnIdentityChangingProjection(t *testing.T) {
	original := testChatGPTAuthJSON(t, "user", "workspace")
	registry, provider, _, sessionsDirectory := newBindingTestRegistry(t, "work", original)
	created, err := session.Create(sessionsDirectory, registry.workingDirectory, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.ProtectForRecovery(); err != nil {
		t.Fatal(err)
	}
	record, exists, err := provider.Load(context.Background(), "work")
	if err != nil || !exists {
		t.Fatalf("load = (%v, %v)", exists, err)
	}
	if err := projectCredential(created.HomeDirectory(), record); err != nil {
		t.Fatal(err)
	}
	clearBytes(record.Auth)
	if err := os.WriteFile(
		filepath.Join(created.HomeDirectory(), ".codex", "auth.json"),
		testChatGPTAuthJSON(t, "other-user", "workspace"), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	if err := registry.quarantine.Create(context.Background(), quarantineMarker{
		Version: recordVersion, Name: "work", SessionID: filepath.Base(created.RootDirectory()),
		Phase: quarantineRecoverable, ProofChallenge: testCleanupProofChallenge,
	}); err != nil {
		t.Fatal(err)
	}
	if err := created.PreserveForRecovery(); err != nil {
		t.Fatal(err)
	}

	disposition, err := registry.Recover(context.Background(), "work")
	if err != nil || disposition != DiscardedProjection {
		t.Fatalf("recovery = (%q, %v)", disposition, err)
	}
	if provider.replaceCalls != 0 || string(provider.records["work"].Auth) != string(original) {
		t.Fatal("identity-changing recovery changed durable credential")
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestStatusSerializesTheSameIdentityThroughFinalization(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, _, runner, _ := newBindingTestRegistry(t, "work", auth)
	runner.started = make(chan struct{}, 1)
	runner.release = make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := registry.Status(context.Background(), "work")
		result <- err
	}()
	<-runner.started
	if _, err := registry.Status(context.Background(), "work"); !errors.Is(err, ErrIdentityBusy) {
		t.Fatalf("concurrent status error = %v", err)
	}
	close(runner.release)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestStatusAllowsDifferentIdentitiesToRunConcurrently(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user-work", "workspace")
	registry, provider, runner, _ := newBindingTestRegistry(t, "work", auth)
	personalAuth := testChatGPTAuthJSON(t, "user-personal", "workspace")
	personalMetadata, err := validateAuthJSON("personal", personalAuth)
	if err != nil {
		t.Fatal(err)
	}
	provider.records["personal"] = credentialRecord{Metadata: personalMetadata, Auth: personalAuth}
	runner.started = make(chan struct{}, 2)
	runner.release = make(chan struct{})
	results := make(chan error, 2)
	for _, name := range []string{"work", "personal"} {
		go func() {
			_, err := registry.Status(context.Background(), name)
			results <- err
		}()
	}
	for range 2 {
		select {
		case <-runner.started:
		case <-time.After(time.Second):
			t.Fatal("different identities did not reach status concurrently")
		}
	}
	close(runner.release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
}

func newBindingTestRegistry(
	t *testing.T,
	name CredentialRef,
	auth []byte,
) (*Registry, *fakeProvider, *fakeStatusRunner, string) {
	t.Helper()
	root := t.TempDir()
	workingDirectory := filepath.Join(root, "workspace")
	if err := os.Mkdir(workingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	provider := newFakeProvider()
	metadata, err := validateAuthJSON(name, auth)
	if err != nil {
		t.Fatal(err)
	}
	provider.records[name] = credentialRecord{Metadata: metadata, Auth: append([]byte(nil), auth...)}
	registry, err := newRegistry(provider, &fakeLoginRunner{}, newFileIdentityLocker(filepath.Join(root, "locks")))
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeStatusRunner{result: statusRunResult{cleanupProven: true}}
	registry.status = runner
	registry.quarantine = newFileBindingQuarantine(filepath.Join(root, "quarantine"))
	registry.sessionsDirectory = filepath.Join(root, "sessions")
	registry.workingDirectory = workingDirectory
	return registry, provider, runner, registry.sessionsDirectory
}

type fakeStatusRunner struct {
	mutex         sync.Mutex
	checkErr      error
	checkCalls    int
	result        statusRunResult
	mutate        func(string) error
	configuration string
	started       chan struct{}
	release       chan struct{}
}

type pendingCleanupStatusRunner struct {
	cleanupDone chan struct{}
	sessionRoot string
	mutate      func(string) error
}

type asyncCleanupLockGate struct {
	identityLocker
	mutex     sync.Mutex
	calls     int
	entered   chan struct{}
	release   chan struct{}
	completed chan struct{}
}

func (gate *asyncCleanupLockGate) TryLock(name CredentialRef) (identityLock, error) {
	gate.mutex.Lock()
	gate.calls++
	call := gate.calls
	gate.mutex.Unlock()
	if call == 2 {
		close(gate.entered)
		<-gate.release
	}
	locked, err := gate.identityLocker.TryLock(name)
	if err != nil || call != 2 {
		return locked, err
	}
	return &completionSignalingIdentityLock{identityLock: locked, completed: gate.completed}, nil
}

type completionSignalingIdentityLock struct {
	identityLock
	completed chan struct{}
}

func (locked *completionSignalingIdentityLock) Release() error {
	err := locked.identityLock.Release()
	close(locked.completed)
	return err
}

type createErrorAfterPublishQuarantine struct{ bindingQuarantine }

func (store createErrorAfterPublishQuarantine) Create(ctx context.Context, marker quarantineMarker) error {
	if err := store.bindingQuarantine.Create(ctx, marker); err != nil {
		return err
	}
	return ErrBindingQuarantined
}

func (runner *pendingCleanupStatusRunner) Prepare(context.Context) (statusPreparation, error) {
	return statusPreparation{run: runner.Run}, nil
}

func (runner *pendingCleanupStatusRunner) Run(
	_ context.Context,
	created *session.Session,
	_, _ string,
	beginProcess func() error,
) statusRunResult {
	if beginProcess != nil {
		if err := beginProcess(); err != nil {
			return statusRunResult{err: ErrStatusFailed, cleanupProven: true}
		}
	}
	if runner.mutate != nil {
		if err := runner.mutate(created.HomeDirectory()); err != nil {
			return statusRunResult{err: ErrStatusFailed, cleanupProven: true}
		}
	}
	runner.sessionRoot = created.RootDirectory()
	process, err := created.RetainUntilProcessDone(pendingCleanupProcess{done: runner.cleanupDone})
	if err != nil {
		return statusRunResult{err: ErrBindingQuarantined, cleanupProven: false}
	}
	if err := launch.RunAttached(process); err != nil {
		return statusRunResult{err: ErrBindingQuarantined, cleanupProven: false, cleanupProcess: process}
	}
	return statusRunResult{err: ErrBindingQuarantined, cleanupProven: false, cleanupProcess: process}
}

type pendingCleanupProcess struct{ done <-chan struct{} }

func (pendingCleanupProcess) Start() error                         { return nil }
func (pendingCleanupProcess) Wait() error                          { return nil }
func (pendingCleanupProcess) Signal(os.Signal) error               { return nil }
func (process pendingCleanupProcess) CleanupDone() <-chan struct{} { return process.done }

func (runner *fakeStatusRunner) Check(context.Context) error {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	runner.checkCalls++
	return runner.checkErr
}

func (runner *fakeStatusRunner) Prepare(ctx context.Context) (statusPreparation, error) {
	if err := runner.Check(ctx); err != nil {
		return statusPreparation{}, err
	}
	return statusPreparation{run: runner.Run}, nil
}

func (runner *fakeStatusRunner) Run(
	_ context.Context,
	created *session.Session,
	_, _ string,
	beginProcess func() error,
) statusRunResult {
	if beginProcess != nil {
		if err := beginProcess(); err != nil {
			return statusRunResult{err: ErrStatusFailed, cleanupProven: true}
		}
	}
	configuration, err := os.ReadFile(filepath.Join(created.HomeDirectory(), ".codex", "config.toml"))
	if err != nil {
		return statusRunResult{err: ErrStatusFailed, cleanupProven: true}
	}
	runner.mutex.Lock()
	runner.configuration = string(configuration)
	runner.mutex.Unlock()
	if runner.mutate != nil {
		if err := runner.mutate(created.HomeDirectory()); err != nil {
			return statusRunResult{err: ErrStatusFailed, cleanupProven: true}
		}
	}
	if runner.started != nil {
		runner.started <- struct{}{}
	}
	if runner.release != nil {
		<-runner.release
	}
	return runner.result
}

func assertNoSessionDirectories(t *testing.T, sessionsDirectory string) {
	t.Helper()
	entries, err := os.ReadDir(sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("Session directories remain: %#v", entries)
	}
}
