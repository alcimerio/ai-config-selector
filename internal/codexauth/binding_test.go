package codexauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestStatusCleanupUncertaintyLeavesMarkerForIdempotentRecovery(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	registry, _, runner, sessionsDirectory := newBindingTestRegistry(t, "work", auth)
	runner.result = statusRunResult{err: ErrBindingQuarantined, cleanupProven: false}

	status, err := registry.Status(context.Background(), "work")
	if !errors.Is(err, ErrBindingQuarantined) || status.Disposition != QuarantinedUncertain {
		t.Fatalf("status = (%#v, %v)", status, err)
	}
	disposition, err := registry.Recover(context.Background(), "work")
	if err != nil || disposition != DiscardedProjection {
		t.Fatalf("recovery = (%q, %v)", disposition, err)
	}
	disposition, err = registry.Recover(context.Background(), "work")
	if err != nil || disposition != DiscardedProjection {
		t.Fatalf("idempotent recovery = (%q, %v)", disposition, err)
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

func (runner *fakeStatusRunner) Check(context.Context) error {
	runner.mutex.Lock()
	defer runner.mutex.Unlock()
	runner.checkCalls++
	return runner.checkErr
}

func (runner *fakeStatusRunner) Run(_ context.Context, created *session.Session) statusRunResult {
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
