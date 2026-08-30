package codexauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

func TestRegistryLoginCreatesWithoutReplacingNamedIdentity(t *testing.T) {
	provider := newFakeProvider()
	runner := &fakeLoginRunner{result: loginRunResult{
		auth:               testChatGPTAuthJSON(t, "user", "workspace"),
		containedRunResult: containedRunResult{cleanupProven: true},
	}}
	registry, err := newRegistry(provider, runner, newFileIdentityLocker(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	configureRegistryTestLifecycle(t, registry)

	metadata, err := registry.Login(context.Background(), LoginRequest{Name: "work"})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Name != "work" || runner.calls != 1 {
		t.Fatalf("metadata = %#v, login calls = %d", metadata, runner.calls)
	}
	if _, err := registry.Login(context.Background(), LoginRequest{Name: "work"}); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("duplicate login error = %v", err)
	}
	if runner.calls != 1 {
		t.Fatalf("duplicate login invoked Codex: calls = %d", runner.calls)
	}
}

func TestRegistryRejectsWorkspaceThatCouldReadRecoveryChallenges(t *testing.T) {
	root := t.TempDir()
	acsHome := filepath.Join(root, "acs")
	workspace := filepath.Join(acsHome, "quarantine")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := New(Config{
		BinaryPath: "/usr/bin/true", ACSHome: acsHome,
		SessionsDirectory: filepath.Join(acsHome, "sessions"), WorkingDirectory: workspace,
	})
	if err == nil {
		t.Fatal("workspace inside ACS home was accepted")
	}
}

func TestRegistryLoginCleanupUncertaintyQuarantinesNameAndProjection(t *testing.T) {
	provider := newFakeProvider()
	cleanupDone := make(chan struct{})
	runner := &fakeLoginRunner{
		result: loginRunResult{containedRunResult: containedRunResult{
			err: ErrLoginCleanupUncertain, cleanupProven: false,
		}},
		cleanupDone: cleanupDone,
	}
	registry, err := newRegistry(provider, runner, newFileIdentityLocker(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	sessionsDirectory := configureRegistryTestLifecycle(t, registry)

	if _, err := registry.Login(context.Background(), LoginRequest{Name: "work"}); !errors.Is(err, ErrLoginCleanupUncertain) {
		t.Fatalf("login error = %v", err)
	}
	marker, exists, err := registry.quarantine.Inspect(context.Background(), "work")
	if err != nil || !exists || marker.Phase != quarantineCleanupPending {
		t.Fatalf("pending quarantine marker = (%#v, %v, %v)", marker, exists, err)
	}
	if _, exists, err := provider.Metadata(context.Background(), "work"); err != nil || exists {
		t.Fatalf("uncertain login stored identity = (%v, %v)", exists, err)
	}
	if _, err := os.Stat(runner.sessionRoot); err != nil {
		t.Fatalf("pending login removed projection: %v", err)
	}
	if _, err := registry.Login(context.Background(), LoginRequest{Name: "work"}); !errors.Is(err, ErrIdentityBusy) {
		t.Fatalf("quarantined login retry error = %v", err)
	}

	close(cleanupDone)
	deadline := time.Now().Add(time.Second)
	for {
		marker, exists, err = registry.quarantine.Inspect(context.Background(), "work")
		if err == nil && exists && marker.Phase == quarantineRecoverable {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("login quarantine did not become recoverable: (%#v, %v, %v)", marker, exists, err)
		}
		time.Sleep(time.Millisecond)
	}
	disposition, err := registry.Recover(context.Background(), "work")
	if err != nil || disposition != DiscardedProjection {
		t.Fatalf("login recovery = (%q, %v)", disposition, err)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestRegistryLoginPublishedMarkerFailurePreservesRecoverableSession(t *testing.T) {
	provider := newFakeProvider()
	runner := &fakeLoginRunner{result: loginRunResult{
		auth:               testChatGPTAuthJSON(t, "user", "workspace"),
		containedRunResult: containedRunResult{cleanupProven: true},
	}}
	registry, err := newRegistry(provider, runner, newFileIdentityLocker(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	sessionsDirectory := configureRegistryTestLifecycle(t, registry)
	registry.quarantine = createErrorAfterPublishQuarantine{bindingQuarantine: registry.quarantine}

	if _, err := registry.Login(context.Background(), LoginRequest{Name: "work"}); !errors.Is(err, ErrLoginCleanupUncertain) {
		t.Fatalf("login error = %v", err)
	}
	if runner.calls != 0 {
		t.Fatalf("published marker failure ran login %d times", runner.calls)
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

func TestRegistryLoginPublishedMarkerTransitionFailureRemovesUnstartedSession(t *testing.T) {
	provider := newFakeProvider()
	runner := &fakeLoginRunner{result: loginRunResult{
		auth:               testChatGPTAuthJSON(t, "user", "workspace"),
		containedRunResult: containedRunResult{cleanupProven: true},
	}}
	registry, err := newRegistry(provider, runner, newFileIdentityLocker(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	sessionsDirectory := configureRegistryTestLifecycle(t, registry)
	registry.quarantine = createAndTransitionErrorQuarantine{bindingQuarantine: registry.quarantine}

	if _, err := registry.Login(context.Background(), LoginRequest{Name: "work"}); !errors.Is(err, ErrLoginCleanupUncertain) {
		t.Fatalf("login error = %v", err)
	}
	if runner.calls != 0 {
		t.Fatalf("published marker failure ran login %d times", runner.calls)
	}
	if _, exists, err := registry.quarantine.Inspect(context.Background(), "work"); err != nil || exists {
		t.Fatalf("marker after rollback = (%v, %v)", exists, err)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestRegistryListUsesMetadataOnlyAndSortsNames(t *testing.T) {
	provider := newFakeProvider()
	for _, name := range []CredentialRef{"work", "personal"} {
		auth := testChatGPTAuthJSON(t, "user-"+string(name), "workspace")
		metadata, err := validateAuthJSON(name, auth)
		if err != nil {
			t.Fatal(err)
		}
		provider.records[name] = credentialRecord{Metadata: metadata, Auth: auth}
	}
	registry, _ := newRegistry(provider, &fakeLoginRunner{}, newFileIdentityLocker(t.TempDir()))
	identities, err := registry.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []CredentialRef{"personal", "work"}
	got := []CredentialRef{identities[0].Name, identities[1].Name}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("names = %q, want %q", got, want)
	}
	if provider.loadCalls != 0 {
		t.Fatalf("list retrieved credential payload %d times", provider.loadCalls)
	}
}

func TestRegistryLogoutIsIdempotentAndHonorsIdentityLock(t *testing.T) {
	locks := newFileIdentityLocker(t.TempDir())
	provider := newFakeProvider()
	registry, _ := newRegistry(provider, &fakeLoginRunner{}, locks)

	held, err := locks.TryLock("work")
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Logout(context.Background(), "work"); !errors.Is(err, ErrIdentityBusy) {
		t.Fatalf("busy logout error = %v", err)
	}
	if err := held.Release(); err != nil {
		t.Fatal(err)
	}
	if err := registry.Logout(context.Background(), "work"); err != nil {
		t.Fatalf("absent logout: %v", err)
	}
}

type fakeLoginRunner struct {
	result      loginRunResult
	calls       int
	deviceAuth  bool
	cleanupDone chan struct{}
	sessionRoot string
}

type createAndTransitionErrorQuarantine struct{ bindingQuarantine }

func (store createAndTransitionErrorQuarantine) Create(ctx context.Context, marker quarantineMarker) error {
	if err := store.bindingQuarantine.Create(ctx, marker); err != nil {
		return err
	}
	return ErrBindingQuarantined
}

func (createAndTransitionErrorQuarantine) MarkRecoverable(context.Context, CredentialRef) error {
	return ErrBindingQuarantined
}

func (*fakeLoginRunner) Check(context.Context) error { return nil }

func (runner *fakeLoginRunner) Run(
	_ context.Context,
	created *session.Session,
	_ string,
	deviceAuth bool,
	_ launch.Terminal,
) loginRunResult {
	runner.calls++
	runner.deviceAuth = deviceAuth
	result := runner.result
	result.auth = append([]byte(nil), result.auth...)
	if runner.cleanupDone != nil {
		runner.sessionRoot = created.RootDirectory()
		process, err := created.RetainUntilProcessDone(pendingCleanupProcess{done: runner.cleanupDone})
		if err != nil {
			return loginRunResult{containedRunResult: containedRunResult{
				err: ErrLoginCleanupUncertain, cleanupProven: false,
			}}
		}
		_ = launch.RunAttached(process)
		result.cleanupProcess = process
	}
	return result
}

func configureRegistryTestLifecycle(t *testing.T, registry *Registry) string {
	t.Helper()
	root := t.TempDir()
	workingDirectory := filepath.Join(root, "workspace")
	if err := os.Mkdir(workingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	registry.sessionsDirectory = filepath.Join(root, "sessions")
	registry.workingDirectory = workingDirectory
	registry.quarantine = newFileBindingQuarantine(filepath.Join(root, "quarantine"))
	return registry.sessionsDirectory
}

type fakeProvider struct {
	mutex        sync.Mutex
	records      map[CredentialRef]credentialRecord
	loadCalls    int
	replaceCalls int
	replaceErr   error
}

func newFakeProvider() *fakeProvider {
	return &fakeProvider{records: make(map[CredentialRef]credentialRecord)}
}

func (provider *fakeProvider) Metadata(_ context.Context, name CredentialRef) (IdentityMetadata, bool, error) {
	provider.mutex.Lock()
	defer provider.mutex.Unlock()
	record, exists := provider.records[name]
	return record.Metadata, exists, nil
}

func (provider *fakeProvider) Create(_ context.Context, record credentialRecord) error {
	provider.mutex.Lock()
	defer provider.mutex.Unlock()
	if _, exists := provider.records[record.Metadata.Name]; exists {
		return ErrIdentityExists
	}
	record.Auth = append([]byte(nil), record.Auth...)
	provider.records[record.Metadata.Name] = record
	return nil
}

func (provider *fakeProvider) Replace(_ context.Context, record credentialRecord) error {
	provider.mutex.Lock()
	defer provider.mutex.Unlock()
	provider.replaceCalls++
	if provider.replaceErr != nil {
		return provider.replaceErr
	}
	if _, exists := provider.records[record.Metadata.Name]; !exists {
		return ErrIdentityNotFound
	}
	record.Auth = append([]byte(nil), record.Auth...)
	provider.records[record.Metadata.Name] = record
	return nil
}

func (provider *fakeProvider) List(context.Context) ([]IdentityMetadata, error) {
	provider.mutex.Lock()
	defer provider.mutex.Unlock()
	result := make([]IdentityMetadata, 0, len(provider.records))
	for _, record := range provider.records {
		result = append(result, record.Metadata)
	}
	return result, nil
}

func (provider *fakeProvider) Load(_ context.Context, name CredentialRef) (credentialRecord, bool, error) {
	provider.mutex.Lock()
	defer provider.mutex.Unlock()
	provider.loadCalls++
	record, exists := provider.records[name]
	record.Auth = append([]byte(nil), record.Auth...)
	return record, exists, nil
}

func (provider *fakeProvider) Delete(_ context.Context, name CredentialRef) error {
	provider.mutex.Lock()
	defer provider.mutex.Unlock()
	delete(provider.records, name)
	return nil
}
