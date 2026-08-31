package codexauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func TestRegistryDefersPrivateWorkspaceRejectionToContainedOperations(t *testing.T) {
	root := t.TempDir()
	acsHome := filepath.Join(root, "acs")
	workspace := filepath.Join(acsHome, "quarantine")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	registry, err := New(Config{
		BinaryPath: "/usr/bin/true", ACSHome: acsHome,
		SessionsDirectory: filepath.Join(acsHome, "sessions"), WorkingDirectory: workspace,
	})
	if err != nil {
		t.Fatalf("registry construction rejected current directory overlap: %v", err)
	}
	if _, err := registry.login.Prepare(context.Background()); !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("contained login preparation error = %v", err)
	}
	if _, err := registry.status.Prepare(context.Background()); !errors.Is(err, ErrStatusFailed) {
		t.Fatalf("contained status preparation error = %v", err)
	}
}

func TestRegistryRejectsLinkedPrivateAncestorsWithoutChangingTheirTargets(t *testing.T) {
	for _, ancestor := range []string{"locks", "quarantine"} {
		t.Run(ancestor, func(t *testing.T) {
			root := t.TempDir()
			acsHome := filepath.Join(root, "acs")
			if err := os.Mkdir(acsHome, 0o700); err != nil {
				t.Fatal(err)
			}
			workspace := filepath.Join(root, "workspace")
			if err := os.Mkdir(workspace, 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(workspace, ancestor+"-target")
			if err := os.Mkdir(target, 0o755); err != nil {
				t.Fatal(err)
			}
			sentinel := filepath.Join(target, "sentinel")
			if err := os.WriteFile(sentinel, []byte("unchanged"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(acsHome, ancestor)); err != nil {
				t.Fatal(err)
			}

			_, err := New(Config{
				BinaryPath: "/usr/bin/true", ACSHome: acsHome,
				SessionsDirectory: filepath.Join(acsHome, "sessions"), WorkingDirectory: workspace,
			})
			if err == nil {
				t.Fatal("linked private ancestor was accepted")
			}
			contents, readErr := os.ReadFile(sentinel)
			if readErr != nil || string(contents) != "unchanged" {
				t.Fatalf("linked target contents = (%q, %v)", contents, readErr)
			}
			info, statErr := os.Stat(target)
			if statErr != nil || info.Mode().Perm() != 0o755 {
				t.Fatalf("linked target mode = (%v, %v)", info, statErr)
			}
			if _, statErr := os.Stat(filepath.Join(target, "codex-auth")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("linked target received private child: %v", statErr)
			}
		})
	}
}

func TestRegistriesDoNotShareOwnershipAcrossCanonicalACSHomeReplacement(t *testing.T) {
	root := t.TempDir()
	ancestor := filepath.Join(root, "canonical")
	acsHome := filepath.Join(ancestor, "acs")
	workspace := filepath.Join(root, "workspace")
	if err := os.MkdirAll(ancestor, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	config := Config{
		BinaryPath: "/usr/bin/true", ACSHome: acsHome,
		SessionsDirectory: filepath.Join(acsHome, "sessions"), WorkingDirectory: workspace,
	}
	oldRegistry, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(root, "canonical-detached")
	if err := os.Rename(ancestor, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(ancestor, 0o700); err != nil {
		t.Fatal(err)
	}
	newRegistry, err := New(config)
	if err != nil {
		t.Fatalf("replacement registry: %v", err)
	}

	if locked, err := oldRegistry.locks.TryLock("work"); !errors.Is(err, ErrProviderUnavailable) || locked != nil {
		t.Fatalf("detached registry lock = (%v, %v)", locked, err)
	}
	marker := quarantineMarker{
		Version: recordVersion, Name: "work", SessionID: "session-replacement",
		Phase: quarantinePrepared, ProofChallenge: strings.Repeat("b", 64),
	}
	if err := oldRegistry.quarantine.Create(context.Background(), marker); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("detached registry marker error = %v", err)
	}
	for _, path := range []string{
		filepath.Join(moved, "acs", "locks", "codex-auth", "work.lock"),
		filepath.Join(moved, "acs", "quarantine", "codex-auth", "work.json"),
		filepath.Join(acsHome, "locks", "codex-auth", "work.lock"),
		filepath.Join(acsHome, "quarantine", "codex-auth", "work.json"),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("detached registry wrote %q: %v", path, err)
		}
	}

	locked, err := newRegistry.locks.TryLock("work")
	if err != nil {
		t.Fatalf("replacement registry lock: %v", err)
	}
	if err := locked.Release(); err != nil {
		t.Fatal(err)
	}
	if err := newRegistry.quarantine.Create(context.Background(), marker); err != nil {
		t.Fatalf("replacement registry marker: %v", err)
	}
	if got, exists, err := newRegistry.quarantine.Inspect(context.Background(), "work"); err != nil || !exists || got != marker {
		t.Fatalf("replacement registry ownership = (%#v, %v, %v)", got, exists, err)
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

func TestRegistryRecoverWaitsForRecoverableSettlementLockHandoff(t *testing.T) {
	provider := newFakeProvider()
	cleanupDone := make(chan struct{})
	runner := &fakeLoginRunner{
		result: loginRunResult{containedRunResult: containedRunResult{
			err: ErrLoginCleanupUncertain, cleanupProven: false,
		}},
		cleanupDone: cleanupDone,
	}
	underlyingLocks := newFileIdentityLocker(t.TempDir())
	lockContention := make(chan struct{})
	registry, err := newRegistry(provider, runner, &busySignalingIdentityLocker{
		identityLocker: underlyingLocks,
		busy:           lockContention,
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionsDirectory := configureRegistryTestLifecycle(t, registry)
	markedRecoverable := make(chan struct{})
	releaseSettlement := make(chan struct{})
	registry.quarantine = &recoverableHandoffQuarantine{
		bindingQuarantine: registry.quarantine,
		marked:            markedRecoverable,
		release:           releaseSettlement,
	}

	if _, err := registry.Login(context.Background(), LoginRequest{Name: "work"}); !errors.Is(err, ErrLoginCleanupUncertain) {
		t.Fatalf("login error = %v", err)
	}
	close(cleanupDone)
	select {
	case <-markedRecoverable:
	case <-time.After(time.Second):
		t.Fatal("asynchronous settlement did not publish recoverable phase")
	}

	type recoveryResult struct {
		disposition BindingDisposition
		err         error
	}
	result := make(chan recoveryResult, 1)
	go func() {
		disposition, err := registry.Recover(context.Background(), "work")
		result <- recoveryResult{disposition: disposition, err: err}
	}()
	select {
	case <-lockContention:
	case <-time.After(time.Second):
		t.Fatal("recovery did not contend with settlement lock")
	}
	close(releaseSettlement)
	recovered := <-result
	if recovered.err != nil || recovered.disposition != DiscardedProjection {
		t.Fatalf("handoff recovery = (%q, %v)", recovered.disposition, recovered.err)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestRegistryRecoverWaitsOnlyForTheObservedRecoverableGeneration(t *testing.T) {
	for _, phase := range []quarantinePhase{quarantinePrepared, quarantineCleanupPending} {
		t.Run(string(phase)+" contention remains busy", func(t *testing.T) {
			registry, err := newRegistry(newFakeProvider(), &fakeLoginRunner{}, newFileIdentityLocker(t.TempDir()))
			if err != nil {
				t.Fatal(err)
			}
			configureRegistryTestLifecycle(t, registry)
			if err := registry.quarantine.Create(context.Background(), quarantineMarker{
				Version: recordVersion, Name: "work", SessionID: "session-contended",
				Phase: phase, ProofChallenge: testCleanupProofChallenge,
			}); err != nil {
				t.Fatal(err)
			}
			held, err := registry.locks.TryLock("work")
			if err != nil {
				t.Fatal(err)
			}
			defer held.Release()

			disposition, err := registry.Recover(context.Background(), "work")
			if !errors.Is(err, ErrIdentityBusy) || disposition != "" {
				t.Fatalf("contended %s recovery = (%q, %v)", phase, disposition, err)
			}
		})
	}

	t.Run("recoverable contention respects cancellation", func(t *testing.T) {
		registry, err := newRegistry(newFakeProvider(), &fakeLoginRunner{}, newFileIdentityLocker(t.TempDir()))
		if err != nil {
			t.Fatal(err)
		}
		configureRegistryTestLifecycle(t, registry)
		if err := registry.quarantine.Create(context.Background(), quarantineMarker{
			Version: recordVersion, Name: "work", SessionID: "session-contended",
			Phase: quarantineRecoverable, ProofChallenge: testCleanupProofChallenge,
		}); err != nil {
			t.Fatal(err)
		}
		held, err := registry.locks.TryLock("work")
		if err != nil {
			t.Fatal(err)
		}
		defer held.Release()
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		disposition, err := registry.Recover(ctx, "work")
		if !errors.Is(err, context.Canceled) || disposition != "" {
			t.Fatalf("canceled recovery = (%q, %v)", disposition, err)
		}
	})

	t.Run("removed recoverable generation is idempotent", func(t *testing.T) {
		underlyingLocks := newFileIdentityLocker(t.TempDir())
		registry, err := newRegistry(newFakeProvider(), &fakeLoginRunner{}, underlyingLocks)
		if err != nil {
			t.Fatal(err)
		}
		configureRegistryTestLifecycle(t, registry)
		underlyingQuarantine := registry.quarantine
		observedRecoverable := make(chan struct{})
		continueRecovery := make(chan struct{})
		registry.quarantine = &recoverableInspectGate{
			bindingQuarantine: underlyingQuarantine,
			observed:          observedRecoverable,
			proceed:           continueRecovery,
		}
		if err := registry.quarantine.Create(context.Background(), quarantineMarker{
			Version: recordVersion, Name: "work", SessionID: "session-contended",
			Phase: quarantineRecoverable, ProofChallenge: testCleanupProofChallenge,
		}); err != nil {
			t.Fatal(err)
		}
		held, err := underlyingLocks.TryLock("work")
		if err != nil {
			t.Fatal(err)
		}
		type recoveryResult struct {
			disposition BindingDisposition
			err         error
		}
		result := make(chan recoveryResult, 1)
		go func() {
			disposition, err := registry.Recover(context.Background(), "work")
			result <- recoveryResult{disposition: disposition, err: err}
		}()
		select {
		case <-observedRecoverable:
		case <-time.After(time.Second):
			t.Fatal("recovery did not observe recoverable contention")
		}
		if err := underlyingQuarantine.Delete(context.Background(), "work"); err != nil {
			t.Fatal(err)
		}
		close(continueRecovery)
		if err := held.Release(); err != nil {
			t.Fatal(err)
		}
		recovered := <-result
		if recovered.err != nil || recovered.disposition != DiscardedProjection {
			t.Fatalf("removed generation recovery = (%q, %v)", recovered.disposition, recovered.err)
		}
	})

	t.Run("replacement generation remains blocked", func(t *testing.T) {
		underlyingLocks := newFileIdentityLocker(t.TempDir())
		registry, err := newRegistry(newFakeProvider(), &fakeLoginRunner{}, underlyingLocks)
		if err != nil {
			t.Fatal(err)
		}
		configureRegistryTestLifecycle(t, registry)
		underlyingQuarantine := registry.quarantine
		observedRecoverable := make(chan struct{})
		continueRecovery := make(chan struct{})
		registry.quarantine = &recoverableInspectGate{
			bindingQuarantine: underlyingQuarantine,
			observed:          observedRecoverable,
			proceed:           continueRecovery,
		}
		original := quarantineMarker{
			Version: recordVersion, Name: "work", SessionID: "session-original",
			Phase: quarantineRecoverable, ProofChallenge: testCleanupProofChallenge,
		}
		if err := registry.quarantine.Create(context.Background(), original); err != nil {
			t.Fatal(err)
		}
		held, err := underlyingLocks.TryLock("work")
		if err != nil {
			t.Fatal(err)
		}
		type recoveryResult struct {
			disposition BindingDisposition
			err         error
		}
		result := make(chan recoveryResult, 1)
		go func() {
			disposition, err := registry.Recover(context.Background(), "work")
			result <- recoveryResult{disposition: disposition, err: err}
		}()
		select {
		case <-observedRecoverable:
		case <-time.After(time.Second):
			t.Fatal("recovery did not observe original recoverable generation")
		}
		if err := underlyingQuarantine.Delete(context.Background(), "work"); err != nil {
			t.Fatal(err)
		}
		replacement := quarantineMarker{
			Version: recordVersion, Name: "work", SessionID: "session-replacement",
			Phase: quarantinePrepared, ProofChallenge: strings.Repeat("a", 64),
		}
		if err := underlyingQuarantine.Create(context.Background(), replacement); err != nil {
			t.Fatal(err)
		}
		close(continueRecovery)
		if err := held.Release(); err != nil {
			t.Fatal(err)
		}
		recovered := <-result
		if !errors.Is(recovered.err, ErrIdentityBusy) || recovered.disposition != QuarantinedUncertain {
			t.Fatalf("replacement generation recovery = (%q, %v)", recovered.disposition, recovered.err)
		}
		marker, exists, err := registry.quarantine.Inspect(context.Background(), "work")
		if err != nil || !exists || marker != replacement {
			t.Fatalf("replacement marker = (%#v, %v, %v)", marker, exists, err)
		}
	})
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

type busySignalingIdentityLocker struct {
	identityLocker
	busy chan struct{}
	once sync.Once
}

func (locker *busySignalingIdentityLocker) TryLock(name CredentialRef) (identityLock, error) {
	locked, err := locker.identityLocker.TryLock(name)
	if errors.Is(err, ErrIdentityBusy) {
		locker.once.Do(func() { close(locker.busy) })
	}
	return locked, err
}

type recoverableHandoffQuarantine struct {
	bindingQuarantine
	marked  chan struct{}
	release chan struct{}
}

type recoverableInspectGate struct {
	bindingQuarantine
	observed chan struct{}
	proceed  chan struct{}
	once     sync.Once
}

func (store *recoverableInspectGate) Inspect(
	ctx context.Context,
	name CredentialRef,
) (quarantineMarker, bool, error) {
	marker, exists, err := store.bindingQuarantine.Inspect(ctx, name)
	if err == nil && exists && marker.Phase == quarantineRecoverable {
		store.once.Do(func() {
			close(store.observed)
			<-store.proceed
		})
	}
	return marker, exists, err
}

func (store *recoverableHandoffQuarantine) MarkRecoverable(ctx context.Context, name CredentialRef) error {
	if err := store.bindingQuarantine.MarkRecoverable(ctx, name); err != nil {
		return err
	}
	close(store.marked)
	<-store.release
	return nil
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

func (runner *fakeLoginRunner) Prepare(context.Context) (loginPreparation, error) {
	return loginPreparation{run: runner.Run}, nil
}

func (runner *fakeLoginRunner) Run(
	_ context.Context,
	created *session.Session,
	_ string,
	beginProcess func() error,
	deviceAuth bool,
	_ launch.Terminal,
) loginRunResult {
	if beginProcess != nil {
		if err := beginProcess(); err != nil {
			return loginRunResult{containedRunResult: containedRunResult{
				err: ErrLoginFailed, cleanupProven: true,
			}}
		}
	}
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
