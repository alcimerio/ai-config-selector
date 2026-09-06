package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

func TestRegistryLoginCreatesWithoutReplacingNamedIdentity(t *testing.T) {
	provider := newFakeProvider()
	runner := &fakeLoginRunner{auth: testChatGPTAuthJSON(t, "user", "workspace"), result: loginRunResult{
		containedRunResult: containedRunResult{cleanupProven: true},
	}}
	registry, err := newRegistry(provider, runner, newFileIdentityLocker(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	configureRegistryTestLifecycle(t, registry)

	metadata, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"})
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Name != "work" || runner.calls != 1 {
		t.Fatalf("metadata = %#v, login calls = %d", metadata, runner.calls)
	}
	if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("duplicate login error = %v", err)
	}
	if runner.calls != 1 {
		t.Fatalf("duplicate login invoked Codex: calls = %d", runner.calls)
	}
	if runner.prepareCalls != 1 {
		t.Fatalf("duplicate login prepared executable: calls = %d", runner.prepareCalls)
	}
}

func TestRegistryLoginPreservesRecoveryForInvalidPreparedProcess(t *testing.T) {
	for _, test := range invalidPreparedProcessCases() {
		t.Run(test.name, func(t *testing.T) {
			provider := newFakeProvider()
			registry, err := newRegistry(provider, &fakeLoginRunner{}, newFileIdentityLocker(t.TempDir()))
			if err != nil {
				t.Fatal(err)
			}
			sessions := configureRegistryTestLifecycle(t, registry)
			sandbox := &invalidPreparedProcessSandbox{typedNil: test.typedNil}
			registry.login = newCodexLoginRunner(codexLoginConfig{
				BinaryPath: "/usr/bin/true", SupportedVersion: SupportedCodexVersion,
				SessionsDirectory: sessions, WorkingDirectory: registry.workingDirectory,
			}, sandbox)

			if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); !errors.Is(err, ErrLoginCleanupUncertain) {
				t.Fatalf("Login error = %v, want cleanup uncertainty", err)
			}
			if sandbox.prepares != 1 {
				t.Fatalf("prepare calls = %d, want 1", sandbox.prepares)
			}
			marker, exists, err := registryTestResources(registry).quarantine.Inspect(context.Background(), "work")
			if err != nil || !exists || marker.Phase != quarantineCleanupPending {
				t.Fatalf("pending marker = (%#v, %v, %v)", marker, exists, err)
			}
			if _, err := os.Stat(filepath.Join(sessions, marker.SessionID)); err != nil {
				t.Fatalf("invalid prepared process lost protected projection: %v", err)
			}
			if _, exists, err := provider.Metadata(context.Background(), "work"); err != nil || exists {
				t.Fatalf("invalid prepared process committed Login = (%v, %v)", exists, err)
			}
		})
	}
}

func TestRegistryDefersPrivateWorkspaceRejectionToContainedOperations(t *testing.T) {
	root := t.TempDir()
	acsHome := filepath.Join(root, "acs")
	workspace := filepath.Join(acsHome, "quarantine")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	registry, err := NewCodexAuth(CodexAuthConfig{
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

func TestProductionRegistryLoginUsesResourceAcquireBeforePreparation(t *testing.T) {
	root := t.TempDir()
	registry, err := NewCodexAuth(CodexAuthConfig{
		BinaryPath:        "/usr/bin/true",
		ACSHome:           filepath.Join(root, "acs"),
		SessionsDirectory: filepath.Join(root, "sessions"),
		WorkingDirectory:  root,
	})
	if err != nil {
		t.Fatal(err)
	}
	invalidateProductionRegistryLockDirectory(t, filepath.Join(root, "acs"))
	runner := &fakeLoginRunner{}
	registry.login = runner
	if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("production resource acquisition error = %v", err)
	}
	if runner.prepareCalls != 0 {
		t.Fatalf("resource failure prepared target: calls = %d", runner.prepareCalls)
	}
}

func TestProductionRegistryRoutesStatusAndLogoutThroughResourceStore(t *testing.T) {
	root := t.TempDir()
	registry, err := NewCodexAuth(CodexAuthConfig{
		BinaryPath:        "/usr/bin/true",
		ACSHome:           filepath.Join(root, "acs"),
		SessionsDirectory: filepath.Join(root, "sessions"),
		WorkingDirectory:  root,
	})
	if err != nil {
		t.Fatal(err)
	}
	invalidateProductionRegistryLockDirectory(t, filepath.Join(root, "acs"))
	runner := &fakeStatusRunner{}
	registry.status = runner
	if _, err := registry.Status(context.Background(), "work"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("production Status resource error = %v", err)
	}
	if runner.checkCalls != 0 {
		t.Fatalf("resource failure prepared status target: calls = %d", runner.checkCalls)
	}
	if err := registry.Logout(context.Background(), "work"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("production Logout resource error = %v", err)
	}
}

func invalidateProductionRegistryLockDirectory(t *testing.T, acsHome string) {
	t.Helper()
	directory := filepath.Join(acsHome, "locks", "codex-auth")
	if err := os.Rename(directory, directory+"-detached"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryLoginProviderInspectionFailurePrecedesPreparation(t *testing.T) {
	providerFailure := errors.New("synthetic provider inspection failure")
	provider := newFakeProvider()
	provider.metadataErr = providerFailure
	runner := &fakeLoginRunner{}
	registry, err := newRegistry(provider, runner, newFileIdentityLocker(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	configureRegistryTestLifecycle(t, registry)

	if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); !errors.Is(err, providerFailure) {
		t.Fatalf("provider inspection error = %v", err)
	}
	if runner.prepareCalls != 0 {
		t.Fatalf("provider inspection failure prepared target: calls = %d", runner.prepareCalls)
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

			_, err := NewCodexAuth(CodexAuthConfig{
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

	if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); !errors.Is(err, ErrLoginCleanupUncertain) {
		t.Fatalf("login error = %v", err)
	}
	marker, exists, err := registryTestResources(registry).quarantine.Inspect(context.Background(), "work")
	if err != nil || !exists || marker.Phase != quarantineCleanupPending {
		t.Fatalf("pending quarantine marker = (%#v, %v, %v)", marker, exists, err)
	}
	if _, exists, err := provider.Metadata(context.Background(), "work"); err != nil || exists {
		t.Fatalf("uncertain login stored identity = (%v, %v)", exists, err)
	}
	if _, err := os.Stat(runner.sessionRoot); err != nil {
		t.Fatalf("pending login removed projection: %v", err)
	}
	if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); !errors.Is(err, ErrIdentityBusy) {
		t.Fatalf("quarantined login retry error = %v", err)
	}

	close(cleanupDone)
	deadline := time.Now().Add(time.Second)
	for {
		marker, exists, err = registryTestResources(registry).quarantine.Inspect(context.Background(), "work")
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

func TestRegistryLoginWithoutProcessProofPreservesOwnedProjection(t *testing.T) {
	runner := &fakeLoginRunner{result: loginRunResult{containedRunResult: containedRunResult{
		err: ErrLoginCleanupUncertain, cleanupProven: false,
	}}}
	registry, err := newRegistry(newFakeProvider(), runner, newFileIdentityLocker(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	configureRegistryTestLifecycle(t, registry)

	if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); !errors.Is(err, ErrLoginCleanupUncertain) {
		t.Fatalf("login error = %v", err)
	}
	if _, err := os.Stat(runner.sessionRoot); err != nil {
		t.Fatalf("unproven projection was not retained: %v", err)
	}
	marker, exists, err := registryTestResources(registry).quarantine.Inspect(context.Background(), "work")
	if err != nil || !exists || marker.Phase != quarantineCleanupPending {
		t.Fatalf("pending ownership = (%#v, %v, %v)", marker, exists, err)
	}
	if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); !errors.Is(err, ErrIdentityBusy) {
		t.Fatalf("pending ownership did not block reuse: %v", err)
	}
}

func TestResourcePendingTransferWaitsForLateCleanupNotification(t *testing.T) {
	root := t.TempDir()
	workingDirectory := filepath.Join(root, "workspace")
	if err := os.Mkdir(workingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	created, err := session.Create(filepath.Join(root, "sessions"), workingDirectory, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.ProtectForRecovery(); err != nil {
		t.Fatal(err)
	}
	cleanupDone := make(chan struct{})
	settled := make(chan struct{})
	binding := &lateSettlementBinding{settled: settled}
	(&CodexAuthService{}).transferResourcePendingBinding(created, binding, "challenge", lateCleanupProcess{done: cleanupDone})
	select {
	case <-settled:
		t.Fatal("pending binding settled before cleanup notification")
	case <-time.After(20 * time.Millisecond):
	}
	close(cleanupDone)
	select {
	case <-settled:
	case <-time.After(time.Second):
		t.Fatal("pending binding did not settle after late cleanup notification")
	}
}

func TestRegistryLoginProviderFailureRemovesProjectionBeforeMarker(t *testing.T) {
	providerFailure := errors.New("synthetic provider failure")
	provider := newFakeProvider()
	provider.createErr = providerFailure
	runner := &fakeLoginRunner{auth: testChatGPTAuthJSON(t, "user", "workspace"), result: loginRunResult{
		containedRunResult: containedRunResult{cleanupProven: true},
	}}
	registry, err := newRegistry(provider, runner, newFileIdentityLocker(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	sessionsDirectory := configureRegistryTestLifecycle(t, registry)
	underlyingQuarantine := registryTestResources(registry).quarantine
	order := &projectionRemovalOrderQuarantine{bindingQuarantine: underlyingQuarantine, sessionsDirectory: sessionsDirectory}
	registryTestResources(registry).quarantine = order
	releaseOrder := &cleanupReleaseOrder{
		sessionsDirectory: sessionsDirectory,
		markerAbsent: func() bool {
			_, exists, inspectErr := underlyingQuarantine.Inspect(context.Background(), "work")
			return inspectErr == nil && !exists
		},
	}
	registryTestResources(registry).locks = releaseOrderLocker{identityLocker: registryTestResources(registry).locks, order: releaseOrder}

	if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); !errors.Is(err, providerFailure) {
		t.Fatalf("provider failure = %v", err)
	}
	if !order.deletedAfterProjection {
		t.Fatal("marker deletion preceded physical projection removal")
	}
	if !releaseOrder.releasedAfterCleanup {
		t.Fatal("identity unlock preceded projection or marker cleanup")
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestRegistryLoginUnsupportedAuthRemovesProjectionAndDoesNotCreate(t *testing.T) {
	provider := newFakeProvider()
	runner := &fakeLoginRunner{auth: []byte(`{"auth_mode":"api_key","OPENAI_API_KEY":"secret"}`), result: loginRunResult{
		containedRunResult: containedRunResult{cleanupProven: true},
	}}
	registry, err := newRegistry(provider, runner, newFileIdentityLocker(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	sessionsDirectory := configureRegistryTestLifecycle(t, registry)

	if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); err != ErrUnsupportedAuth {
		t.Fatalf("unsupported auth error = %v", err)
	}
	if provider.createCalls != 0 {
		t.Fatalf("unsupported auth create calls = %d", provider.createCalls)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestRegistryLoginContainedFailureRemovesProjectionAndDoesNotCreate(t *testing.T) {
	provider := newFakeProvider()
	runner := &fakeLoginRunner{result: loginRunResult{containedRunResult: containedRunResult{
		err: ErrLoginFailed, cleanupProven: true,
	}}}
	registry, err := newRegistry(provider, runner, newFileIdentityLocker(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	sessionsDirectory := configureRegistryTestLifecycle(t, registry)

	if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); err != ErrLoginFailed {
		t.Fatalf("contained failure = %v", err)
	}
	if provider.createCalls != 0 {
		t.Fatalf("contained failure create calls = %d", provider.createCalls)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestRegistryLoginMarkerRemovalFailureRetainsQuarantineAfterPhysicalCleanup(t *testing.T) {
	provider := newFakeProvider()
	runner := &fakeLoginRunner{auth: testChatGPTAuthJSON(t, "user", "workspace"), result: loginRunResult{
		containedRunResult: containedRunResult{cleanupProven: true},
	}}
	registry, err := newRegistry(provider, runner, newFileIdentityLocker(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	sessionsDirectory := configureRegistryTestLifecycle(t, registry)
	underlying := registryTestResources(registry).quarantine
	registryTestResources(registry).quarantine = deleteFailureQuarantine{bindingQuarantine: underlying}

	if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); !errors.Is(err, ErrLoginCleanupUncertain) {
		t.Fatalf("marker removal error = %v", err)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
	marker, exists, err := underlying.Inspect(context.Background(), "work")
	if err != nil || !exists || marker.Phase != quarantineRecoverable {
		t.Fatalf("retained cleanup marker = (%#v, %v, %v)", marker, exists, err)
	}
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
	registryTestResources(registry).quarantine = &recoverableHandoffQuarantine{
		bindingQuarantine: registryTestResources(registry).quarantine,
		marked:            markedRecoverable,
		release:           releaseSettlement,
	}

	if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); !errors.Is(err, ErrLoginCleanupUncertain) {
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
			if err := registryTestResources(registry).quarantine.Create(context.Background(), quarantineMarker{
				Version: recordVersion, Name: "work", SessionID: "session-contended",
				Phase: phase, ProofChallenge: testCleanupProofChallenge,
			}); err != nil {
				t.Fatal(err)
			}
			held, err := registryTestResources(registry).locks.TryLock("work")
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
		if err := registryTestResources(registry).quarantine.Create(context.Background(), quarantineMarker{
			Version: recordVersion, Name: "work", SessionID: "session-contended",
			Phase: quarantineRecoverable, ProofChallenge: testCleanupProofChallenge,
		}); err != nil {
			t.Fatal(err)
		}
		held, err := registryTestResources(registry).locks.TryLock("work")
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
		underlyingQuarantine := registryTestResources(registry).quarantine
		observedRecoverable := make(chan struct{})
		continueRecovery := make(chan struct{})
		registryTestResources(registry).quarantine = &recoverableInspectGate{
			bindingQuarantine: underlyingQuarantine,
			observed:          observedRecoverable,
			proceed:           continueRecovery,
		}
		if err := registryTestResources(registry).quarantine.Create(context.Background(), quarantineMarker{
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
		underlyingQuarantine := registryTestResources(registry).quarantine
		observedRecoverable := make(chan struct{})
		continueRecovery := make(chan struct{})
		registryTestResources(registry).quarantine = &recoverableInspectGate{
			bindingQuarantine: underlyingQuarantine,
			observed:          observedRecoverable,
			proceed:           continueRecovery,
		}
		original := quarantineMarker{
			Version: recordVersion, Name: "work", SessionID: "session-original",
			Phase: quarantineRecoverable, ProofChallenge: testCleanupProofChallenge,
		}
		if err := registryTestResources(registry).quarantine.Create(context.Background(), original); err != nil {
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
		marker, exists, err := registryTestResources(registry).quarantine.Inspect(context.Background(), "work")
		if err != nil || !exists || marker != replacement {
			t.Fatalf("replacement marker = (%#v, %v, %v)", marker, exists, err)
		}
	})
}

func TestRegistryLoginPublishedMarkerFailurePreservesRecoverableSession(t *testing.T) {
	provider := newFakeProvider()
	runner := &fakeLoginRunner{auth: testChatGPTAuthJSON(t, "user", "workspace"), result: loginRunResult{
		containedRunResult: containedRunResult{cleanupProven: true},
	}}
	registry, err := newRegistry(provider, runner, newFileIdentityLocker(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	sessionsDirectory := configureRegistryTestLifecycle(t, registry)
	registryTestResources(registry).quarantine = createErrorAfterPublishQuarantine{bindingQuarantine: registryTestResources(registry).quarantine}

	if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); !errors.Is(err, ErrLoginCleanupUncertain) {
		t.Fatalf("login error = %v", err)
	}
	if runner.calls != 0 {
		t.Fatalf("published marker failure ran login %d times", runner.calls)
	}
	marker, exists, err := registryTestResources(registry).quarantine.Inspect(context.Background(), "work")
	if err != nil || !exists || marker.Phase != quarantineRecoverable {
		t.Fatalf("recoverable marker = (%#v, %v, %v)", marker, exists, err)
	}
	disposition, err := registry.Recover(context.Background(), "work")
	if err != nil || disposition != DiscardedProjection {
		t.Fatalf("recovery = (%q, %v)", disposition, err)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestRegistryLoginUnpublishedMarkerFailurePreservesOriginalError(t *testing.T) {
	registry, err := newRegistry(newFakeProvider(), &fakeLoginRunner{}, newFileIdentityLocker(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	sessionsDirectory := configureRegistryTestLifecycle(t, registry)
	registryTestResources(registry).quarantine = createFailureQuarantine{bindingQuarantine: registryTestResources(registry).quarantine}

	if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); err != ErrProviderUnavailable {
		t.Fatalf("unpublished marker error = %v", err)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestRegistryLoginPublishedMarkerTransitionFailureRetainsRecoverableSession(t *testing.T) {
	provider := newFakeProvider()
	runner := &fakeLoginRunner{auth: testChatGPTAuthJSON(t, "user", "workspace"), result: loginRunResult{
		containedRunResult: containedRunResult{cleanupProven: true},
	}}
	registry, err := newRegistry(provider, runner, newFileIdentityLocker(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	sessionsDirectory := configureRegistryTestLifecycle(t, registry)
	registryTestResources(registry).quarantine = createAndTransitionErrorQuarantine{bindingQuarantine: registryTestResources(registry).quarantine}

	if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); !errors.Is(err, ErrLoginCleanupUncertain) {
		t.Fatalf("login error = %v", err)
	}
	if runner.calls != 0 {
		t.Fatalf("published marker failure ran login %d times", runner.calls)
	}
	marker, exists, err := registryTestResources(registry).quarantine.Inspect(context.Background(), "work")
	if err != nil || !exists || marker.Phase != quarantinePrepared {
		t.Fatalf("retained marker = (%#v, %v, %v)", marker, exists, err)
	}
	disposition, err := registry.Recover(context.Background(), "work")
	if err != nil || disposition != DiscardedProjection {
		t.Fatalf("prepared recovery = (%q, %v)", disposition, err)
	}
	assertNoSessionDirectories(t, sessionsDirectory)
}

func TestRegistryLoginUncertainMarkerInspectionNeverDeletesPossiblePublication(t *testing.T) {
	registry, err := newRegistry(newFakeProvider(), &fakeLoginRunner{}, newFileIdentityLocker(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	sessionsDirectory := configureRegistryTestLifecycle(t, registry)
	underlying := registryTestResources(registry).quarantine
	registryTestResources(registry).quarantine = &inspectErrorAfterPublishQuarantine{bindingQuarantine: underlying}

	if _, err := registry.Login(context.Background(), CodexLoginRequest{Name: "work"}); !errors.Is(err, ErrLoginCleanupUncertain) {
		t.Fatalf("login error = %v", err)
	}
	entries, err := os.ReadDir(sessionsDirectory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("preserved Sessions = (%d, %v)", len(entries), err)
	}
	marker, exists, err := underlying.Inspect(context.Background(), "work")
	if err != nil || !exists || marker.Phase != quarantinePrepared {
		t.Fatalf("possible publication = (%#v, %v, %v)", marker, exists, err)
	}
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
	auth         []byte
	result       loginRunResult
	prepareCalls int
	calls        int
	deviceAuth   bool
	cleanupDone  chan struct{}
	sessionRoot  string
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

type createFailureQuarantine struct{ bindingQuarantine }

type deleteFailureQuarantine struct{ bindingQuarantine }

func (deleteFailureQuarantine) Delete(context.Context, CredentialRef) error {
	return ErrProviderUnavailable
}

func (createFailureQuarantine) Create(context.Context, quarantineMarker) error {
	return ErrProviderUnavailable
}

type projectionRemovalOrderQuarantine struct {
	bindingQuarantine
	sessionsDirectory      string
	deletedAfterProjection bool
}

type cleanupReleaseOrder struct {
	sessionsDirectory    string
	markerAbsent         func() bool
	releasedAfterCleanup bool
}

type releaseOrderLocker struct {
	identityLocker
	order *cleanupReleaseOrder
}

func (locker releaseOrderLocker) TryLock(name CredentialRef) (identityLock, error) {
	locked, err := locker.identityLocker.TryLock(name)
	if err != nil {
		return nil, err
	}
	return releaseOrderLock{identityLock: locked, order: locker.order}, nil
}

type releaseOrderLock struct {
	identityLock
	order *cleanupReleaseOrder
}

func (lock releaseOrderLock) Release() error {
	entries, err := os.ReadDir(lock.order.sessionsDirectory)
	lock.order.releasedAfterCleanup = err == nil && len(entries) == 0 && lock.order.markerAbsent()
	return lock.identityLock.Release()
}

type lateCleanupProcess struct{ done <-chan struct{} }

func (lateCleanupProcess) Start() error                         { return nil }
func (lateCleanupProcess) Wait() error                          { return nil }
func (lateCleanupProcess) Signal(os.Signal) error               { return nil }
func (process lateCleanupProcess) CleanupDone() <-chan struct{} { return process.done }

type lateSettlementBinding struct{ settled chan struct{} }

func (*lateSettlementBinding) Release() error                                        { return nil }
func (*lateSettlementBinding) PublishPrepared(context.Context, string, string) error { return nil }
func (*lateSettlementBinding) Published(context.Context, string, string) (bool, error) {
	return false, nil
}
func (*lateSettlementBinding) MarkCleanupPending(context.Context) error { return nil }
func (*lateSettlementBinding) MarkRecoverable(context.Context) error    { return nil }
func (binding *lateSettlementBinding) SettlePending(context.Context, string, string) error {
	close(binding.settled)
	return nil
}
func (*lateSettlementBinding) DeleteMarkerAfterProjectionRemoval(context.Context) error { return nil }
func (*lateSettlementBinding) CommitLogin(context.Context, string) (IdentityMetadata, error) {
	return IdentityMetadata{}, nil
}
func (*lateSettlementBinding) Project(string) error                     { return nil }
func (*lateSettlementBinding) MarkRefreshAllowed(context.Context) error { return nil }
func (*lateSettlementBinding) FinalizeStatus(context.Context, string) (codexauthresource.BindingDisposition, error) {
	return codexauthresource.DiscardedProjection, nil
}

func (store *projectionRemovalOrderQuarantine) Delete(ctx context.Context, name CredentialRef) error {
	entries, err := os.ReadDir(store.sessionsDirectory)
	store.deletedAfterProjection = err == nil && len(entries) == 0
	return store.bindingQuarantine.Delete(ctx, name)
}

type inspectErrorAfterPublishQuarantine struct {
	bindingQuarantine
	published bool
}

func (store *inspectErrorAfterPublishQuarantine) Create(ctx context.Context, marker quarantineMarker) error {
	if err := store.bindingQuarantine.Create(ctx, marker); err != nil {
		return err
	}
	store.published = true
	return ErrBindingQuarantined
}

func (store *inspectErrorAfterPublishQuarantine) Inspect(ctx context.Context, name CredentialRef) (quarantineMarker, bool, error) {
	if store.published {
		return quarantineMarker{}, false, ErrProviderUnavailable
	}
	return store.bindingQuarantine.Inspect(ctx, name)
}

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
	runner.prepareCalls++
	return loginPreparation{run: runner.Run}, nil
}

func (runner *fakeLoginRunner) Run(
	ctx context.Context,
	created *session.Session,
	_ string,
	binding loginResourceBinding,
	deviceAuth bool,
	_ launch.Terminal,
) loginRunResult {
	runner.sessionRoot = created.RootDirectory()
	if binding == nil || binding.MarkCleanupPending(ctx) != nil {
		return loginRunResult{containedRunResult: containedRunResult{
			err: ErrLoginFailed, cleanupProven: true,
		}}
	}
	runner.calls++
	runner.deviceAuth = deviceAuth
	result := runner.result
	if len(runner.auth) != 0 {
		codexHome := filepath.Join(created.HomeDirectory(), ".codex")
		if err := os.MkdirAll(codexHome, 0o700); err != nil {
			return loginRunResult{containedRunResult: containedRunResult{err: ErrLoginFailed, cleanupProven: true}}
		}
		if err := os.WriteFile(filepath.Join(codexHome, "auth.json"), runner.auth, 0o600); err != nil {
			return loginRunResult{containedRunResult: containedRunResult{err: ErrLoginFailed, cleanupProven: true}}
		}
		// The fake target writes the projection; it does not return credentials
		// to CodexAuthService.Login.
	}
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

func configureRegistryTestLifecycle(t *testing.T, registry *CodexAuthService) string {
	t.Helper()
	root := t.TempDir()
	workingDirectory := filepath.Join(root, "workspace")
	if err := os.Mkdir(workingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	registry.sessionsDirectory = filepath.Join(root, "sessions")
	registry.workingDirectory = workingDirectory
	registryTestResources(registry).quarantine = newFileBindingQuarantine(filepath.Join(root, "quarantine"))
	return registry.sessionsDirectory
}

type credentialRecord struct {
	Metadata IdentityMetadata
	Auth     []byte
}

type credentialProvider interface {
	Metadata(context.Context, CredentialRef) (IdentityMetadata, bool, error)
	Create(context.Context, credentialRecord) error
	Replace(context.Context, credentialRecord) error
	List(context.Context) ([]IdentityMetadata, error)
	Load(context.Context, CredentialRef) (credentialRecord, bool, error)
	Delete(context.Context, CredentialRef) error
}

type identityLocker interface {
	TryLock(CredentialRef) (identityLock, error)
}

type identityLock interface{ Release() error }

func newRegistry(provider credentialProvider, login loginRunner, locks identityLocker) (*CodexAuthService, error) {
	registry := &CodexAuthService{
		login:         login,
		status:        &fakeStatusRunner{},
		verifyCleanup: launch.VerifySessionCleanupProof,
	}
	resources := &testLoginResources{
		registry:   registry,
		provider:   provider,
		locks:      locks,
		quarantine: noBindingQuarantine{},
	}
	registry.resources = resources
	return registry, nil
}

func registryTestResources(registry *CodexAuthService) *testLoginResources {
	resources, ok := registry.resources.(*testLoginResources)
	if !ok {
		panic("registry does not use test authentication resources")
	}
	return resources
}

func (registry *CodexAuthService) tryLock(ctx context.Context, name CredentialRef, recoverable bool) (identityLock, error) {
	locked, err := registryTestResources(registry).locks.TryLock(name)
	if err == nil {
		return locked, nil
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, ctxErr
	}
	if errors.Is(err, ErrIdentityBusy) && recoverable {
		return nil, err
	}
	return nil, err
}

// testLoginResources is an upper-layer capability fixture.  It has the same
// opaque root-path commit contract as the lower Store; lower Store tests cover
// its durable provider and marker implementation independently.
type testLoginResources struct {
	registry   *CodexAuthService
	provider   credentialProvider
	locks      identityLocker
	quarantine bindingQuarantine
}

func (resources testLoginResources) AcquireLogin(ctx context.Context, value string) (loginResourceBinding, error) {
	name, err := ParseCredentialRef(value)
	if err != nil {
		return nil, err
	}
	locked, err := resources.registry.tryLock(ctx, name, false)
	if err != nil {
		return nil, err
	}
	if _, exists, err := registryTestResources(resources.registry).provider.Metadata(ctx, name); err != nil {
		_ = locked.Release()
		return nil, fmt.Errorf("inspect Codex authentication identity %q: %w", name, err)
	} else if exists {
		_ = locked.Release()
		return nil, fmt.Errorf("%w: %q", ErrIdentityExists, name)
	}
	return testLoginBinding{registry: resources.registry, name: name, lock: locked}, nil
}

func (resources testLoginResources) AcquireStatus(ctx context.Context, value string) (loginResourceBinding, IdentityMetadata, error) {
	name, err := ParseCredentialRef(value)
	if err != nil {
		return nil, IdentityMetadata{}, err
	}
	locked, err := resources.registry.tryLock(ctx, name, false)
	if err != nil {
		return nil, IdentityMetadata{}, err
	}
	record, exists, err := registryTestResources(resources.registry).provider.Load(ctx, name)
	if err != nil {
		_ = locked.Release()
		return nil, IdentityMetadata{}, fmt.Errorf("load Codex authentication identity %q: %w", name, err)
	}
	if !exists {
		_ = locked.Release()
		return nil, IdentityMetadata{}, fmt.Errorf("%w: %q", ErrIdentityNotFound, name)
	}
	return testLoginBinding{registry: resources.registry, name: name, lock: locked, record: record, hasRecord: true}, record.Metadata, nil
}

func (resources testLoginResources) AcquireRecovery(ctx context.Context, value string) (recoveryResourceBinding, error) {
	name, err := ParseCredentialRef(value)
	if err != nil {
		return nil, err
	}
	var expected *quarantineMarker
	for {
		locked, err := resources.registry.tryLock(ctx, name, true)
		if err == nil {
			marker, exists, inspectErr := registryTestResources(resources.registry).quarantine.Inspect(ctx, name)
			if inspectErr != nil {
				_ = locked.Release()
				return nil, inspectErr
			}
			if !exists {
				_ = locked.Release()
				return nil, nil
			}
			if expected != nil && marker != *expected {
				_ = locked.Release()
				return nil, testRecoveryGenerationChanged{name: name}
			}
			return &testRecoveryBinding{registry: resources.registry, name: name, lock: locked, marker: marker}, nil
		}
		if !errors.Is(err, ErrIdentityBusy) {
			return nil, err
		}
		marker, exists, inspectErr := registryTestResources(resources.registry).quarantine.Inspect(ctx, name)
		if inspectErr != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, err
		}
		if expected == nil {
			if !exists || marker.Phase != quarantineRecoverable {
				return nil, err
			}
			expected = &marker
		} else if exists && marker != *expected {
			return nil, testRecoveryGenerationChanged{name: name}
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (resources testLoginResources) List(ctx context.Context) ([]IdentityMetadata, error) {
	identities, err := registryTestResources(resources.registry).provider.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Codex authentication identities: %w", err)
	}
	sort.Slice(identities, func(left, right int) bool { return identities[left].Name < identities[right].Name })
	return identities, nil
}

func (resources testLoginResources) Logout(ctx context.Context, value string) error {
	name, err := ParseCredentialRef(value)
	if err != nil {
		return err
	}
	locked, err := resources.registry.tryLock(ctx, name, false)
	if err != nil {
		return err
	}
	defer locked.Release()
	if err := registryTestResources(resources.registry).provider.Delete(ctx, name); err != nil {
		return fmt.Errorf("remove Codex authentication identity %q: %w", name, err)
	}
	return nil
}

type testLoginBinding struct {
	registry  *CodexAuthService
	name      CredentialRef
	lock      identityLock
	record    credentialRecord
	hasRecord bool
}

func (binding testLoginBinding) Release() error { return binding.lock.Release() }
func (binding testLoginBinding) PublishPrepared(ctx context.Context, root, challenge string) error {
	sessionID := filepath.Base(root)
	return registryTestResources(binding.registry).quarantine.Create(ctx, quarantineMarker{Version: recordVersion, Name: binding.name, SessionID: sessionID, Phase: quarantinePrepared, ProofChallenge: challenge})
}
func (binding testLoginBinding) Published(ctx context.Context, sessionID, challenge string) (bool, error) {
	marker, exists, err := registryTestResources(binding.registry).quarantine.Inspect(ctx, binding.name)
	if err != nil {
		return false, err
	}
	return exists && marker.SessionID == sessionID && marker.ProofChallenge == challenge && marker.Phase == quarantinePrepared, nil
}
func (binding testLoginBinding) MarkCleanupPending(ctx context.Context) error {
	return registryTestResources(binding.registry).quarantine.MarkCleanupPending(ctx, binding.name)
}
func (binding testLoginBinding) MarkRecoverable(ctx context.Context) error {
	return registryTestResources(binding.registry).quarantine.MarkRecoverable(ctx, binding.name)
}
func (binding testLoginBinding) SettlePending(ctx context.Context, sessionID, challenge string) error {
	locked, err := registryTestResources(binding.registry).locks.TryLock(binding.name)
	if err != nil {
		return err
	}
	defer locked.Release()
	marker, exists, err := registryTestResources(binding.registry).quarantine.Inspect(ctx, binding.name)
	if err != nil || !exists || marker.SessionID != sessionID || marker.ProofChallenge != challenge || marker.Phase != quarantineCleanupPending {
		return ErrBindingQuarantined
	}
	return registryTestResources(binding.registry).quarantine.MarkRecoverable(ctx, binding.name)
}
func (binding testLoginBinding) DeleteMarkerAfterProjectionRemoval(ctx context.Context) error {
	return registryTestResources(binding.registry).quarantine.Delete(ctx, binding.name)
}
func (binding testLoginBinding) CommitLogin(ctx context.Context, root string) (IdentityMetadata, error) {
	auth, err := readSessionAuthFile(root)
	if err != nil {
		return IdentityMetadata{}, ErrUnsupportedAuth
	}
	defer clearBytes(auth)
	metadata, err := validateAuthJSON(binding.name, auth)
	if err != nil {
		return IdentityMetadata{}, err
	}
	if err := registryTestResources(binding.registry).provider.Create(ctx, credentialRecord{Metadata: metadata, Auth: auth}); err != nil {
		return IdentityMetadata{}, fmt.Errorf("store Codex authentication identity %q: %w", binding.name, err)
	}
	return metadata, nil
}

func (binding testLoginBinding) Project(home string) error {
	return projectCredentialForTest(home, binding.record)
}

func (binding testLoginBinding) MarkRefreshAllowed(ctx context.Context) error {
	return registryTestResources(binding.registry).quarantine.MarkRefreshAllowed(ctx, binding.name)
}

func (binding testLoginBinding) FinalizeStatus(ctx context.Context, root string) (codexauthresource.BindingDisposition, error) {
	if !binding.hasRecord {
		return codexauthresource.QuarantinedUncertain, ErrProviderUnavailable
	}
	projected, err := readSessionAuthFile(root)
	if err != nil {
		return codexauthresource.DiscardedProjection, ErrProjectedAuthInvalid
	}
	defer clearBytes(projected)
	metadata, err := validateAuthJSON(binding.name, projected)
	if err != nil || metadata != binding.record.Metadata {
		return codexauthresource.DiscardedProjection, ErrProjectedAuthInvalid
	}
	if bytes.Equal(projected, binding.record.Auth) {
		return codexauthresource.DiscardedProjection, nil
	}
	if err := registryTestResources(binding.registry).provider.Replace(ctx, credentialRecord{Metadata: metadata, Auth: projected}); err != nil {
		return codexauthresource.QuarantinedUncertain, ErrBindingQuarantined
	}
	return codexauthresource.CommittedSameIdentityRefresh, nil
}

type testRecoveryGenerationChanged struct{ name CredentialRef }

func (err testRecoveryGenerationChanged) Error() string {
	return fmt.Sprintf("%v: %q", ErrIdentityBusy, err.name)
}
func (testRecoveryGenerationChanged) Unwrap() error              { return ErrIdentityBusy }
func (testRecoveryGenerationChanged) RecoveryGenerationChanged() {}

type testRecoveryBinding struct {
	registry *CodexAuthService
	name     CredentialRef
	lock     identityLock
	marker   quarantineMarker
}

func (binding *testRecoveryBinding) Release() error    { return binding.lock.Release() }
func (binding *testRecoveryBinding) SessionID() string { return binding.marker.SessionID }
func (binding *testRecoveryBinding) Prepared() bool {
	return binding.marker.Phase == quarantinePrepared
}
func (binding *testRecoveryBinding) CleanupPending() bool {
	return binding.marker.Phase == quarantineCleanupPending
}
func (binding *testRecoveryBinding) CleanupChallenge() string { return binding.marker.ProofChallenge }
func (binding *testRecoveryBinding) DeleteMarkerAfterProjectionRemoval(ctx context.Context) error {
	marker, exists, err := registryTestResources(binding.registry).quarantine.Inspect(ctx, binding.name)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if marker != binding.marker {
		return ErrBindingQuarantined
	}
	return registryTestResources(binding.registry).quarantine.Delete(ctx, binding.name)
}
func (binding *testRecoveryBinding) FinalizeRecovery(ctx context.Context, root string) (codexauthresource.BindingDisposition, error) {
	record, exists, err := registryTestResources(binding.registry).provider.Load(ctx, binding.name)
	if err != nil {
		return codexauthresource.QuarantinedUncertain, ErrBindingQuarantined
	}
	if !exists || !binding.marker.RefreshAllowed {
		return codexauthresource.DiscardedProjection, nil
	}
	defer clearBytes(record.Auth)
	projected, err := readSessionAuthFile(root)
	if err != nil {
		return codexauthresource.DiscardedProjection, nil
	}
	defer clearBytes(projected)
	metadata, err := validateAuthJSON(binding.name, projected)
	if err != nil || metadata != record.Metadata || bytes.Equal(projected, record.Auth) {
		return codexauthresource.DiscardedProjection, nil
	}
	if err := registryTestResources(binding.registry).provider.Replace(ctx, credentialRecord{Metadata: metadata, Auth: projected}); err != nil {
		return codexauthresource.QuarantinedUncertain, ErrBindingQuarantined
	}
	return codexauthresource.CommittedSameIdentityRefresh, nil
}

type fakeProvider struct {
	mutex        sync.Mutex
	records      map[CredentialRef]credentialRecord
	loadCalls    int
	replaceCalls int
	replaceErr   error
	metadataErr  error
	createErr    error
	createCalls  int
}

func newFakeProvider() *fakeProvider {
	return &fakeProvider{records: make(map[CredentialRef]credentialRecord)}
}

func (provider *fakeProvider) Metadata(_ context.Context, name CredentialRef) (IdentityMetadata, bool, error) {
	provider.mutex.Lock()
	defer provider.mutex.Unlock()
	record, exists := provider.records[name]
	return record.Metadata, exists, provider.metadataErr
}

func (provider *fakeProvider) Create(_ context.Context, record credentialRecord) error {
	provider.mutex.Lock()
	defer provider.mutex.Unlock()
	provider.createCalls++
	if provider.createErr != nil {
		return provider.createErr
	}
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

func projectCredentialForTest(home string, record credentialRecord) error {
	if _, err := validateAuthJSON(record.Metadata.Name, record.Auth); err != nil {
		return ErrProjectedAuthInvalid
	}
	codexHome := filepath.Join(home, ".codex")
	if err := os.Mkdir(codexHome, 0o700); err != nil {
		return ErrProjectedAuthInvalid
	}
	configuration := "cli_auth_credentials_store = \"file\"\nforced_login_method = \"chatgpt\"\n"
	if record.Metadata.Workspace != "" {
		configuration += fmt.Sprintf("forced_chatgpt_workspace_id = %q\n", record.Metadata.Workspace)
	}
	if err := os.WriteFile(filepath.Join(codexHome, "config.toml"), []byte(configuration), 0o600); err != nil {
		return ErrProjectedAuthInvalid
	}
	if err := os.WriteFile(filepath.Join(codexHome, "auth.json"), record.Auth, 0o600); err != nil {
		return ErrProjectedAuthInvalid
	}
	return nil
}
