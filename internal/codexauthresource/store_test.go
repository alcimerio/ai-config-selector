package codexauthresource

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/session"
)

type testProvider struct {
	metadata      IdentityMetadata
	record        credentialRecord
	exists        bool
	created       credentialRecord
	metadataErr   error
	createErr     error
	loadErr       error
	replaceErr    error
	listErr       error
	deleteErr     error
	listed        []IdentityMetadata
	metadataCalls int
	loadCalls     int
	replaceCalls  int
	deleteCalls   int
}

func (p *testProvider) Metadata(context.Context, CredentialRef) (IdentityMetadata, bool, error) {
	p.metadataCalls++
	return p.metadata, p.exists, p.metadataErr
}
func (p *testProvider) Create(_ context.Context, record credentialRecord) error {
	if p.createErr != nil {
		return p.createErr
	}
	p.created = credentialRecord{Metadata: record.Metadata, Auth: append([]byte(nil), record.Auth...)}
	return nil
}
func (p *testProvider) Replace(_ context.Context, record credentialRecord) error {
	p.replaceCalls++
	if p.replaceErr != nil {
		return p.replaceErr
	}
	p.record = credentialRecord{Metadata: record.Metadata, Auth: append([]byte(nil), record.Auth...)}
	return nil
}
func (p *testProvider) List(context.Context) ([]IdentityMetadata, error) {
	if p.listErr != nil {
		return nil, p.listErr
	}
	if p.listed != nil {
		return append([]IdentityMetadata(nil), p.listed...), nil
	}
	return []IdentityMetadata{p.metadata}, nil
}
func (p *testProvider) Load(context.Context, CredentialRef) (credentialRecord, bool, error) {
	p.loadCalls++
	record := credentialRecord{Metadata: p.record.Metadata, Auth: append([]byte(nil), p.record.Auth...)}
	return record, p.exists, p.loadErr
}
func (p *testProvider) Delete(context.Context, CredentialRef) error {
	p.deleteCalls++
	return p.deleteErr
}

type testLock struct{ released bool }

func (lock *testLock) Release() error { lock.released = true; return nil }

type testLocker struct{ lock *testLock }

func (locker testLocker) TryLock(CredentialRef) (identityLock, error) { return locker.lock, nil }

type scriptedLocker struct {
	calls        int
	lock         *testLock
	beforeSecond func()
}

func (locker *scriptedLocker) TryLock(CredentialRef) (identityLock, error) {
	locker.calls++
	if locker.calls == 1 {
		return nil, ErrIdentityBusy
	}
	if locker.beforeSecond != nil {
		locker.beforeSecond()
	}
	return locker.lock, nil
}

type testMarkers struct {
	marker     quarantineMarker
	exists     bool
	inspectErr error
}

func (markers *testMarkers) Inspect(context.Context, CredentialRef) (quarantineMarker, bool, error) {
	return markers.marker, markers.exists, markers.inspectErr
}
func (markers *testMarkers) Create(_ context.Context, marker quarantineMarker) error {
	markers.marker, markers.exists = marker, true
	return nil
}
func (markers *testMarkers) MarkCleanupPending(context.Context, CredentialRef) error {
	markers.marker.Phase = quarantineCleanupPending
	return nil
}
func (markers *testMarkers) MarkRefreshAllowed(context.Context, CredentialRef) error {
	markers.marker.RefreshAllowed = true
	return nil
}
func (markers *testMarkers) MarkRecoverable(context.Context, CredentialRef) error {
	markers.marker.Phase = quarantineRecoverable
	return nil
}
func (markers *testMarkers) Delete(context.Context, CredentialRef) error {
	markers.exists = false
	return nil
}

func TestAcquireLoginChecksExistingBeforeBindingEscapes(t *testing.T) {
	lock := &testLock{}
	store := &Store{provider: &testProvider{exists: true}, locks: testLocker{lock}, markers: &testMarkers{}}
	if _, err := store.AcquireLogin(context.Background(), "work"); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("error = %v", err)
	}
	if !lock.released {
		t.Fatal("existing identity retained lock")
	}
}

func TestAcquireLoginReleasesAuthorityOnProviderFailure(t *testing.T) {
	providerFailure := errors.New("provider unavailable")
	lock := &testLock{}
	store := &Store{provider: &testProvider{metadataErr: providerFailure}, locks: testLocker{lock}, markers: &testMarkers{}}
	if _, err := store.AcquireLogin(context.Background(), "work"); !errors.Is(err, providerFailure) {
		t.Fatalf("error = %v", err)
	}
	if !lock.released {
		t.Fatal("provider failure retained lock")
	}
}

func TestAcquireLoginMarkerFailureAndExistencePrecedeProviderRead(t *testing.T) {
	for _, test := range []struct {
		name    string
		markers testMarkers
		want    error
	}{
		{name: "inspection failure", markers: testMarkers{inspectErr: ErrProviderUnavailable}, want: ErrProviderUnavailable},
		{name: "existing marker", markers: testMarkers{exists: true}, want: ErrIdentityBusy},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := &testProvider{}
			lock := &testLock{}
			markers := test.markers
			store := &Store{provider: provider, locks: testLocker{lock}, markers: &markers}
			if _, err := store.AcquireLogin(context.Background(), "work"); !errors.Is(err, test.want) {
				t.Fatalf("error = %v", err)
			}
			if provider.metadataCalls != 0 {
				t.Fatalf("provider reads = %d", provider.metadataCalls)
			}
			if !lock.released {
				t.Fatal("marker failure retained lock")
			}
		})
	}
}

func TestAcquireStatusKeepsRecordPrivateAndReleasesIt(t *testing.T) {
	name, _ := ParseCredentialRef("work")
	lock := &testLock{}
	store := &Store{provider: &testProvider{exists: true, record: credentialRecord{Metadata: IdentityMetadata{Name: name}, Auth: []byte("secret")}}, locks: testLocker{lock}, markers: &testMarkers{}}
	binding, metadata, err := store.AcquireStatus(context.Background(), "work")
	if err != nil || metadata.Name != name {
		t.Fatalf("acquire = (%v, %#v)", err, metadata)
	}
	if err := binding.Release(); err != nil || !lock.released {
		t.Fatalf("release = (%v, %v)", err, lock.released)
	}
}

func TestListSortsMetadataAndLogoutUsesDurableAuthority(t *testing.T) {
	provider := &testProvider{listed: []IdentityMetadata{{Name: "work"}, {Name: "personal"}}}
	store := &Store{provider: provider, locks: testLocker{&testLock{}}, markers: &testMarkers{}}
	listed, err := store.List(context.Background())
	if err != nil || len(listed) != 2 || listed[0].Name != "personal" || listed[1].Name != "work" {
		t.Fatalf("list = (%#v, %v)", listed, err)
	}
	if err := store.Logout(context.Background(), "work"); err != nil || provider.deleteCalls != 1 {
		t.Fatalf("logout = %v, deletes = %d", err, provider.deleteCalls)
	}
	provider.deleteErr = ErrProviderUnavailable
	if err := store.Logout(context.Background(), "work"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("provider logout error = %v", err)
	}
	busy := &Store{provider: provider, locks: testLocker{&testLock{}}, markers: &testMarkers{exists: true}}
	before := provider.deleteCalls
	if err := busy.Logout(context.Background(), "work"); !errors.Is(err, ErrIdentityBusy) || provider.deleteCalls != before {
		t.Fatalf("busy logout = %v, deletes = %d", err, provider.deleteCalls)
	}
}

func TestAcquireRecoveryNeverSwitchesObservedRecoverableGeneration(t *testing.T) {
	original := quarantineMarker{Version: recordVersion, Name: "work", SessionID: "session-original", Phase: quarantineRecoverable, ProofChallenge: testCleanupProofChallenge}
	markers := &testMarkers{marker: original, exists: true}
	lock := &testLock{}
	locker := &scriptedLocker{lock: lock, beforeSecond: func() {
		markers.marker = quarantineMarker{Version: recordVersion, Name: "work", SessionID: "session-newer", Phase: quarantineRecoverable, ProofChallenge: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	}}
	store := &Store{provider: &testProvider{}, locks: locker, markers: markers}
	binding, err := store.AcquireRecovery(context.Background(), "work")
	if binding != nil || !errors.Is(err, ErrIdentityBusy) {
		t.Fatalf("changed generation acquisition = (%#v, %v)", binding, err)
	}
	if _, changed := err.(interface{ RecoveryGenerationChanged() }); !changed {
		t.Fatalf("changed generation error lost identity: %T", err)
	}
	if !lock.released {
		t.Fatal("changed generation retained replacement lock")
	}
}

func TestStoresDoNotShareOwnershipAcrossCanonicalDirectoryReplacement(t *testing.T) {
	root := t.TempDir()
	ancestor := filepath.Join(root, "canonical")
	locksDirectory := filepath.Join(ancestor, "locks")
	markersDirectory := filepath.Join(ancestor, "markers")
	for _, directory := range []string{locksDirectory, markersDirectory} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	oldStore := &Store{provider: &testProvider{}, locks: newFileIdentityLocker(locksDirectory), markers: newFileBindingQuarantine(markersDirectory)}
	moved := filepath.Join(root, "canonical-detached")
	if err := os.Rename(ancestor, moved); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{locksDirectory, markersDirectory} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	newStore := &Store{provider: &testProvider{}, locks: newFileIdentityLocker(locksDirectory), markers: newFileBindingQuarantine(markersDirectory)}
	if binding, err := oldStore.AcquireLogin(context.Background(), "work"); binding != nil || !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("detached store acquisition = (%#v, %v)", binding, err)
	}
	for _, path := range []string{
		filepath.Join(moved, "locks", "work.lock"), filepath.Join(moved, "markers", "work.json"),
		filepath.Join(locksDirectory, "work.lock"), filepath.Join(markersDirectory, "work.json"),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("detached store wrote %q: %v", path, err)
		}
	}
	binding, err := newStore.AcquireLogin(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	if err := binding.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryFinalizationRequiresExactMarkerGeneration(t *testing.T) {
	marker := quarantineMarker{Version: recordVersion, Name: "work", SessionID: "session-original", Phase: quarantineRecoverable, ProofChallenge: testCleanupProofChallenge, RefreshAllowed: true}
	markers := &testMarkers{marker: marker, exists: true}
	provider := &testProvider{exists: true}
	binding := &RecoveryBinding{store: &Store{provider: provider, markers: markers}, name: "work", lock: &testLock{}, marker: marker}
	markers.marker.SessionID = "session-newer"
	if _, err := binding.FinalizeRecovery(context.Background(), t.TempDir()); !errors.Is(err, ErrBindingQuarantined) {
		t.Fatalf("stale recovery finalization error = %v", err)
	}
	if provider.loadCalls != 0 || provider.replaceCalls != 0 {
		t.Fatalf("stale recovery touched provider: loads=%d replacements=%d", provider.loadCalls, provider.replaceCalls)
	}
}

func TestRecoveryFinalizationCommitsOnlySameIdentityEligibleRefresh(t *testing.T) {
	name, _ := ParseCredentialRef("work")
	original := testChatGPTAuthJSON(t, "user", "workspace")
	metadata, _ := ValidateAuthJSON(name, original)
	refreshed := bytes.Replace(original, []byte("access-secret"), []byte("recovered-access"), 1)
	created := newProtectedTestSession(t)
	directory := filepath.Join(created.HomeDirectory(), ".codex")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "auth.json"), refreshed, 0o600); err != nil {
		t.Fatal(err)
	}
	marker := quarantineMarker{Version: recordVersion, Name: name, SessionID: filepath.Base(created.RootDirectory()), Phase: quarantineRecoverable, ProofChallenge: testCleanupProofChallenge, RefreshAllowed: true}
	markers := &testMarkers{marker: marker, exists: true}
	provider := &testProvider{exists: true, record: credentialRecord{Metadata: metadata, Auth: original}}
	binding := &RecoveryBinding{store: &Store{provider: provider, markers: markers}, name: name, lock: &testLock{}, marker: marker}
	disposition, err := binding.FinalizeRecovery(context.Background(), created.RootDirectory())
	if err != nil || disposition != CommittedSameIdentityRefresh || provider.replaceCalls != 1 || !bytes.Equal(provider.record.Auth, refreshed) {
		t.Fatalf("recovery finalization = (%q, %v), replacements = %d", disposition, err, provider.replaceCalls)
	}
}

func TestAcquireStatusProviderAndMarkerFailuresPrecedeProjection(t *testing.T) {
	providerFailure := errors.New("load failed")
	for _, test := range []struct {
		name     string
		provider *testProvider
		markers  *testMarkers
		want     error
	}{
		{name: "marker", provider: &testProvider{}, markers: &testMarkers{exists: true}, want: ErrIdentityBusy},
		{name: "provider", provider: &testProvider{loadErr: providerFailure}, markers: &testMarkers{}, want: providerFailure},
		{name: "missing", provider: &testProvider{}, markers: &testMarkers{}, want: ErrIdentityNotFound},
	} {
		t.Run(test.name, func(t *testing.T) {
			lock := &testLock{}
			store := &Store{provider: test.provider, locks: testLocker{lock}, markers: test.markers}
			if _, _, err := store.AcquireStatus(context.Background(), "work"); !errors.Is(err, test.want) {
				t.Fatalf("error = %v", err)
			}
			if !lock.released {
				t.Fatal("failed acquisition retained lock")
			}
		})
	}
}

func TestStatusProjectionCommitsOnlyEligibleSameIdentityRefresh(t *testing.T) {
	name, _ := ParseCredentialRef("work")
	original := testChatGPTAuthJSON(t, "user", "workspace")
	metadata, err := ValidateAuthJSON(name, original)
	if err != nil {
		t.Fatal(err)
	}
	provider := &testProvider{exists: true, record: credentialRecord{Metadata: metadata, Auth: original}}
	markers := &testMarkers{}
	store := &Store{provider: provider, locks: testLocker{&testLock{}}, markers: markers}
	binding, _, err := store.AcquireStatus(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Release()
	created := newProtectedTestSession(t)
	if err := binding.PublishPrepared(context.Background(), created.RootDirectory(), testCleanupProofChallenge); err != nil {
		t.Fatal(err)
	}
	if err := binding.Project(created.HomeDirectory()); err != nil {
		t.Fatal(err)
	}
	refreshed := bytes.Replace(original, []byte("access-secret"), []byte("access-refreshed"), 1)
	if err := os.WriteFile(filepath.Join(created.HomeDirectory(), ".codex", "auth.json"), refreshed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := binding.MarkCleanupPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := binding.MarkRefreshAllowed(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := binding.MarkRecoverable(context.Background()); err != nil {
		t.Fatal(err)
	}
	disposition, err := binding.FinalizeStatus(context.Background(), created.RootDirectory())
	if err != nil || disposition != CommittedSameIdentityRefresh || provider.replaceCalls != 1 || !bytes.Equal(provider.record.Auth, refreshed) {
		t.Fatalf("finalize = (%q, %v), replacements = %d", disposition, err, provider.replaceCalls)
	}
}

func TestStatusProjectionRejectsForeignSessionHome(t *testing.T) {
	name, _ := ParseCredentialRef("work")
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	metadata, _ := ValidateAuthJSON(name, auth)
	store := &Store{provider: &testProvider{exists: true, record: credentialRecord{Metadata: metadata, Auth: auth}}, locks: testLocker{&testLock{}}, markers: &testMarkers{}}
	binding, _, err := store.AcquireStatus(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Release()
	bound := newProtectedTestSession(t)
	foreign := newProtectedTestSession(t)
	if err := binding.PublishPrepared(context.Background(), bound.RootDirectory(), testCleanupProofChallenge); err != nil {
		t.Fatal(err)
	}
	if err := binding.Project(foreign.HomeDirectory()); !errors.Is(err, ErrProjectedAuthInvalid) {
		t.Fatalf("foreign projection error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(foreign.HomeDirectory(), ".codex")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("foreign projection wrote credential directory: %v", err)
	}
}

func TestStatusFinalizationPreservesLastValidRecordOnInvalidOrFailedReplacement(t *testing.T) {
	name, _ := ParseCredentialRef("work")
	original := testChatGPTAuthJSON(t, "user", "workspace")
	metadata, _ := ValidateAuthJSON(name, original)
	for _, test := range []struct {
		name       string
		projected  []byte
		replaceErr error
		want       error
	}{
		{name: "identity changed", projected: testChatGPTAuthJSON(t, "other", "workspace"), want: ErrProjectedAuthInvalid},
		{name: "provider replacement failed", projected: bytes.Replace(original, []byte("access-secret"), []byte("new-access"), 1), replaceErr: errors.New("replace failed"), want: ErrBindingQuarantined},
	} {
		t.Run(test.name, func(t *testing.T) {
			provider := &testProvider{exists: true, record: credentialRecord{Metadata: metadata, Auth: append([]byte(nil), original...)}, replaceErr: test.replaceErr}
			markers := &testMarkers{}
			store := &Store{provider: provider, locks: testLocker{&testLock{}}, markers: markers}
			binding, _, err := store.AcquireStatus(context.Background(), "work")
			if err != nil {
				t.Fatal(err)
			}
			defer binding.Release()
			created := newProtectedTestSession(t)
			if err := binding.PublishPrepared(context.Background(), created.RootDirectory(), testCleanupProofChallenge); err != nil {
				t.Fatal(err)
			}
			if err := binding.Project(created.HomeDirectory()); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(created.HomeDirectory(), ".codex", "auth.json"), test.projected, 0o600); err != nil {
				t.Fatal(err)
			}
			_ = binding.MarkCleanupPending(context.Background())
			_ = binding.MarkRefreshAllowed(context.Background())
			_ = binding.MarkRecoverable(context.Background())
			if _, err := binding.FinalizeStatus(context.Background(), created.RootDirectory()); !errors.Is(err, test.want) {
				t.Fatalf("error = %v", err)
			}
			if !bytes.Equal(provider.record.Auth, original) {
				t.Fatal("last valid record changed")
			}
		})
	}
}

func TestCommitLoginReadsOnlyProtectedSessionProjection(t *testing.T) {
	name, _ := ParseCredentialRef("work")
	provider := &testProvider{}
	store := &Store{provider: provider, locks: testLocker{&testLock{}}, markers: &testMarkers{}}
	binding, err := store.AcquireLogin(context.Background(), string(name))
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Release()
	root, auth := writeTestSessionAuth(t)
	if err := binding.PublishPrepared(context.Background(), root, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if err := binding.MarkRecoverable(context.Background()); err != nil {
		t.Fatal(err)
	}
	metadata, err := binding.CommitLogin(context.Background(), root)
	if err != nil || metadata.Name != name || string(provider.created.Auth) != string(auth) {
		t.Fatalf("commit = (%#v, %v), created = %#v", metadata, err, provider.created)
	}
}

func TestCommitLoginRejectsDifferentProtectedSessionProjection(t *testing.T) {
	provider := &testProvider{}
	store := &Store{provider: provider, locks: testLocker{&testLock{}}, markers: &testMarkers{}}
	binding, err := store.AcquireLogin(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Release()
	boundRoot, _ := writeTestSessionAuth(t)
	if err := binding.PublishPrepared(context.Background(), boundRoot, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if err := binding.MarkRecoverable(context.Background()); err != nil {
		t.Fatal(err)
	}
	foreignRoot, _ := writeTestSessionAuth(t)
	if _, err := binding.CommitLogin(context.Background(), foreignRoot); !errors.Is(err, ErrBindingQuarantined) {
		t.Fatalf("foreign projection error = %v", err)
	}
	if provider.created.Auth != nil {
		t.Fatal("foreign projection created an identity")
	}
}

func TestCommitLoginRejectsUnprotectedPublishedSession(t *testing.T) {
	provider := &testProvider{}
	store := &Store{provider: provider, locks: testLocker{&testLock{}}, markers: &testMarkers{}}
	binding, err := store.AcquireLogin(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Release()
	root := t.TempDir()
	workingDirectory := filepath.Join(root, "workspace")
	if err := os.Mkdir(workingDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	created, err := session.Create(filepath.Join(root, "sessions"), workingDirectory, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = created.Remove() })
	if err := binding.PublishPrepared(context.Background(), created.RootDirectory(), testCleanupProofChallenge); err != nil {
		t.Fatal(err)
	}
	if err := binding.MarkRecoverable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.CommitLogin(context.Background(), created.RootDirectory()); !errors.Is(err, ErrBindingQuarantined) {
		t.Fatalf("unprotected projection error = %v", err)
	}
	if provider.created.Auth != nil {
		t.Fatal("unprotected projection created an identity")
	}
}

func TestCommitLoginUsesCreateOnlyAndPreservesProviderErrorIdentity(t *testing.T) {
	name, _ := ParseCredentialRef("work")
	provider := &testProvider{createErr: ErrIdentityExists}
	store := &Store{provider: provider, locks: testLocker{&testLock{}}, markers: &testMarkers{}}
	binding, err := store.AcquireLogin(context.Background(), string(name))
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Release()
	root, _ := writeTestSessionAuth(t)
	if err := binding.PublishPrepared(context.Background(), root, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if err := binding.MarkRecoverable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.CommitLogin(context.Background(), root); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("create-only error = %v", err)
	}
	if provider.created.Auth != nil {
		t.Fatal("failed Create recorded credential bytes")
	}
}

func TestCommitLoginRejectsInterruptedProtocolBeforeCreate(t *testing.T) {
	provider := &testProvider{}
	store := &Store{provider: provider, locks: testLocker{&testLock{}}, markers: &testMarkers{}}
	binding, err := store.AcquireLogin(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Release()
	root, _ := writeTestSessionAuth(t)
	if err := binding.PublishPrepared(context.Background(), root, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if err := binding.MarkCleanupPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.CommitLogin(context.Background(), root); !errors.Is(err, ErrBindingQuarantined) {
		t.Fatalf("interrupted commit error = %v", err)
	}
	if provider.created.Auth != nil {
		t.Fatal("interrupted protocol created an identity")
	}
}

func TestReleasedLoginBindingCannotMutateOrCommit(t *testing.T) {
	root := t.TempDir()
	locksDirectory := filepath.Join(root, "locks")
	markersDirectory := filepath.Join(root, "markers")
	if err := os.MkdirAll(locksDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(markersDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	store := &Store{provider: &testProvider{}, locks: newFileIdentityLocker(locksDirectory), markers: newFileBindingQuarantine(markersDirectory)}
	binding, err := store.AcquireLogin(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "session-released"
	const challenge = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := binding.PublishPrepared(context.Background(), filepath.Join(root, sessionID), challenge); err != nil {
		t.Fatal(err)
	}
	if err := binding.Release(); err != nil {
		t.Fatal(err)
	}
	for operation, err := range map[string]error{
		"pending":     binding.MarkCleanupPending(context.Background()),
		"refresh":     binding.MarkRefreshAllowed(context.Background()),
		"recoverable": binding.MarkRecoverable(context.Background()),
		"delete":      binding.DeleteMarkerAfterProjectionRemoval(context.Background()),
	} {
		if !errors.Is(err, ErrProviderUnavailable) {
			t.Fatalf("released %s error = %v", operation, err)
		}
	}
	marker, exists, err := store.markers.Inspect(context.Background(), "work")
	if err != nil || !exists || marker.Phase != quarantinePrepared {
		t.Fatalf("released binding changed marker = (%#v, %v, %v)", marker, exists, err)
	}
	projection, _ := writeTestSessionAuth(t)
	if _, err := binding.CommitLogin(context.Background(), projection); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("released commit error = %v", err)
	}
}

func writeTestSessionAuth(t *testing.T) (string, []byte) {
	t.Helper()
	created := newProtectedTestSession(t)
	directory := filepath.Join(created.HomeDirectory(), ".codex")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user"}`))
	auth := []byte(`{"auth_mode":"chatgpt","tokens":{"id_token":"a.` + claims + `.c","access_token":"access","refresh_token":"refresh"}}`)
	if err := os.WriteFile(filepath.Join(directory, "auth.json"), auth, 0o600); err != nil {
		t.Fatal(err)
	}
	return created.RootDirectory(), auth
}

func newProtectedTestSession(t *testing.T) *session.Session {
	t.Helper()
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
	t.Cleanup(func() { _ = created.Remove() })
	return created
}

func TestSettlePendingRequiresTheExactDurableGeneration(t *testing.T) {
	root := t.TempDir()
	locksDirectory := filepath.Join(root, "locks")
	markersDirectory := filepath.Join(root, "markers")
	if err := os.MkdirAll(locksDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(markersDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	store := &Store{
		provider: &testProvider{},
		locks:    newFileIdentityLocker(locksDirectory),
		markers:  newFileBindingQuarantine(markersDirectory),
	}
	binding, err := store.AcquireLogin(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	const sessionID = "session-one"
	const challenge = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := binding.PublishPrepared(context.Background(), filepath.Join(root, sessionID), challenge); err != nil {
		t.Fatal(err)
	}
	if err := binding.MarkCleanupPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := binding.Release(); err != nil {
		t.Fatal(err)
	}
	if err := binding.SettlePending(context.Background(), sessionID, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); !errors.Is(err, ErrBindingQuarantined) {
		t.Fatalf("stale challenge settlement error = %v", err)
	}
	marker, exists, err := store.markers.Inspect(context.Background(), "work")
	if err != nil || !exists || marker.Phase != quarantineCleanupPending {
		t.Fatalf("stale settlement changed marker = (%#v, %v, %v)", marker, exists, err)
	}
	if err := binding.SettlePending(context.Background(), sessionID, challenge); err != nil {
		t.Fatal(err)
	}
	marker, exists, err = store.markers.Inspect(context.Background(), "work")
	if err != nil || !exists || marker.Phase != quarantineRecoverable {
		t.Fatalf("exact settlement marker = (%#v, %v, %v)", marker, exists, err)
	}
	if err := store.markers.Delete(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	replacement := quarantineMarker{
		Version: recordVersion, Name: "work", SessionID: "session-newer",
		Phase: quarantineCleanupPending, ProofChallenge: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	}
	if err := store.markers.Create(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if err := binding.SettlePending(context.Background(), sessionID, challenge); !errors.Is(err, ErrBindingQuarantined) {
		t.Fatalf("released stale binding settlement error = %v", err)
	}
	marker, exists, err = store.markers.Inspect(context.Background(), "work")
	if err != nil || !exists || marker != replacement {
		t.Fatalf("released stale binding changed replacement = (%#v, %v, %v)", marker, exists, err)
	}
}
