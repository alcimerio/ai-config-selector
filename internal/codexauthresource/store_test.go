package codexauthresource

import (
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
	metadataCalls int
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
func (p *testProvider) Replace(context.Context, credentialRecord) error  { return nil }
func (p *testProvider) List(context.Context) ([]IdentityMetadata, error) { return nil, nil }
func (p *testProvider) Load(context.Context, CredentialRef) (credentialRecord, bool, error) {
	return p.record, p.exists, nil
}
func (p *testProvider) Delete(context.Context, CredentialRef) error { return nil }

type testLock struct{ released bool }

func (lock *testLock) Release() error { lock.released = true; return nil }

type testLocker struct{ lock *testLock }

func (locker testLocker) TryLock(CredentialRef) (identityLock, error) { return locker.lock, nil }

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

func TestCommitLoginReadsOnlyProtectedSessionProjection(t *testing.T) {
	name, _ := ParseCredentialRef("work")
	provider := &testProvider{}
	store := &Store{provider: provider, locks: testLocker{&testLock{}}, markers: &testMarkers{}}
	binding, err := store.AcquireLogin(context.Background(), string(name))
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Release()
	if err := binding.PublishPrepared(context.Background(), "session-commit", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if err := binding.MarkRecoverable(context.Background()); err != nil {
		t.Fatal(err)
	}
	root, auth := writeTestSessionAuth(t)
	metadata, err := binding.CommitLogin(context.Background(), root)
	if err != nil || metadata.Name != name || string(provider.created.Auth) != string(auth) {
		t.Fatalf("commit = (%#v, %v), created = %#v", metadata, err, provider.created)
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
	if err := binding.PublishPrepared(context.Background(), "session-create-only", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if err := binding.MarkRecoverable(context.Background()); err != nil {
		t.Fatal(err)
	}
	root, _ := writeTestSessionAuth(t)
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
	if err := binding.PublishPrepared(context.Background(), "session-interrupted", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if err := binding.MarkCleanupPending(context.Background()); err != nil {
		t.Fatal(err)
	}
	root, _ := writeTestSessionAuth(t)
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
	if err := binding.PublishPrepared(context.Background(), sessionID, challenge); err != nil {
		t.Fatal(err)
	}
	if err := binding.Release(); err != nil {
		t.Fatal(err)
	}
	for operation, err := range map[string]error{
		"pending":     binding.MarkCleanupPending(context.Background()),
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
	if err := binding.PublishPrepared(context.Background(), sessionID, challenge); err != nil {
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
