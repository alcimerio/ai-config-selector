package codexauthresource

import (
	"context"
	"errors"
	"testing"
)

type testProvider struct {
	metadata IdentityMetadata
	record   credentialRecord
	exists   bool
}

func (p *testProvider) Metadata(context.Context, CredentialRef) (IdentityMetadata, bool, error) {
	return p.metadata, p.exists, nil
}
func (p *testProvider) Create(context.Context, credentialRecord) error   { return nil }
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

type testMarkers struct{}

func (testMarkers) Inspect(context.Context, CredentialRef) (quarantineMarker, bool, error) {
	return quarantineMarker{}, false, nil
}
func (testMarkers) Create(context.Context, quarantineMarker) error          { return nil }
func (testMarkers) MarkCleanupPending(context.Context, CredentialRef) error { return nil }
func (testMarkers) MarkRefreshAllowed(context.Context, CredentialRef) error { return nil }
func (testMarkers) MarkRecoverable(context.Context, CredentialRef) error    { return nil }
func (testMarkers) Delete(context.Context, CredentialRef) error             { return nil }

func TestAcquireLoginChecksExistingBeforeBindingEscapes(t *testing.T) {
	lock := &testLock{}
	store := &Store{provider: &testProvider{exists: true}, locks: testLocker{lock}, markers: testMarkers{}}
	if _, err := store.AcquireLogin(context.Background(), "work"); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("error = %v", err)
	}
	if !lock.released {
		t.Fatal("existing identity retained lock")
	}
}

func TestAcquireStatusKeepsRecordPrivateAndReleasesIt(t *testing.T) {
	name, _ := ParseCredentialRef("work")
	lock := &testLock{}
	store := &Store{provider: &testProvider{exists: true, record: credentialRecord{Metadata: IdentityMetadata{Name: name}, Auth: []byte("secret")}}, locks: testLocker{lock}, markers: testMarkers{}}
	binding, metadata, err := store.AcquireStatus(context.Background(), "work")
	if err != nil || metadata.Name != name {
		t.Fatalf("acquire = (%v, %#v)", err, metadata)
	}
	if err := binding.Release(); err != nil || !lock.released {
		t.Fatalf("release = (%v, %v)", err, lock.released)
	}
}
