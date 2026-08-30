package codexauth

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestRegistryLoginCreatesWithoutReplacingNamedIdentity(t *testing.T) {
	provider := newFakeProvider()
	runner := &fakeLoginRunner{auth: testChatGPTAuthJSON(t, "user", "workspace")}
	registry, err := newRegistry(provider, runner, newFileIdentityLocker(t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}

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
	auth       []byte
	err        error
	calls      int
	deviceAuth bool
}

func (runner *fakeLoginRunner) Login(_ context.Context, deviceAuth bool, _ launch.Terminal) ([]byte, error) {
	runner.calls++
	runner.deviceAuth = deviceAuth
	return append([]byte(nil), runner.auth...), runner.err
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
