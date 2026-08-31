package codexauth

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestKeychainProviderListsAttributesWithoutRetrievingSecrets(t *testing.T) {
	client := newFakeKeychainClient()
	provider := &keychainProvider{client: client}
	for _, name := range []CredentialRef{"work", "personal"} {
		auth := testChatGPTAuthJSON(t, "user-"+string(name), "workspace")
		metadata, err := validateAuthJSON(name, auth)
		if err != nil {
			t.Fatal(err)
		}
		if err := provider.Create(context.Background(), credentialRecord{Metadata: metadata, Auth: auth}); err != nil {
			t.Fatal(err)
		}
	}

	identities, err := provider.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, want := []CredentialRef{identities[0].Name, identities[1].Name}, []CredentialRef{"personal", "work"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("names = %q, want %q", got, want)
	}
	if client.dataCalls != 0 {
		t.Fatalf("metadata-only list retrieved %d secret payloads", client.dataCalls)
	}
}

func TestKeychainProviderLoadsAndRevalidatesOneRecord(t *testing.T) {
	client := newFakeKeychainClient()
	provider := &keychainProvider{client: client}
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	metadata, _ := validateAuthJSON("work", auth)
	if err := provider.Create(context.Background(), credentialRecord{Metadata: metadata, Auth: auth}); err != nil {
		t.Fatal(err)
	}
	record, exists, err := provider.Load(context.Background(), "work")
	if err != nil || !exists {
		t.Fatalf("Load = (%#v, %v, %v)", record, exists, err)
	}
	if record.Metadata != metadata || string(record.Auth) != string(auth) {
		t.Fatalf("loaded record changed")
	}
	clearBytes(record.Auth)

	item := client.items["work"]
	item.comment = `{"version":1,"identity":{"name":"personal","method":"chatgpt","fingerprint":"sha256:` + string(make([]byte, 64)) + `"}}`
	client.items["work"] = item
	if _, _, err := provider.Load(context.Background(), "work"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("mismatched metadata error = %v", err)
	}
}

func TestKeychainProviderCreateIsAtomicAndLogoutIsIdempotent(t *testing.T) {
	client := newFakeKeychainClient()
	provider := &keychainProvider{client: client}
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	metadata, _ := validateAuthJSON("work", auth)
	record := credentialRecord{Metadata: metadata, Auth: auth}
	if err := provider.Create(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	if err := provider.Create(context.Background(), record); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("duplicate create error = %v", err)
	}
	if err := provider.Delete(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	if err := provider.Delete(context.Background(), "work"); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

func TestKeychainProviderReplacesOnlyAnExistingValidatedRecord(t *testing.T) {
	client := newFakeKeychainClient()
	provider := &keychainProvider{client: client}
	original := testChatGPTAuthJSON(t, "user", "workspace")
	metadata, _ := validateAuthJSON("work", original)
	if err := provider.Create(context.Background(), credentialRecord{Metadata: metadata, Auth: original}); err != nil {
		t.Fatal(err)
	}
	refreshed := []byte(strings.Replace(
		string(original), "2026-08-29T12:34:56Z", "2026-08-29T15:34:56Z", 1,
	))
	if err := provider.Replace(context.Background(), credentialRecord{Metadata: metadata, Auth: refreshed}); err != nil {
		t.Fatal(err)
	}
	record, exists, err := provider.Load(context.Background(), "work")
	if err != nil || !exists || string(record.Auth) != string(refreshed) {
		t.Fatalf("refreshed record = (%#v, %v, %v)", record.Metadata, exists, err)
	}
	clearBytes(record.Auth)

	mismatched := metadata
	mismatched.Workspace = "other-workspace"
	if err := provider.Replace(context.Background(), credentialRecord{Metadata: mismatched, Auth: refreshed}); !errors.Is(err, ErrUnsupportedAuth) {
		t.Fatalf("mismatched replacement error = %v", err)
	}
	missingAuth := testChatGPTAuthJSON(t, "missing-user", "workspace")
	missingMetadata, _ := validateAuthJSON("missing", missingAuth)
	if err := provider.Replace(context.Background(), credentialRecord{Metadata: missingMetadata, Auth: missingAuth}); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("missing replacement error = %v", err)
	}
}

func TestKeychainProviderRejectsCredentialMetadataMismatchBeforeWrite(t *testing.T) {
	client := newFakeKeychainClient()
	provider := &keychainProvider{client: client}
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	metadata, _ := validateAuthJSON("work", auth)
	metadata.Workspace = "other-workspace"

	if err := provider.Create(context.Background(), credentialRecord{Metadata: metadata, Auth: auth}); !errors.Is(err, ErrUnsupportedAuth) {
		t.Fatalf("mismatch error = %v", err)
	}
	if len(client.items) != 0 {
		t.Fatal("invalid record reached Keychain")
	}
}

func TestUnavailableKeychainProviderFailsClosedWithoutBlockingConstruction(t *testing.T) {
	provider := &keychainProvider{client: unavailableKeychainClient{}}
	if _, err := provider.List(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("list error = %v", err)
	}
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	metadata, _ := validateAuthJSON("work", auth)
	if err := provider.Create(context.Background(), credentialRecord{Metadata: metadata, Auth: auth}); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("create error = %v", err)
	}
}

func TestKeychainSecretReadFailureMapsToProviderUnavailable(t *testing.T) {
	client := newFakeKeychainClient()
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	metadata, _ := validateAuthJSON("work", auth)
	provider := &keychainProvider{client: client}
	if err := provider.Create(context.Background(), credentialRecord{Metadata: metadata, Auth: auth}); err != nil {
		t.Fatal(err)
	}
	client.dataErr = errors.New("synthetic locked or unavailable Keychain")
	if _, _, err := provider.Load(context.Background(), "work"); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("secret-read failure error = %v", err)
	}
}

type fakeKeychainItem struct {
	comment string
	secret  []byte
}

type fakeKeychainClient struct {
	items     map[string]fakeKeychainItem
	dataCalls int
	dataErr   error
}

func newFakeKeychainClient() *fakeKeychainClient {
	return &fakeKeychainClient{items: make(map[string]fakeKeychainItem)}
}

func (client *fakeKeychainClient) Add(service, account, comment string, secret []byte) error {
	if service != keychainService {
		return ErrProviderUnavailable
	}
	if _, exists := client.items[account]; exists {
		return ErrIdentityExists
	}
	client.items[account] = fakeKeychainItem{comment: comment, secret: append([]byte(nil), secret...)}
	return nil
}

func (client *fakeKeychainClient) Update(service, account, comment string, secret []byte) error {
	if service != keychainService {
		return ErrProviderUnavailable
	}
	if _, exists := client.items[account]; !exists {
		return errKeychainItemNotFound
	}
	client.items[account] = fakeKeychainItem{comment: comment, secret: append([]byte(nil), secret...)}
	return nil
}

func (client *fakeKeychainClient) Attributes(service string, account *string) ([]keychainAttributes, error) {
	if service != keychainService {
		return nil, ErrProviderUnavailable
	}
	result := make([]keychainAttributes, 0, len(client.items))
	for name, item := range client.items {
		if account == nil || name == *account {
			result = append(result, keychainAttributes{Account: name, Comment: item.comment})
		}
	}
	if len(result) == 0 {
		return nil, errKeychainItemNotFound
	}
	return result, nil
}

func (client *fakeKeychainClient) Data(service, account string) ([]byte, error) {
	client.dataCalls++
	if client.dataErr != nil {
		return nil, client.dataErr
	}
	if service != keychainService {
		return nil, ErrProviderUnavailable
	}
	item, exists := client.items[account]
	if !exists {
		return nil, errKeychainItemNotFound
	}
	return append([]byte(nil), item.secret...), nil
}

func (client *fakeKeychainClient) Delete(service, account string) error {
	if service != keychainService {
		return ErrProviderUnavailable
	}
	if _, exists := client.items[account]; !exists {
		return errKeychainItemNotFound
	}
	delete(client.items, account)
	return nil
}
