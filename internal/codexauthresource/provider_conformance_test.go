package codexauthresource

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
)

// Reuse these synthetic fixtures when introducing another provider. Concrete
// transport tests still own atomicity, duplicate-record and permission races.
func testProviderConformance(t *testing.T, fresh func() credentialProvider) {
	t.Helper()
	t.Run("identity lifecycle", func(t *testing.T) {
		provider := fresh()
		ctx := context.Background()
		if rows, err := provider.List(ctx); err != nil || len(rows) != 0 {
			t.Fatalf("empty list = (%v, %v)", rows, err)
		}
		if _, exists, err := provider.Metadata(ctx, "work"); err != nil || exists {
			t.Fatalf("absent metadata = (%v, %v)", exists, err)
		}
		if _, exists, err := provider.Load(ctx, "work"); err != nil || exists {
			t.Fatalf("absent load = (%v, %v)", exists, err)
		}
		auth := testChatGPTAuthJSON(t, "user", "workspace")
		metadata, err := validateAuthJSON("work", auth)
		if err != nil {
			t.Fatal(err)
		}
		record := credentialRecord{Metadata: metadata, Auth: auth}
		if err := provider.Replace(ctx, record); !errors.Is(err, ErrProviderUnavailable) {
			t.Fatalf("replace absent identity = %v", err)
		}
		if err := provider.Create(ctx, record); err != nil {
			t.Fatal(err)
		}
		// Create must never act as an upsert, even with a valid other identity.
		other := testChatGPTAuthJSON(t, "other-user", "workspace")
		otherMetadata, _ := validateAuthJSON("work", other)
		if err := provider.Create(ctx, credentialRecord{Metadata: otherMetadata, Auth: other}); !errors.Is(err, ErrIdentityExists) {
			t.Fatalf("duplicate create = %v", err)
		}
		if got, exists, err := provider.Metadata(ctx, "work"); err != nil || !exists || got != metadata {
			t.Fatalf("metadata changed: exists=%v err=%v", exists, err)
		}
		if rows, err := provider.List(ctx); err != nil || !reflect.DeepEqual(rows, []IdentityMetadata{metadata}) {
			t.Fatalf("list mismatch: %v", err)
		}
		loaded, exists, err := provider.Load(ctx, "work")
		if err != nil || !exists || loaded.Metadata != metadata || !bytes.Equal(loaded.Auth, auth) {
			t.Fatalf("load mismatch: exists=%v err=%v", exists, err)
		}
		clearBytes(loaded.Auth)
		refreshed := bytes.Replace(auth, []byte("access-secret"), []byte("refreshed-access"), 1)
		if err := provider.Replace(ctx, credentialRecord{Metadata: metadata, Auth: refreshed}); err != nil {
			t.Fatal(err)
		}
		loaded, exists, err = provider.Load(ctx, "work")
		if err != nil || !exists || loaded.Metadata != metadata || !bytes.Equal(loaded.Auth, refreshed) {
			t.Fatalf("refresh mismatch: exists=%v err=%v", exists, err)
		}
		clearBytes(loaded.Auth)
		for range 2 {
			if err := provider.Delete(ctx, "work"); err != nil {
				t.Fatalf("idempotent delete = %v", err)
			}
		}
		if _, exists, err := provider.Load(ctx, "work"); err != nil || exists {
			t.Fatalf("deleted load = (%v, %v)", exists, err)
		}
	})
	t.Run("validation and cancellation preserve identity", func(t *testing.T) {
		provider := fresh()
		auth := testChatGPTAuthJSON(t, "user", "workspace")
		metadata, _ := validateAuthJSON("work", auth)
		valid := credentialRecord{Metadata: metadata, Auth: auth}
		invalid := valid
		invalid.Metadata.Workspace = "other-workspace"
		if err := provider.Create(context.Background(), invalid); !errors.Is(err, ErrUnsupportedAuth) {
			t.Fatalf("invalid create = %v", err)
		}
		if err := provider.Create(context.Background(), valid); err != nil {
			t.Fatal(err)
		}
		if err := provider.Replace(context.Background(), invalid); !errors.Is(err, ErrUnsupportedAuth) {
			t.Fatalf("invalid replace = %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		testProviderFailures(t, provider, ctx, valid, context.Canceled)
		loaded, exists, err := provider.Load(context.Background(), "work")
		if err != nil || !exists || !bytes.Equal(loaded.Auth, auth) || loaded.Metadata != metadata {
			t.Fatalf("failed operation changed identity: exists=%v err=%v", exists, err)
		}
		clearBytes(loaded.Auth)
	})
}

func testProviderFailures(t *testing.T, provider credentialProvider, ctx context.Context, record credentialRecord, want error) {
	t.Helper()
	metadata, exists, err := provider.Metadata(ctx, record.Metadata.Name)
	if !errors.Is(err, want) || exists || metadata != (IdentityMetadata{}) {
		t.Fatalf("failed metadata: exists=%v err=%v", exists, err)
	}
	loaded, exists, err := provider.Load(ctx, record.Metadata.Name)
	if !errors.Is(err, want) || exists || len(loaded.Auth) != 0 || loaded.Metadata != (IdentityMetadata{}) {
		t.Fatalf("failed load: exists=%v err=%v", exists, err)
	}
	if rows, err := provider.List(ctx); !errors.Is(err, want) || len(rows) != 0 {
		t.Fatalf("failed list = %v", err)
	}
	for _, op := range []func() error{
		func() error { return provider.Create(ctx, record) },
		func() error { return provider.Replace(ctx, record) },
		func() error { return provider.Delete(ctx, record.Metadata.Name) },
	} {
		if err := op(); !errors.Is(err, want) {
			t.Fatalf("failed write = %v, want %v", err, want)
		}
	}
}

func TestKeychainProviderConformance(t *testing.T) {
	testProviderConformance(t, func() credentialProvider { return &keychainProvider{client: newFakeKeychainClient()} })
}

func TestUnavailableProviderFailsEveryOperation(t *testing.T) {
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	metadata, _ := validateAuthJSON("work", auth)
	record := credentialRecord{Metadata: metadata, Auth: auth}
	for _, err := range []error{ErrProviderNotSelected, ErrProviderChoice, ErrProviderUnavailable, nil} {
		testProviderFailures(t, unavailableProvider{err: err}, context.Background(), record, ErrProviderUnavailable)
	}
	testProviderFailures(t, &keychainProvider{client: unavailableKeychainClient{}}, context.Background(), record, ErrProviderUnavailable)
}
