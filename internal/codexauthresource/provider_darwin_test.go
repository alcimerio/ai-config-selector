package codexauthresource

import (
	"errors"
	"testing"
)

func TestDarwinProviderFactoryKeepsKeychain(t *testing.T) {
	// Even hostile Linux configuration must not change existing Mac behavior.
	t.Setenv("XDG_CONFIG_HOME", "relative-invalid-linux-configuration")
	if id, err := SelectedProvider(); err != nil || id != ProviderKeychain {
		t.Fatalf("selected provider = (%q, %v)", id, err)
	}
	if _, ok := newPlatformProvider().(*keychainProvider); !ok {
		t.Fatal("production factory did not select the existing Keychain provider")
	}
	if err := SelectProvider(ProviderKeychain); err != nil {
		t.Fatal(err)
	}
	for _, id := range []ProviderID{ProviderFile, ProviderSecretService, "", "unknown"} {
		if err := SelectProvider(id); !errors.Is(err, ErrProviderChoice) {
			t.Fatalf("select %q = %v", id, err)
		}
		if _, ok := newCredentialProvider(id).(unavailableProvider); !ok {
			t.Fatalf("factory allowed alternative provider %q", id)
		}
	}
}
