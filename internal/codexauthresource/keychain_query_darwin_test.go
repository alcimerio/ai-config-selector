//go:build darwin

package codexauthresource

import (
	"errors"
	"testing"
)

func TestNativeKeychainDisablesFileKeychainUI(t *testing.T) {
	for _, status := range []int32{0, -1} {
		t.Run(map[bool]string{true: "success", false: "failure"}[status == 0], func(t *testing.T) {
			called := false
			api := &keychainAPI{secKeychainSetUserInteractionAllowed: func(allowed uint8) int32 {
				called = true
				if allowed != 0 {
					t.Fatal("file Keychain UI was enabled")
				}
				return status
			}}
			err := api.disableUserInteraction()
			if !called || (status == 0 && err != nil) || (status != 0 && !errors.Is(err, ErrProviderUnavailable)) {
				t.Fatalf("disable interaction = %v, called=%t", err, called)
			}
		})
	}
}

func TestNativeKeychainQueriesRequireAuthenticationUIToFail(t *testing.T) {
	const (
		dictionary           = uintptr(1)
		classKey             = uintptr(2)
		genericPassword      = uintptr(3)
		authenticationUIKey  = uintptr(4)
		authenticationUIFail = uintptr(5)
	)
	values := make(map[uintptr]uintptr)
	api := &keychainAPI{
		dictionarySetValue: func(gotDictionary, key, value uintptr) {
			if gotDictionary != dictionary {
				t.Fatal("configured an unexpected dictionary")
			}
			values[key] = value
		},
		secClass:                   classKey,
		secClassGenericPassword:    genericPassword,
		secUseAuthenticationUI:     authenticationUIKey,
		secUseAuthenticationUIFail: authenticationUIFail,
	}

	api.configureQuery(dictionary)
	if values[classKey] != genericPassword {
		t.Fatal("query omitted the generic-password class")
	}
	if values[authenticationUIKey] != authenticationUIFail {
		t.Fatal("query did not prohibit authentication UI")
	}
}
