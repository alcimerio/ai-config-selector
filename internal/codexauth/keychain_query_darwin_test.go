//go:build darwin

package codexauth

import "testing"

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
