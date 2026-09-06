//go:build !darwin

package codexauthresource

func newNativeKeychainClient() (keychainClient, error) { return unavailableKeychainClient{}, nil }
