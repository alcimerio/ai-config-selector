//go:build !darwin

package codexauth

func newNativeKeychainClient() (keychainClient, error) { return unavailableKeychainClient{}, nil }
