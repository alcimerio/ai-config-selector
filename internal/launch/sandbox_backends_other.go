//go:build !darwin && !linux

package launch

func nativeSandboxBackends() map[string]sandboxBackend { return nil }

func currentLinuxRelease() (string, error) { return "", errLinuxReleaseUnavailable }
