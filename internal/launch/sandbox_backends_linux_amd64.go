//go:build linux && amd64

package launch

func linuxNativeSandboxBackends() map[string]sandboxBackend {
	return map[string]sandboxBackend{"linux": linuxProductionBackend{}}
}
