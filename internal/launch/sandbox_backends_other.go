//go:build !darwin

package launch

func defaultSandboxBackends() map[string]sandboxBackend {
	return nil
}
