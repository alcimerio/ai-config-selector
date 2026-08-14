//go:build darwin

package launch

func defaultSandboxBackends() map[string]sandboxBackend {
	return map[string]sandboxBackend{"darwin": newSeatbeltBackend(seatbeltExecutable)}
}
