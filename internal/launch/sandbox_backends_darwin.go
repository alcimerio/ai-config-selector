//go:build darwin

package launch

func nativeSandboxBackends() map[string]sandboxBackend {
	return map[string]sandboxBackend{"darwin": newSeatbeltBackend(seatbeltExecutable)}
}
