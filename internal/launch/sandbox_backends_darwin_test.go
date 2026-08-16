//go:build darwin

package launch

import "testing"

func TestProductionDarwinSandboxRegistersSeatbelt(t *testing.T) {
	backends := nativeSandboxBackends()
	backend, ok := backends["darwin"].(*seatbeltBackend)
	if !ok || backend == nil {
		t.Fatalf("production Darwin sandbox backend = %T, want *seatbeltBackend", backends["darwin"])
	}
	if len(backends) != 1 {
		t.Fatalf("production Darwin sandbox backends = %v, want only darwin", backends)
	}
}
