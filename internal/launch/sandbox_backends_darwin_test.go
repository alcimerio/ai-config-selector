//go:build darwin

package launch

import (
	"context"
	"testing"
)

func TestProductionDarwinSandboxRemainsUnavailable(t *testing.T) {
	sandbox := newNativeProcessSandbox(func() (Platform, error) {
		return Platform{OS: "darwin", Architecture: "arm64", Release: "26.0"}, nil
	}, nativeSandboxBackends())
	err := sandbox.Check(context.Background(), SandboxCheck{})
	if err == nil {
		t.Fatal("production Darwin sandbox unexpectedly registered a backend")
	}
	assertSandboxCategory(t, err, SandboxBackendUnavailable)
}
