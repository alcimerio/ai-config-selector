package launch

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestSandboxReadinessReportsSelectedBackendAndExactSupportedPlatformResult(t *testing.T) {
	backend := &capturingBackend{}
	sandbox := newNativeProcessSandbox(
		func() (Platform, error) {
			return Platform{OS: "linux", Architecture: "arm64", Distribution: "ubuntu", Release: "24.04.3"}, nil
		},
		map[string]sandboxBackend{"linux": backend},
	)

	readiness, err := sandbox.Readiness(context.Background())
	if err != nil {
		t.Fatalf("readiness: %v", err)
	}
	if got, want := readiness.RequiredMode, "native"; got != want {
		t.Errorf("required mode = %q, want %q", got, want)
	}
	if got, want := readiness.Backend, "Bubblewrap"; got != want {
		t.Errorf("backend = %q, want %q", got, want)
	}
	if got, want := readiness.Platform, "Ubuntu 24.04.3 LTS on linux/arm64"; got != want {
		t.Errorf("platform = %q, want %q", got, want)
	}
	if !readiness.Supported {
		t.Error("supported platform reported as unsupported")
	}
	if !readiness.Ready {
		t.Error("available backend reported as unavailable")
	}
	if backend.checks != 1 {
		t.Fatalf("backend checks = %d, want 1", backend.checks)
	}
}

func TestSandboxReadinessReportsUnsupportedPlatformWithoutCheckingABackend(t *testing.T) {
	backend := &capturingBackend{}
	sandbox := newNativeProcessSandbox(
		func() (Platform, error) {
			return Platform{OS: "linux", Architecture: "amd64", Distribution: "debian", Release: "12"}, nil
		},
		map[string]sandboxBackend{"linux": backend},
	)

	readiness, err := sandbox.Readiness(context.Background())
	if err != nil {
		t.Fatalf("readiness: %v", err)
	}
	if readiness.Supported {
		t.Error("unsupported platform reported as supported")
	}
	if readiness.Ready {
		t.Error("unsupported platform reported as ready")
	}
	if got, want := readiness.Backend, "Bubblewrap"; got != want {
		t.Errorf("backend = %q, want %q", got, want)
	}
	if got, want := readiness.Platform, "Debian 12 on linux/amd64"; got != want {
		t.Errorf("platform = %q, want %q", got, want)
	}
	if got, want := readiness.Failure.Category, SandboxUnsupportedPlatform; got != want {
		t.Errorf("failure category = %q, want %q", got, want)
	}
	if backend.checks != 0 {
		t.Fatalf("backend checks = %d, want 0", backend.checks)
	}
}

func TestSandboxReadinessSanitizesBackendVerificationFailure(t *testing.T) {
	backend := &capturingBackend{checkErr: errors.New("PRIVATE_BACKEND_OUTPUT\n\x1b[31m")}
	sandbox := newNativeProcessSandbox(
		func() (Platform, error) {
			return Platform{OS: "darwin", Architecture: "amd64", Release: "26.1"}, nil
		},
		map[string]sandboxBackend{"darwin": backend},
	)

	readiness, err := sandbox.Readiness(context.Background())
	if err != nil {
		t.Fatalf("readiness: %v", err)
	}
	if readiness.Ready {
		t.Error("failed verification reported as ready")
	}
	if got, want := readiness.Failure.Category, SandboxVerificationFailed; got != want {
		t.Errorf("failure category = %q, want %q", got, want)
	}
	for _, private := range []string{"PRIVATE_BACKEND_OUTPUT", "\n", "\x1b"} {
		if strings.Contains(readiness.Failure.Error(), private) {
			t.Fatalf("readiness leaked %q: %q", private, readiness.Failure)
		}
	}
}
