package launch

import (
	"context"
	"errors"
	"testing"
)

func TestProcessSandboxCachesSuccessfulBackendCheckPerSelector(t *testing.T) {
	probes := 0
	backend := &capturingBackend{}
	sandbox := newNativeProcessSandbox(
		func() (Platform, error) {
			probes++
			return Platform{OS: "darwin", Architecture: "arm64", Release: "26.1"}, nil
		},
		map[string]sandboxBackend{"darwin": backend},
	)
	for range 4 {
		if _, err := sandbox.selectedBackend(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if err := sandbox.checkEnvironmentTransport(); err != nil {
		t.Fatal(err)
	}
	if probes != 1 || backend.checks != 1 {
		t.Fatalf("platform probes = %d, backend checks = %d; want 1 and 1", probes, backend.checks)
	}
}

func TestProcessSandboxRetriesFailedBackendCheck(t *testing.T) {
	probes := 0
	backend := &capturingBackend{checkErr: errors.New("transient")}
	sandbox := newNativeProcessSandbox(
		func() (Platform, error) {
			probes++
			if probes == 1 {
				return Platform{}, errors.New("sw_vers failed")
			}
			return Platform{OS: "darwin", Architecture: "arm64", Release: "26.1"}, nil
		},
		map[string]sandboxBackend{"darwin": backend},
	)
	if _, err := sandbox.selectedBackend(context.Background()); err == nil {
		t.Fatal("failed platform probe was accepted")
	}
	if _, err := sandbox.selectedBackend(context.Background()); err == nil {
		t.Fatal("failed backend check was accepted")
	}
	backend.checkErr = nil
	if _, err := sandbox.selectedBackend(context.Background()); err != nil {
		t.Fatalf("recovered backend rejected: %v", err)
	}
	if _, err := sandbox.selectedBackend(context.Background()); err != nil {
		t.Fatal(err)
	}
	if probes != 2 || backend.checks != 2 {
		t.Fatalf("platform probes = %d, backend checks = %d; want 2 and 2 (failures are never cached)", probes, backend.checks)
	}
}

func TestNewProcessSandboxIsSharedPerProcess(t *testing.T) {
	if NewProcessSandbox() != NewProcessSandbox() {
		t.Fatal("NewProcessSandbox returned distinct selectors; backend checks would repeat per caller")
	}
}
