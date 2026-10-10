package launch

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestLinuxHasNoSandboxBackend(t *testing.T) {
	if backends := nativeSandboxBackends(); len(backends) != 0 {
		t.Fatalf("Linux registered sandbox backends: %v", backends)
	}
}

func TestLinuxSandboxFailsClosed(t *testing.T) {
	sandbox := NewProcessSandbox()
	_, platformErr := CurrentPlatform()
	_, prepareErr := sandbox.Prepare(context.Background(), ProcessRequest{})
	for name, err := range map[string]error{
		"platform":   platformErr,
		"validation": ValidatePlatform(Platform{OS: "linux", Architecture: runtime.GOARCH}),
		"check":      sandbox.Check(context.Background(), SandboxCheck{}),
		"environment check": sandbox.Check(context.Background(), SandboxCheck{
			RequiresEnvironment: true,
		}),
		"prepare": prepareErr,
	} {
		t.Run(name, func(t *testing.T) { assertLinuxUnsupported(t, err) })
	}
	readiness, err := sandbox.Readiness(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if readiness.Supported || readiness.Ready || readiness.Backend != "None" {
		t.Fatalf("Linux readiness = %+v", readiness)
	}
	assertLinuxUnsupported(t, readiness.Failure)
}

func assertLinuxUnsupported(t *testing.T, err error) {
	t.Helper()
	assertSandboxCategory(t, err, SandboxUnsupportedPlatform)
	for _, want := range []string{
		"Linux sandbox backend is not available yet",
		"ACS never runs targets unsandboxed",
		"docs/design/linux-support.md",
		requiredSandboxNotice,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}
