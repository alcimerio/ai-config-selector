package launch

import (
	"context"
	"runtime"
	"strings"
	"testing"
)

func TestLinuxAmd64RegistersTheQualifiedBackend(t *testing.T) {
	backends := nativeSandboxBackends()
	if runtime.GOARCH == "amd64" {
		if _, ok := backends["linux"]; !ok || len(backends) != 0 && len(backends) != 1 {
			t.Fatalf("Linux sandbox backends = %v", backends)
		}
		if _, ok := backends["linux"]; !ok {
			t.Fatal("linux/amd64 backend is not registered")
		}
		return
	}
	if len(backends) != 0 {
		t.Fatalf("unqualified Linux architecture registered backends: %v", backends)
	}
}

func TestLinuxSandboxFailsClosed(t *testing.T) {
	if err := ValidatePlatform(Platform{OS: "linux", Architecture: "arm64", Release: "6.12.0"}); err == nil {
		t.Fatal("linux/arm64 admitted")
	} else {
		assertLinuxUnsupported(t, err)
	}
	if err := ValidatePlatform(Platform{OS: "linux", Architecture: "amd64", Release: "6.12.0"}); err != nil {
		t.Fatal(err)
	}
	sandbox := NewProcessSandbox()
	err := sandbox.Check(context.Background(), SandboxCheck{})
	if err == nil || !strings.Contains(err.Error(), requiredSandboxNotice) {
		t.Fatalf("empty Linux check = %v", err)
	}
	readiness, readyErr := sandbox.Readiness(context.Background())
	if readyErr != nil {
		t.Fatal(readyErr)
	}
	if runtime.GOARCH != "amd64" {
		if readiness.Supported || readiness.Ready {
			t.Fatalf("unqualified architecture readiness = %+v", readiness)
		}
		return
	}
	if !readiness.Supported || readiness.Backend != "Bubblewrap" {
		t.Fatalf("linux/amd64 readiness = %+v", readiness)
	}
	if readiness.Ready == (readiness.Failure != nil) {
		t.Fatalf("readiness ready/failure mismatch: %+v", readiness)
	}
}

func assertLinuxUnsupported(t *testing.T, err error) {
	t.Helper()
	assertSandboxCategory(t, err, SandboxUnsupportedPlatform)
	for _, want := range []string{
		"Linux support requires native linux/amd64",
		"ACS never runs targets unsandboxed",
		"docs/design/linux-support.md",
		requiredSandboxNotice,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}
