package main

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestBuildVersionUsesTaggedModuleMetadata(t *testing.T) {
	version := buildVersion(func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}}, true
	})
	if version != "v0.1.0" {
		t.Fatalf("version = %q, want v0.1.0", version)
	}
}

func TestBuildVersionFallsBackForDevelopmentAndUnavailableMetadata(t *testing.T) {
	tests := []struct {
		name string
		read func() (*debug.BuildInfo, bool)
	}{
		{name: "development", read: func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true
		}},
		{name: "empty version", read: func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{}, true
		}},
		{name: "local pseudo-version", read: func() (*debug.BuildInfo, bool) {
			return &debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20260805002849-816e7b63d8fb+dirty"}}, true
		}},
		{name: "unavailable", read: func() (*debug.BuildInfo, bool) {
			return nil, false
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if version := buildVersion(test.read); version != "devel" {
				t.Fatalf("version = %q, want devel", version)
			}
		})
	}
}

func TestRequireSupportedPlatformAcceptsDarwinAndLinux(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			if err := requireSupportedPlatform(goos); err != nil {
				t.Fatalf("%s rejected: %v", goos, err)
			}
		})
	}
}

func TestRequireSupportedPlatformRejectsEveryOtherOperatingSystemFamily(t *testing.T) {
	for _, goos := range []string{"aix", "android", "dragonfly", "freebsd", "illumos", "ios", "js", "netbsd", "openbsd", "plan9", "solaris", "wasip1", "windows"} {
		t.Run(goos, func(t *testing.T) {
			err := requireSupportedPlatform(goos)
			if err == nil {
				t.Fatal("unsupported platform was accepted")
			}
			for _, want := range []string{"macOS", "Linux", goos} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("unsupported-platform error omits %q: %v", want, err)
				}
			}
		})
	}
}
