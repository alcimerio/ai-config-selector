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

func TestRequireSupportedPlatformRejectsNonDarwin(t *testing.T) {
	if err := requireSupportedPlatform("darwin"); err != nil {
		t.Fatalf("darwin rejected: %v", err)
	}
	err := requireSupportedPlatform("linux")
	if err == nil {
		t.Fatal("unsupported platform was accepted")
	}
	if !strings.Contains(err.Error(), "macOS") || !strings.Contains(err.Error(), "linux") {
		t.Fatalf("unsupported-platform error is unclear: %v", err)
	}
}
