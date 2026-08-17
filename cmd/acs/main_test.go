package main

import (
	"runtime/debug"
	"testing"
)

func TestBuildVersionUsesTaggedModuleMetadata(t *testing.T) {
	version := buildVersion("", func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Main: debug.Module{Version: "v0.1.0"}}, true
	})
	if version != "v0.1.0" {
		t.Fatalf("version = %q, want v0.1.0", version)
	}
}

func TestBuildVersionUsesCanonicalReleaseBuilderTag(t *testing.T) {
	version := buildVersion("v0.2.0", func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true
	})
	if version != "v0.2.0" {
		t.Fatalf("version = %q, want v0.2.0", version)
	}
}

func TestBuildVersionRejectsUnqualifiedReleaseBuilderMetadata(t *testing.T) {
	tests := []struct {
		name    string
		release string
		info    *debug.BuildInfo
	}{
		{name: "empty", release: "", info: &debug.BuildInfo{}},
		{name: "malformed", release: "0.2.0", info: &debug.BuildInfo{}},
		{name: "prerelease", release: "v0.2.0-rc.1", info: &debug.BuildInfo{}},
		{name: "pseudo-version", release: "v0.0.0-20260805002849-816e7b63d8fb", info: &debug.BuildInfo{}},
		{name: "dirty", release: "v0.2.0", info: &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.modified", Value: "true"}}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			version := buildVersion(test.release, func() (*debug.BuildInfo, bool) {
				return test.info, true
			})
			if version != "devel" {
				t.Fatalf("version = %q, want devel", version)
			}
		})
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
			if version := buildVersion("", test.read); version != "devel" {
				t.Fatalf("version = %q, want devel", version)
			}
		})
	}
}
