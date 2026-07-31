package main

import (
	"strings"
	"testing"
)

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
