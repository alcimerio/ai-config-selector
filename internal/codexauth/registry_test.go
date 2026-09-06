package codexauth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRegistryForwardsFixedOperationsToExecutor(t *testing.T) {
	root := t.TempDir()
	sessionsDirectory := filepath.Join(root, "sessions")
	registry, err := New(Config{
		BinaryPath: "/usr/bin/true", ACSHome: filepath.Join(root, "acs"),
		SessionsDirectory: sessionsDirectory, WorkingDirectory: root,
	})
	if err != nil {
		t.Fatal(err)
	}
	for operation, err := range map[string]error{
		"login": func() error {
			_, err := registry.Login(context.Background(), LoginRequest{Name: "Invalid"})
			return err
		}(),
		"status":  func() error { _, err := registry.Status(context.Background(), "Invalid"); return err }(),
		"recover": func() error { _, err := registry.Recover(context.Background(), "Invalid"); return err }(),
		"logout":  registry.Logout(context.Background(), "Invalid"),
	} {
		if !errors.Is(err, ErrInvalidCredentialRef) {
			t.Fatalf("%s error = %v", operation, err)
		}
	}
	if _, err := os.Stat(sessionsDirectory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("invalid operations created Sessions state: %v", err)
	}
}

func TestRegistryRejectsIncompleteExecutorConfiguration(t *testing.T) {
	if registry, err := New(Config{}); registry != nil || err == nil || err.Error() != "create Codex authentication registry: binary path is required" {
		t.Fatalf("construction = (%#v, %v)", registry, err)
	}
}
