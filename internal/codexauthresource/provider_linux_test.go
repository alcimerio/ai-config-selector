package codexauthresource

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func providerTestConfig(t *testing.T) string {
	t.Helper()
	// The production check rejects every untrusted ancestor. Use the owned
	// checkout's ignored build directory (also excluded by documentation scans)
	// because some containers map the owner of /tmp to nobody.
	err := os.Mkdir("dist", 0o700)
	createdParent := err == nil
	if err != nil && !os.IsExist(err) {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("dist", ".provider-test-")
	if err != nil {
		t.Fatal(err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Error(err)
		}
		if createdParent {
			_ = os.Remove("dist")
		}
	})
	t.Setenv("HOME", root)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	for _, variable := range []string{"XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR"} {
		t.Setenv(variable, filepath.Join(root, variable))
	}
	return filepath.Join(root, "config", "acs")
}

func TestLinuxProviderChoiceIsExplicitAndDurable(t *testing.T) {
	for _, id := range []ProviderID{ProviderFile, ProviderSecretService} {
		t.Run(string(id), func(t *testing.T) {
			directory := providerTestConfig(t)
			if chosen, err := SelectedProvider(); chosen != "" || !errors.Is(err, ErrProviderNotSelected) {
				t.Fatalf("unchosen = (%q, %v)", chosen, err)
			}
			if _, err := os.Stat(filepath.Dir(directory)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("read provisioned configuration: %v", err)
			}
			if err := SelectProvider(id); err != nil {
				t.Fatal(err)
			}
			if chosen, err := readProviderSelection(directory); err != nil || chosen != id {
				t.Fatalf("reopened choice = (%q, %v)", chosen, err)
			}
			if err := SelectProvider(id); err != nil {
				t.Fatalf("repeat selection = %v", err)
			}
			other := ProviderFile
			if id == other {
				other = ProviderSecretService
			}
			if err := SelectProvider(other); !errors.Is(err, ErrProviderConflict) {
				t.Fatalf("namespace switch = %v", err)
			}
			for path, mode := range map[string]os.FileMode{directory: 0o700, filepath.Join(directory, providerSelectionFilename): 0o600} {
				info, err := os.Stat(path)
				if err != nil || info.Mode().Perm() != mode {
					t.Fatalf("private selection mode: %v", err)
				}
			}
			for _, variable := range []string{"XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR"} {
				if _, err := os.Stat(os.Getenv(variable)); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("selection created %s storage: %v", variable, err)
				}
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 1 || entries[0].Name() != providerSelectionFilename {
				t.Fatalf("selection left unexpected files: %v", err)
			}
		})
	}
}

func TestLinuxProviderFactoryNeverFallsBack(t *testing.T) {
	for _, id := range []ProviderID{"", ProviderSecretService} {
		t.Run(string(id), func(t *testing.T) {
			providerTestConfig(t)
			if id != "" {
				if err := SelectProvider(id); err != nil {
					t.Fatal(err)
				}
			}
			auth := testChatGPTAuthJSON(t, "user", "workspace")
			metadata, _ := validateAuthJSON("work", auth)
			provider := newPlatformProvider()
			testProviderFailures(t, provider, context.Background(), credentialRecord{Metadata: metadata, Auth: auth}, ErrProviderUnavailable)
			store, err := New(t.TempDir(), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := store.List(context.Background()); !errors.Is(err, ErrProviderUnavailable) {
				t.Fatalf("production list = %v", err)
			}
			if binding, err := store.AcquireLogin(context.Background(), "work"); binding != nil || !errors.Is(err, ErrProviderUnavailable) {
				t.Fatalf("production login = (%v, %v)", binding, err)
			}
			if binding, _, err := store.AcquireStatus(context.Background(), "work"); binding != nil || !errors.Is(err, ErrProviderUnavailable) {
				t.Fatalf("production status = (%v, %v)", binding, err)
			}
		})
	}
	for _, id := range []ProviderID{ProviderKeychain, "unknown", ""} {
		if _, ok := newCredentialProvider(id).(unavailableProvider); !ok {
			t.Fatalf("factory accepted %q", id)
		}
	}
}

func TestLinuxProviderConfigUsesXDGOrHome(t *testing.T) {
	providerTestConfig(t)
	t.Setenv("XDG_CONFIG_HOME", "")
	want := filepath.Join(os.Getenv("HOME"), ".config", "acs")
	if got, err := providerConfigDirectory(); err != nil || got != want {
		t.Fatalf("default directory = (%q, %v)", got, err)
	}
	if err := SelectProvider(ProviderFile); err != nil {
		t.Fatal(err)
	}
	if got, err := readProviderSelection(want); err != nil || got != ProviderFile {
		t.Fatalf("default choice = (%q, %v)", got, err)
	}
	for _, variable := range []string{"XDG_CONFIG_HOME", "HOME"} {
		t.Setenv(variable, "private-relative-value")
		if _, err := SelectedProvider(); !errors.Is(err, ErrProviderChoice) || strings.Contains(err.Error(), "private-relative-value") {
			t.Fatalf("relative %s error = %v", variable, err)
		}
		t.Setenv(variable, "")
	}
}

func TestLinuxProviderRejectsInvalidSelectionWithoutChangingIt(t *testing.T) {
	for _, contents := range []string{
		`{}`, `null`, `{"version":2,"provider":"file"}`, `{"version":1,"provider":"unknown"}`,
		`{"version":1,"provider":"keychain"}`, `{"version":1,"provider":"file","extra":true}`,
		`{"version":1,"provider":"file","provider":"secret-service"}`,
		`{"version":1,"provider":"secret-service","PROVIDER":"file"}`, `{"version":1,"Provider":"file"}`,
		`{"version":1,"provider":"file"} {}`, `{"version":1,"provider":"file"`, strings.Repeat("x", maximumProviderSelectionSize+1),
	} {
		t.Run(contents, func(t *testing.T) {
			directory := providerTestConfig(t)
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, providerSelectionFilename)
			if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := SelectedProvider(); !errors.Is(err, ErrProviderChoice) {
				t.Fatalf("invalid choice error = %v", err)
			}
			if err := SelectProvider(ProviderFile); !errors.Is(err, ErrProviderChoice) {
				t.Fatalf("overwrote invalid choice: %v", err)
			}
			if actual, err := os.ReadFile(path); err != nil || string(actual) != contents {
				t.Fatalf("invalid choice was changed: %v", err)
			}
		})
	}
}

func TestLinuxProviderRejectsUnsafeStorage(t *testing.T) {
	for name, mutate := range map[string]func(string) error{
		"public file":      func(path string) error { return os.Chmod(path, 0o644) },
		"read only file":   func(path string) error { return os.Chmod(path, 0o400) },
		"public directory": func(path string) error { return os.Chmod(filepath.Dir(path), 0o755) },
		"writable parent":  func(path string) error { return os.Chmod(filepath.Dir(filepath.Dir(path)), 0o777) },
		"hard link":        func(path string) error { return os.Link(path, path+".alias") },
		"symlink": func(path string) error {
			if err := os.Rename(path, path+".target"); err != nil {
				return err
			}
			return os.Symlink(path+".target", path)
		},
		"directory": func(path string) error {
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Mkdir(path, 0o700)
		},
		"fifo": func(path string) error {
			if err := os.Remove(path); err != nil {
				return err
			}
			return unix.Mkfifo(path, 0o600)
		},
		"symlink parent": func(path string) error {
			parent := filepath.Dir(path)
			if err := os.Rename(parent, parent+".target"); err != nil {
				return err
			}
			return os.Symlink(parent+".target", parent)
		},
	} {
		t.Run(name, func(t *testing.T) {
			directory := providerTestConfig(t)
			if err := SelectProvider(ProviderFile); err != nil {
				t.Fatal(err)
			}
			if err := mutate(filepath.Join(directory, providerSelectionFilename)); err != nil {
				t.Fatal(err)
			}
			if _, err := SelectedProvider(); !errors.Is(err, ErrProviderChoice) {
				t.Fatalf("unsafe storage error = %v", err)
			}
			if err := SelectProvider(ProviderFile); !errors.Is(err, ErrProviderChoice) {
				t.Fatalf("selection repaired unsafe storage: %v", err)
			}
		})
	}
}

func TestLinuxProviderConcurrentSelectionCannotSwitchNamespaces(t *testing.T) {
	directory := providerTestConfig(t)
	var workers sync.WaitGroup
	results := make(chan error, 16)
	for i := range 16 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			id := ProviderFile
			if i%2 == 0 {
				id = ProviderSecretService
			}
			results <- SelectProvider(id)
		}()
	}
	workers.Wait()
	close(results)
	for err := range results {
		if err != nil && !errors.Is(err, ErrProviderConflict) {
			t.Fatalf("concurrent selection = %v", err)
		}
	}
	id, err := readProviderSelection(directory)
	if err != nil || (id != ProviderFile && id != ProviderSecretService) {
		t.Fatalf("winning choice = (%q, %v)", id, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary files remained: %v", err)
	}
}
