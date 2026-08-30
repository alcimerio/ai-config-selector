package codexauth

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFileBindingQuarantineCreatesPrivateSecretFreeMarkerWithoutReplacement(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "quarantine")
	store := newFileBindingQuarantine(directory)
	marker := quarantineMarker{
		Version: recordVersion, Name: "work", SessionID: "session-fixture", Phase: quarantineCleanupPending,
	}

	if err := store.Create(context.Background(), marker); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(context.Background(), marker); !errors.Is(err, ErrIdentityBusy) {
		t.Fatalf("duplicate marker error = %v", err)
	}
	got, exists, err := store.Inspect(context.Background(), "work")
	if err != nil || !exists || got != marker {
		t.Fatalf("inspect = (%#v, %v, %v)", got, exists, err)
	}
	if err := store.MarkRecoverable(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkRecoverable(context.Background(), "work"); err != nil {
		t.Fatalf("idempotent recoverable transition: %v", err)
	}
	got, exists, err = store.Inspect(context.Background(), "work")
	if err != nil || !exists || got.Phase != quarantineRecoverable {
		t.Fatalf("recoverable marker = (%#v, %v, %v)", got, exists, err)
	}

	for path, mode := range map[string]os.FileMode{
		directory:          0o700,
		store.path("work"): 0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Errorf("mode for %q = %o, want %o", path, info.Mode().Perm(), mode)
		}
	}
	contents, err := os.ReadFile(store.path("work"))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"auth.json", "token", "fingerprint", "workspace"} {
		if bytes.Contains(contents, []byte(forbidden)) {
			t.Fatalf("quarantine marker contains forbidden field %q: %s", forbidden, contents)
		}
	}

	if err := store.Delete(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := store.Inspect(context.Background(), "work"); err != nil || exists {
		t.Fatalf("inspect after delete = (%v, %v)", exists, err)
	}
}

func TestFileBindingQuarantineRejectsMalformedAndLinkedMarkers(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*testing.T, *fileBindingQuarantine)
	}{
		{
			name: "missing phase",
			prepare: func(t *testing.T, store *fileBindingQuarantine) {
				writeQuarantineFixture(t, store, []byte(`{"version":1,"name":"work","sessionId":"session-fixture"}`))
			},
		},
		{
			name: "unknown field",
			prepare: func(t *testing.T, store *fileBindingQuarantine) {
				writeQuarantineFixture(t, store, []byte(`{"version":1,"name":"work","sessionId":"session-fixture","phase":"recoverable","secret":"no"}`))
			},
		},
		{
			name: "duplicate field",
			prepare: func(t *testing.T, store *fileBindingQuarantine) {
				writeQuarantineFixture(t, store, []byte(`{"version":1,"name":"work","name":"work","sessionId":"session-fixture","phase":"recoverable"}`))
			},
		},
		{
			name: "symlink",
			prepare: func(t *testing.T, store *fileBindingQuarantine) {
				if err := os.MkdirAll(store.directory, 0o700); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(filepath.Dir(store.directory), "target")
				if err := os.WriteFile(target, []byte(`{"version":1,"name":"work","sessionId":"session-fixture","phase":"recoverable"}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, store.path("work")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard link",
			prepare: func(t *testing.T, store *fileBindingQuarantine) {
				writeQuarantineFixture(t, store, []byte(`{"version":1,"name":"work","sessionId":"session-fixture","phase":"recoverable"}`))
				if err := os.Link(store.path("work"), filepath.Join(store.directory, "copy")); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newFileBindingQuarantine(filepath.Join(t.TempDir(), "quarantine"))
			test.prepare(t, store)
			if _, _, err := store.Inspect(context.Background(), "work"); !errors.Is(err, ErrProviderUnavailable) {
				t.Fatalf("inspect error = %v", err)
			}
		})
	}
}

func TestFileBindingQuarantineRejectsSymlinkDirectoryWithoutChangingTarget(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "quarantine")
	if err := os.Symlink(target, directory); err != nil {
		t.Fatal(err)
	}
	store := newFileBindingQuarantine(directory)
	marker := quarantineMarker{
		Version: recordVersion, Name: "work", SessionID: "session-fixture", Phase: quarantineCleanupPending,
	}
	if err := store.Create(context.Background(), marker); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("symlink directory error = %v", err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("symlink target mode changed to %o", info.Mode().Perm())
	}
}

func writeQuarantineFixture(t *testing.T, store *fileBindingQuarantine, contents []byte) {
	t.Helper()
	if err := os.MkdirAll(store.directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(store.path("work"), contents, 0o600); err != nil {
		t.Fatal(err)
	}
}
