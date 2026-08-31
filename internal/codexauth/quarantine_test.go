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
		Version: recordVersion, Name: "work", SessionID: "session-fixture", Phase: quarantinePrepared,
		ProofChallenge: testCleanupProofChallenge,
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
	if err := store.MarkCleanupPending(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkCleanupPending(context.Background(), "work"); err != nil {
		t.Fatalf("idempotent pending transition: %v", err)
	}
	got, exists, err = store.Inspect(context.Background(), "work")
	if err != nil || !exists || got.Phase != quarantineCleanupPending {
		t.Fatalf("pending marker = (%#v, %v, %v)", got, exists, err)
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
		directory:                             0o700,
		filepath.Join(directory, "work.json"): 0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode {
			t.Errorf("mode for %q = %o, want %o", path, info.Mode().Perm(), mode)
		}
	}
	contents, err := os.ReadFile(filepath.Join(directory, "work.json"))
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
		prepare func(*testing.T, string)
	}{
		{
			name: "missing phase",
			prepare: func(t *testing.T, directory string) {
				writeQuarantineFixture(t, directory, []byte(`{"version":1,"name":"work","sessionId":"session-fixture"}`))
			},
		},
		{
			name: "unknown field",
			prepare: func(t *testing.T, directory string) {
				writeQuarantineFixture(t, directory, []byte(`{"version":1,"name":"work","sessionId":"session-fixture","phase":"recoverable","secret":"no"}`))
			},
		},
		{
			name: "duplicate field",
			prepare: func(t *testing.T, directory string) {
				writeQuarantineFixture(t, directory, []byte(`{"version":1,"name":"work","name":"work","sessionId":"session-fixture","phase":"recoverable"}`))
			},
		},
		{
			name: "symlink",
			prepare: func(t *testing.T, directory string) {
				target := filepath.Join(filepath.Dir(directory), "target")
				if err := os.WriteFile(target, []byte(`{"version":1,"name":"work","sessionId":"session-fixture","phase":"recoverable"}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(directory, "work.json")); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard link",
			prepare: func(t *testing.T, directory string) {
				writeQuarantineFixture(t, directory, []byte(`{"version":1,"name":"work","sessionId":"session-fixture","phase":"recoverable"}`))
				if err := os.Link(filepath.Join(directory, "work.json"), filepath.Join(directory, "copy")); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "quarantine")
			store := newFileBindingQuarantine(directory)
			test.prepare(t, directory)
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
		ProofChallenge: testCleanupProofChallenge,
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

func TestFileBindingQuarantinePinsDirectoryAcrossAncestorReplacement(t *testing.T) {
	root := t.TempDir()
	ancestor := filepath.Join(root, "auth")
	directory := filepath.Join(ancestor, "quarantine")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store := newFileBindingQuarantine(directory)

	moved := filepath.Join(root, "auth-moved")
	if err := os.Rename(ancestor, moved); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(ancestor, "quarantine")
	if err := os.MkdirAll(replacement, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := quarantineMarker{
		Version: recordVersion, Name: "work", SessionID: "session-fixture", Phase: quarantinePrepared,
		ProofChallenge: testCleanupProofChallenge,
	}

	if err := store.Create(context.Background(), marker); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(moved, "quarantine", "work.json")); err != nil {
		t.Fatalf("pinned marker: %v", err)
	}
	if _, err := os.Stat(filepath.Join(replacement, "work.json")); !os.IsNotExist(err) {
		t.Fatalf("replacement marker error = %v", err)
	}
	if err := store.Create(context.Background(), marker); !errors.Is(err, ErrIdentityBusy) {
		t.Fatalf("duplicate pinned marker error = %v", err)
	}
	if err := store.MarkCleanupPending(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkRefreshAllowed(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	got, exists, err := store.Inspect(context.Background(), "work")
	if err != nil || !exists || got.Phase != quarantineCleanupPending || !got.RefreshAllowed {
		t.Fatalf("inspect pinned marker = (%#v, %v, %v)", got, exists, err)
	}
	if err := store.MarkRecoverable(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(moved, "quarantine", "work.json")); !os.IsNotExist(err) {
		t.Fatalf("deleted pinned marker error = %v", err)
	}
	entries, err := os.ReadDir(replacement)
	if err != nil || len(entries) != 0 {
		t.Fatalf("replacement quarantine entries = (%v, %v)", entries, err)
	}
}

func writeQuarantineFixture(t *testing.T, directory string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, "work.json"), contents, 0o600); err != nil {
		t.Fatal(err)
	}
}
