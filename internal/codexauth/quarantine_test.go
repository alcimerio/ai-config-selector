package codexauth

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
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
	info, err := os.Stat(filepath.Join(directory, "work.json"))
	if err != nil {
		t.Fatal(err)
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("published marker lacks native metadata")
	}
	if native.Nlink != 1 {
		t.Fatalf("published marker link count = %v, want 1", native.Nlink)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != "work.json" {
		t.Fatalf("published marker entries = (%v, %v)", entries, err)
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

func TestFileBindingQuarantineFailsClosedAcrossAncestorReplacement(t *testing.T) {
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

	if err := store.Create(context.Background(), marker); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("detached store create error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(moved, "quarantine", "work.json")); !os.IsNotExist(err) {
		t.Fatalf("detached store wrote marker: %v", err)
	}
	if _, err := os.Stat(filepath.Join(replacement, "work.json")); !os.IsNotExist(err) {
		t.Fatalf("replacement marker error = %v", err)
	}

	replacementStore := newFileBindingQuarantine(replacement)
	if err := replacementStore.Create(context.Background(), marker); err != nil {
		t.Fatalf("replacement store create: %v", err)
	}
	got, exists, err := replacementStore.Inspect(context.Background(), "work")
	if err != nil || !exists || got != marker {
		t.Fatalf("replacement store marker = (%#v, %v, %v)", got, exists, err)
	}
}

func TestFileBindingQuarantineNeverFollowsSwappedAncestor(t *testing.T) {
	root := t.TempDir()
	ancestor := filepath.Join(root, "auth")
	directory := filepath.Join(ancestor, "quarantine")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	store := newFileBindingQuarantine(directory)
	moved := filepath.Join(root, "auth-detached")
	if err := os.Rename(ancestor, moved); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "attacker", "quarantine")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(target), ancestor); err != nil {
		t.Fatal(err)
	}
	marker := quarantineMarker{
		Version: recordVersion, Name: "work", SessionID: "session-fixture",
		Phase: quarantinePrepared, ProofChallenge: testCleanupProofChallenge,
	}
	if err := store.Create(context.Background(), marker); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("swapped ancestor error = %v", err)
	}
	for _, path := range []string{
		filepath.Join(moved, "quarantine", "work.json"),
		filepath.Join(target, "work.json"),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("swapped ancestor received marker at %q: %v", path, err)
		}
	}
}

func TestPrivateDirectoryExclusiveRenamePublishesOneCrashSafeLink(t *testing.T) {
	directory := newFileBindingQuarantine(filepath.Join(t.TempDir(), "quarantine")).directory
	temporary, temporaryName, err := directory.createTemporary(".marker-")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := temporary.Write([]byte("marker")); err != nil {
		t.Fatal(err)
	}
	if err := temporary.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := temporary.Close(); err != nil {
		t.Fatal(err)
	}
	if err := directory.renameNoReplace(temporaryName, "work.json"); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.open(temporaryName, syscall.O_RDONLY, 0); !errors.Is(err, syscall.ENOENT) {
		t.Fatalf("temporary marker survived publication: %v", err)
	}
	file, err := directory.open("work.json", syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	_ = file.Close()
	if err != nil {
		t.Fatal(err)
	}
	native := info.Sys().(*syscall.Stat_t)
	if native.Nlink != 1 {
		t.Fatalf("published marker link count = %d, want 1", native.Nlink)
	}
	second, secondName, err := directory.createTemporary(".marker-")
	if err != nil {
		t.Fatal(err)
	}
	_ = second.Close()
	defer directory.unlink(secondName)
	if err := directory.renameNoReplace(secondName, "work.json"); !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("exclusive rename error = %v", err)
	}
}

func writeQuarantineFixture(t *testing.T, directory string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, "work.json"), contents, 0o600); err != nil {
		t.Fatal(err)
	}
}
