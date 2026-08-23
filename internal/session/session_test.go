package session_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/session"
)

type recordingMaterializer struct {
	home string
}

func (materializer *recordingMaterializer) Materialize(home string) error {
	materializer.home = home
	bundle := filepath.Join(home, ".agents", "skills", "review")
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(bundle, "SKILL.md"), []byte("# review\n"), 0o600)
}

func TestCreateMaterializesProfileIntoLeasedSyntheticHome(t *testing.T) {
	sessionsDirectory := filepath.Join(t.TempDir(), "sessions")
	workingDirectory := t.TempDir()
	materializer := &recordingMaterializer{}

	created, err := session.Create(sessionsDirectory, workingDirectory, materializer)
	if err != nil {
		t.Fatal(err)
	}
	root := created.RootDirectory()
	defer func() {
		if err := created.Remove(); err != nil {
			t.Fatal(err)
		}
	}()

	if materializer.home != created.HomeDirectory() {
		t.Fatalf("materializer home = %q, want %q", materializer.home, created.HomeDirectory())
	}
	if filepath.Dir(root) != sessionsDirectory {
		t.Fatalf("Session root = %q, want child of %q", root, sessionsDirectory)
	}
	for _, directory := range []string{
		created.HomeDirectory(),
		created.TemporaryDirectory(),
		filepath.Join(created.HomeDirectory(), ".config"),
		filepath.Join(created.HomeDirectory(), ".local", "share"),
		filepath.Join(created.HomeDirectory(), ".cache"),
		filepath.Join(created.HomeDirectory(), ".local", "state"),
	} {
		info, err := os.Stat(directory)
		if err != nil {
			t.Fatalf("stat synthetic Session directory: %v", err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Errorf("permissions for %q = %o, want 700", directory, info.Mode().Perm())
		}
	}
	if _, err := os.Stat(filepath.Join(created.HomeDirectory(), ".agents", "skills", "review", "SKILL.md")); err != nil {
		t.Fatalf("selected Skill was not materialized: %v", err)
	}
	verification := created.VerificationContext()
	if verification.SessionsDirectory != sessionsDirectory ||
		verification.SessionDirectory != root ||
		verification.SessionHome != created.HomeDirectory() ||
		verification.TemporaryDirectory != created.TemporaryDirectory() ||
		verification.WorkingDirectory != workingDirectory {
		t.Fatalf("verification context = %#v", verification)
	}

	if err := created.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("Remove left Session root behind: %v", err)
	}
}

type failingMaterializer struct{}

func (failingMaterializer) Materialize(home string) error {
	if err := os.WriteFile(filepath.Join(home, "partial"), []byte("sensitive"), 0o600); err != nil {
		return err
	}
	return errors.New("materialization failed")
}

func TestCreateRemovesPartialSessionWhenMaterializationFails(t *testing.T) {
	sessionsDirectory := filepath.Join(t.TempDir(), "sessions")
	if _, err := session.Create(sessionsDirectory, t.TempDir(), failingMaterializer{}); err == nil {
		t.Fatal("Session creation unexpectedly succeeded")
	}
	entries, err := os.ReadDir(sessionsDirectory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "session-") {
			t.Fatalf("failed materialization left partial Session %q", entry.Name())
		}
	}
}
