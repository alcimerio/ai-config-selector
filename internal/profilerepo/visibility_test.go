package profilerepo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPassiveRevisionReadDuringOwnedPublication(t *testing.T) {
	r := New(t.TempDir())
	ctx := context.Background()
	expected, _ := AbsentRevision("example")
	r.hook = func(point string) error {
		if point != "publish.link.after" {
			return nil
		}
		snapshot, err := r.Read(ctx, "example")
		if err != nil || !snapshot.Exists {
			t.Fatal("passive revision read during publication", err)
		}
		return errors.New("preserve committed decision")
	}
	if _, err := r.Apply(ctx, CreateRequest{"example", expected, []byte("future bytes")}); err == nil {
		t.Fatal("missing interruption")
	}
}
func TestNativeVolumeAliasPolicy(t *testing.T) {
	r := seeded(t)
	directory := filepath.Join(r.acsHome, "profiles")
	lower, err := os.Stat(filepath.Join(directory, "source.json"))
	if err != nil {
		t.Fatal(err)
	}
	upper, upperErr := os.Stat(filepath.Join(directory, "SOURCE.json"))
	aliases := upperErr == nil && os.SameFile(lower, upper)
	var fs unix.Statfs_t
	if err = unix.Statfs(directory, &fs); err != nil {
		t.Fatal(err)
	}
	t.Logf("tested filesystem: os=%s arch=%s type=%x ASCII-case-alias=%v; no other volume or hardware claim", runtime.GOOS, runtime.GOARCH, fs.Type, aliases)
	for _, request := range []Request{
		RenameRequest{"source", "SOURCE", revision("source", true, []byte(oldBytes)), revision("SOURCE", false, nil), []byte(newBytes)},
		CloneRequest{"source", "SOURCE", revision("source", true, []byte(oldBytes)), revision("SOURCE", false, nil), []byte(newBytes)},
	} {
		if _, err = r.Apply(context.Background(), request); !errors.Is(err, ErrConflict) {
			t.Fatal("case-only pair must be rejected", err)
		}
	}
	out, err := r.Apply(context.Background(), CreateRequest{"SOURCE", revision("SOURCE", false, nil), []byte(newBytes)})
	if aliases {
		if err == nil || out.State != NotCommitted {
			t.Fatal("occupied volume alias overwritten", err)
		}
	} else if err != nil || out.State != Committed {
		t.Fatal("distinct volume spelling rejected", err)
	}
	original, _ := os.ReadFile(filepath.Join(directory, "source.json"))
	if string(original) != oldBytes {
		t.Fatal("alias changed source")
	}
}
func TestPrecancelAndPassiveMissingReadNeverBootstrap(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	r := New(root)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Read(context.Background(), "missing"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Apply(ctx, operation("create")); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := r.Recover(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("passive or pre-cancel path bootstrapped", err)
	}
}
func TestAbortedPreparationRecoveryCanItselfBeInterrupted(t *testing.T) {
	for _, initial := range []string{"stage.write.after", "pending.write.after", "plan.publish.after"} {
		t.Run(initial, func(t *testing.T) {
			baseline := seeded(t)
			runKilled(t, baseline, "apply", "create", initial)
			points := trace(t, baseline, "recover", "create")
			for _, point := range points {
				if !strings.HasPrefix(point, "cleanup.") && !strings.HasPrefix(point, "complete.recovery-sync.") {
					continue
				}
				t.Run(point, func(t *testing.T) {
					r := seeded(t)
					runKilled(t, r, "apply", "create", initial)
					runKilled(t, r, "recover", "create", point)
					recoverFreshTwice(t, r)
					assertSettled(t, r, "create")
				})
			}
		})
	}
}

func TestFirstUseBootstrapProcessCrashes(t *testing.T) {
	newRepository := func() *Repository { return New(filepath.Join(t.TempDir(), "acs")) }
	baseline := newRepository()
	points := trace(t, baseline, "apply", "create")
	for _, point := range points {
		if !strings.HasPrefix(point, "home.") && !strings.HasPrefix(point, "repository.") && !strings.HasPrefix(point, "lock.") {
			continue
		}
		t.Run(point, func(t *testing.T) {
			r := newRepository()
			runKilled(t, r, "apply", "create", point)
			recoverFreshTwice(t, r)
			snapshot, err := r.Read(context.Background(), "destination")
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Exists && string(snapshot.Bytes) != newBytes {
				t.Fatal("bootstrap lost canonical bytes")
			}
			// A subsequent real mutation must work even if recovery found nothing to do.
			if !snapshot.Exists {
				if _, err = r.Apply(context.Background(), operation("create")); err != nil {
					t.Fatal("bootstrap did not converge", err)
				}
			}
		})
	}
}
func TestTerminalCleanupRecoveryCanItselfBeInterrupted(t *testing.T) {
	for _, initial := range []string{"complete.publish.after", "cleanup.stage.after", "cleanup.decision.after", "cleanup.plan.after"} {
		t.Run(initial, func(t *testing.T) {
			baseline := seeded(t)
			runKilled(t, baseline, "apply", "rename", initial)
			points := trace(t, baseline, "recover", "rename")
			for _, point := range points {
				if !strings.HasPrefix(point, "cleanup.") && !strings.HasPrefix(point, "complete.recovery-sync.") {
					continue
				}
				t.Run(point, func(t *testing.T) {
					r := seeded(t)
					runKilled(t, r, "apply", "rename", initial)
					runKilled(t, r, "recover", "rename", point)
					recoverFreshTwice(t, r)
					assertSettled(t, r, "rename")
				})
			}
		})
	}
}
