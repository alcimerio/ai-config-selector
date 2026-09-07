package exchangefile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishNoClobberAndAtomicFailure(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "profile.json")
	if err := os.WriteFile(destination, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if outcome, err := (Publisher{}).Publish(context.Background(), destination, []byte("new")); err == nil || outcome.Published {
		t.Fatalf("collision = %#v, %v", outcome, err)
	}
	contents, _ := os.ReadFile(destination)
	if string(contents) != "existing" {
		t.Fatalf("destination = %q", contents)
	}

	failing := Publisher{Hook: func(point string) error {
		if point == "file-sync.before" {
			return errors.New("injected")
		}
		return nil
	}}
	other := filepath.Join(directory, "other.json")
	if outcome, err := failing.Publish(context.Background(), other, []byte("new")); err == nil || outcome.Published {
		t.Fatalf("failure = %#v, %v", outcome, err)
	}
	if _, err := os.Lstat(other); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial destination: %v", err)
	}
}

func TestPublishReportsPostPublicationFailure(t *testing.T) {
	for _, point := range []string{"publish.after", "directory-sync.before", "directory-sync.after"} {
		t.Run(point, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "profile.json")
			publisher := Publisher{Hook: func(observed string) error {
				if observed == point {
					return errors.New("injected")
				}
				return nil
			}}
			outcome, err := publisher.Publish(context.Background(), destination, []byte("complete"))
			if err == nil || !outcome.Published {
				t.Fatalf("outcome = %#v, %v", outcome, err)
			}
			contents, readErr := os.ReadFile(destination)
			if readErr != nil || string(contents) != "complete" {
				t.Fatalf("published = %q, %v", contents, readErr)
			}
			info, statErr := os.Stat(destination)
			if statErr != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("mode = %v, %v", info, statErr)
			}
		})
	}
}

func TestPublishObservesCancellationAtPublicationBoundary(t *testing.T) {
	directory := t.TempDir()
	destination := filepath.Join(directory, "profile.json")
	ctx, cancel := context.WithCancel(context.Background())
	publisher := Publisher{Hook: func(point string) error {
		if point == "publish.before" {
			cancel()
		}
		return nil
	}}
	outcome, err := publisher.Publish(ctx, destination, []byte("complete"))
	if !errors.Is(err, context.Canceled) || outcome.Published {
		t.Fatalf("outcome = %#v, %v", outcome, err)
	}
	if _, statErr := os.Lstat(destination); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("destination exists: %v", statErr)
	}
	entries, readErr := os.ReadDir(directory)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("owned temporary remained: %#v, %v", entries, readErr)
	}
}

func TestPublishReportsCancellationAfterPublicationAndAttemptsDurability(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "profile.json")
	ctx, cancel := context.WithCancel(context.Background())
	directorySyncObserved := false
	durabilityErr := errors.New("injected durability failure")
	publisher := Publisher{Hook: func(point string) error {
		switch point {
		case "publish.after":
			cancel()
		case "directory-sync.before":
			directorySyncObserved = true
			return durabilityErr
		}
		return nil
	}}
	outcome, err := publisher.Publish(ctx, destination, []byte("complete"))
	if !errors.Is(err, context.Canceled) || !errors.Is(err, durabilityErr) || !outcome.Published {
		t.Fatalf("outcome = %#v, %v", outcome, err)
	}
	if !directorySyncObserved {
		t.Fatal("directory durability was not attempted")
	}
	contents, readErr := os.ReadFile(destination)
	if readErr != nil || string(contents) != "complete" {
		t.Fatalf("published = %q, %v", contents, readErr)
	}
}

func TestPublishRefusesExistingSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	destination := filepath.Join(directory, "exchange.json")
	if err := os.WriteFile(target, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, destination); err != nil {
		t.Fatal(err)
	}
	if outcome, err := (Publisher{}).Publish(context.Background(), destination, []byte("new")); err == nil || outcome.Published {
		t.Fatalf("symlink = %#v, %v", outcome, err)
	}
	contents, _ := os.ReadFile(target)
	if string(contents) != "sentinel" {
		t.Fatalf("target = %q", contents)
	}
}
