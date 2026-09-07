package profilerepo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHistoryEventPublicationRetryValidatesPartialWitness(t *testing.T) {
	r := New(t.TempDir())
	absent, _ := r.Read(context.Background(), "alpha")
	injected := errors.New("interrupted after snapshot publication")
	fired := false
	r.hook = func(point string) error {
		if point == "history.event-snapshot.publish.after" && !fired {
			fired = true
			return injected
		}
		return nil
	}
	out, err := r.Apply(context.Background(), CreateRequest{"alpha", absent.Revision, []byte("new")})
	if !errors.Is(err, injected) || out.State != Unknown || !out.RecoveryRequired {
		t.Fatalf("outcome=%+v err=%v", out, err)
	}
	r.hook = nil
	out, err = r.Recover(context.Background())
	if err != nil || out.State != Committed || out.RecoveryRequired {
		t.Fatalf("recover=%+v err=%v", out, err)
	}
	history, err := r.History(context.Background(), HistorySelector{Name: "alpha"}, 100)
	if err != nil || len(history.Events) != 1 || history.Events[0].Profile.Revision != revisionText("alpha", true, []byte("new")) {
		t.Fatalf("history=%+v err=%v", history, err)
	}
}

func TestHistoryPartialPublicationRejectsDifferentExistingSnapshot(t *testing.T) {
	r := New(t.TempDir())
	absent, _ := r.Read(context.Background(), "alpha")
	injected := errors.New("stop")
	r.hook = func(point string) error {
		if point == "history.event-snapshot.publish.after" {
			return injected
		}
		return nil
	}
	_, _ = r.Apply(context.Background(), CreateRequest{"alpha", absent.Revision, []byte("new")})
	r.hook = nil
	entries, _ := os.ReadDir(filepath.Join(r.acsHome, "profiles", "history"))
	var lineage string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "ln_") {
			lineage = entry.Name()
		}
	}
	files, _ := os.ReadDir(filepath.Join(r.acsHome, "profiles", "history", lineage))
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".snapshot") {
			if err := os.WriteFile(filepath.Join(r.acsHome, "profiles", "history", lineage, file.Name()), []byte("evil"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	out, err := r.Recover(context.Background())
	if !errors.Is(err, ErrUnsafe) || out.State != Unknown || !out.RecoveryRequired {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestCorruptCurrentLineageBlocksOnlyThatProfile(t *testing.T) {
	r := New(t.TempDir())
	ctx := context.Background()
	for _, name := range []string{"alpha", "bravo"} {
		a, _ := r.Read(ctx, name)
		if _, e := r.Apply(ctx, CreateRequest{name, a.Revision, []byte(name)}); e != nil {
			t.Fatal(e)
		}
	}
	ha, _ := r.History(ctx, HistorySelector{Name: "alpha"}, 100)
	event := ha.Events[0].EventID
	if err := os.WriteFile(filepath.Join(r.acsHome, "profiles", "history", ha.LineageID, event+".json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	a, _ := r.Read(ctx, "alpha")
	out, err := r.Apply(ctx, ReplaceRequest{"alpha", a.Revision, []byte("changed")})
	if !errors.Is(err, ErrUnsafe) || out.State != NotCommitted {
		t.Fatalf("alpha out=%+v err=%v", out, err)
	}
	b, _ := r.Read(ctx, "bravo")
	if out, err = r.Apply(ctx, ReplaceRequest{"bravo", b.Revision, []byte("changed")}); err != nil || out.State != Committed {
		t.Fatalf("bravo out=%+v err=%v", out, err)
	}
}

func TestEventSelectionMatchesAdvertisedPostRevisionAndAdoptsPriorBytes(t *testing.T) {
	r := New(t.TempDir())
	ctx := context.Background()
	profiles := filepath.Join(r.acsHome, "profiles")
	if err := os.MkdirAll(profiles, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profiles, "alpha.json"), []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	old, _ := r.Read(ctx, "alpha")
	if _, err := r.Apply(ctx, ReplaceRequest{"alpha", old.Revision, []byte("new")}); err != nil {
		t.Fatal(err)
	}
	history, err := r.History(ctx, HistorySelector{Name: "alpha"}, 100)
	if err != nil || len(history.Events) != 2 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	latest := history.Events[0]
	selected, err := r.RestoreSnapshot(ctx, HistorySelector{Name: "alpha"}, latest.EventID)
	if err != nil || string(selected.Bytes) != "new" || latest.Profile.Revision != revisionText("alpha", true, selected.Bytes) {
		t.Fatalf("latest=%+v selected=%+v err=%v", latest, selected, err)
	}
	prior := history.Events[1]
	selected, err = r.RestoreSnapshot(ctx, HistorySelector{Name: "alpha"}, prior.EventID)
	if err != nil || string(selected.Bytes) != "old" || prior.Operation != "adoption" {
		t.Fatalf("prior=%+v selected=%+v err=%v", prior, selected, err)
	}
}

func TestHistoryCreationStaysBoundToValidatedRepositoryDescriptor(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "acs")
	r := New(home)
	absent, _ := r.Read(context.Background(), "alpha")
	swapped := false
	r.hook = func(point string) error {
		if point == "history.mkdir.after" && !swapped {
			swapped = true
			if err := os.Rename(home, home+"-original"); err != nil {
				return err
			}
			if err := os.Mkdir(home, 0700); err != nil {
				return err
			}
		}
		return nil
	}
	out, err := r.Apply(context.Background(), CreateRequest{"alpha", absent.Revision, []byte("new")})
	if err == nil || out.State != Unknown || !out.RecoveryRequired {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if _, err := os.Stat(filepath.Join(home, "profiles", "history")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement received history: %v", err)
	}
}
