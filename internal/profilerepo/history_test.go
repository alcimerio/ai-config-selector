package profilerepo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func TestExplicitDeletedLineageRestoreAppendsToBoundHead(t *testing.T) {
	r := New(t.TempDir())
	ctx := context.Background()
	absent, _ := r.Read(ctx, "alpha")
	if out, err := r.Apply(ctx, CreateRequest{"alpha", absent.Revision, []byte("created")}); err != nil || out.State != Committed {
		t.Fatalf("create=%+v err=%v", out, err)
	}
	created, err := r.History(ctx, HistorySelector{Name: "alpha"}, 100)
	if err != nil || len(created.Events) != 1 {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	current, _ := r.Read(ctx, "alpha")
	if out, err := r.Apply(ctx, DeleteRequest{"alpha", current.Revision}); err != nil || out.State != Committed {
		t.Fatalf("delete=%+v err=%v", out, err)
	}
	absent, _ = r.Read(ctx, "restored")
	request := HistoryRequest{Request: CreateRequest{"restored", absent.Revision, []byte("created")}, Operation: "restore", Lineage: created.LineageID}
	injected := errors.New("interrupt explicit-lineage history publication")
	fired := false
	r.hook = func(point string) error {
		if point == "history.event-snapshot.publish.after" && !fired {
			fired = true
			return injected
		}
		return nil
	}
	if out, err := r.Apply(ctx, request); !errors.Is(err, injected) || out.State != Unknown || !out.RecoveryRequired {
		t.Fatalf("interrupted restore=%+v err=%v", out, err)
	}
	r.hook = nil
	for i := 0; i < 2; i++ {
		if out, err := r.Recover(ctx); err != nil || out.RecoveryRequired {
			t.Fatalf("recover %d=%+v err=%v", i, out, err)
		} else if i == 0 && out.State != Committed {
			t.Fatalf("first recovery did not complete the decided restore: %+v", out)
		}
	}
	history, err := r.History(ctx, HistorySelector{Name: "restored"}, 100)
	if err != nil || history.LineageID != created.LineageID || len(history.Events) != 3 || history.Events[0].Operation != "restore" {
		t.Fatalf("restored=%+v err=%v", history, err)
	}
	d, err := r.open(false)
	if err != nil {
		t.Fatal(err)
	}
	defer d.close()
	root, err := openHistoryRoot(d, false)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	lineage, err := readLineage(root, created.LineageID)
	if err != nil || len(lineage.records) != 3 || lineage.records[2].Sequence != 3 {
		t.Fatalf("lineage=%+v err=%v", lineage, err)
	}
	parent, _ := json.Marshal(lineage.records[1])
	if lineage.records[2].ParentDigest != digestHex(parent) {
		t.Fatal("restore record is not parent-bound to the deleted lineage head")
	}
}

func TestExplicitLiveLineageCannotBranchToAbsentDestination(t *testing.T) {
	r := New(t.TempDir())
	ctx := context.Background()
	alpha, _ := r.Read(ctx, "alpha")
	if _, err := r.Apply(ctx, CreateRequest{"alpha", alpha.Revision, []byte("alpha")}); err != nil {
		t.Fatal(err)
	}
	history, _ := r.History(ctx, HistorySelector{Name: "alpha"}, 1)
	bravo, _ := r.Read(ctx, "bravo")
	out, err := r.Apply(ctx, HistoryRequest{Request: CreateRequest{"bravo", bravo.Revision, []byte("alpha")}, Operation: "restore", Lineage: history.LineageID})
	if !errors.Is(err, ErrConflict) || out.State != NotCommitted || out.RecoveryRequired {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if bravo, err = r.Read(ctx, "bravo"); err != nil || bravo.Exists {
		t.Fatalf("bravo=%+v err=%v", bravo, err)
	}
	if current, err := r.History(ctx, HistorySelector{Name: "alpha"}, 100); err != nil || len(current.Events) != 1 {
		t.Fatalf("alpha history=%+v err=%v", current, err)
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
	if err == nil || out.State != NotCommitted || !out.RecoveryRequired {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if _, err := os.Stat(filepath.Join(home, "profiles", "history")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement received history: %v", err)
	}
}

func TestHistoryTransactionIsDigestBoundToImmutableProfilePlan(t *testing.T) {
	r := New(t.TempDir())
	ctx := context.Background()
	absent, _ := r.Read(ctx, "alpha")
	tampered := false
	r.hook = func(point string) error {
		if point != "decision.publish.before" || tampered {
			return nil
		}
		tampered = true
		entries, e := os.ReadDir(filepath.Join(r.acsHome, "profiles", "history"))
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), "txn_") || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			path := filepath.Join(r.acsHome, "profiles", "history", entry.Name())
			data, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			var txn historyTxn
			if e = json.Unmarshal(data, &txn); e != nil {
				return e
			}
			txn.Record.LineageID = "ln_00000000000000000000000000000000"
			data, e = json.Marshal(txn)
			if e != nil {
				return e
			}
			return os.WriteFile(path, data, 0600)
		}
		return errors.New("transaction witness missing")
	}
	out, err := r.Apply(ctx, CreateRequest{"alpha", absent.Revision, []byte("new")})
	if err == nil || out.State != Unknown || !out.RecoveryRequired {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if current, _ := r.Read(ctx, "alpha"); current.Exists {
		t.Fatal("tampered history authorized public mutation")
	}
	if out, err = r.Recover(ctx); err == nil || !out.RecoveryRequired {
		t.Fatalf("recovery discarded restrictive evidence: %+v %v", out, err)
	}
}

func TestInterruptedPinAndPruneRecoverUnderRepositoryLock(t *testing.T) {
	ctx := context.Background()
	t.Run("pin", func(t *testing.T) {
		r := New(t.TempDir())
		a, _ := r.Read(ctx, "alpha")
		if _, e := r.Apply(ctx, CreateRequest{"alpha", a.Revision, []byte("one")}); e != nil {
			t.Fatal(e)
		}
		h, _ := r.History(ctx, HistorySelector{Name: "alpha"}, 100)
		dir := filepath.Join(r.acsHome, "profiles", "history", h.LineageID)
		data, _ := json.Marshal(struct {
			Version int      `json:"version"`
			Events  []string `json:"events"`
		}{1, []string{h.Events[0].EventID}})
		if e := os.WriteFile(filepath.Join(dir, "pins.next"), data, 0600); e != nil {
			t.Fatal(e)
		}
		for i := 0; i < 2; i++ {
			out, e := r.Recover(ctx)
			if e != nil || out.RecoveryRequired {
				t.Fatalf("recover %d: %+v %v", i, out, e)
			}
		}
		h, e := r.History(ctx, HistorySelector{Name: "alpha"}, 100)
		if e != nil || !h.Events[0].Pinned {
			t.Fatalf("history=%+v err=%v", h, e)
		}
	})
	t.Run("partial-prune", func(t *testing.T) {
		r := New(t.TempDir())
		for _, body := range []string{"one", "two", "three", "four"} {
			s, _ := r.Read(ctx, "alpha")
			var request Request = ReplaceRequest{"alpha", s.Revision, []byte(body)}
			if !s.Exists {
				request = CreateRequest{"alpha", s.Revision, []byte(body)}
			}
			if _, e := r.Apply(ctx, request); e != nil {
				t.Fatal(e)
			}
		}
		h, _ := r.History(ctx, HistorySelector{Name: "alpha"}, 100)
		preview, e := r.PreviewPrune(ctx, h.LineageID, 1)
		if e != nil {
			t.Fatal(e)
		}
		d, e := r.open(false)
		if e != nil {
			t.Fatal(e)
		}
		root, e := openHistoryRoot(d, false)
		if e != nil {
			t.Fatal(e)
		}
		lineage, e := resolveLineage(root, HistorySelector{Lineage: h.LineageID})
		if e != nil {
			t.Fatal(e)
		}
		ids := pruneCandidates(lineage, 1)
		root.Close()
		d.close()
		if len(ids) == 0 {
			t.Fatal("no candidates")
		}
		dir := filepath.Join(r.acsHome, "profiles", "history", h.LineageID)
		journal, _ := json.Marshal(pruneJournal{1, preview.Digest, ids})
		if e = os.WriteFile(filepath.Join(dir, "prune.json"), journal, 0600); e != nil {
			t.Fatal(e)
		}
		if e = os.Remove(filepath.Join(dir, ids[0]+".json")); e != nil {
			t.Fatal(e)
		}
		for i := 0; i < 2; i++ {
			out, e := r.Recover(ctx)
			if e != nil || out.RecoveryRequired {
				t.Fatalf("recover %d: %+v %v", i, out, e)
			}
		}
		if _, e = r.History(ctx, HistorySelector{Name: "alpha"}, 100); e != nil {
			t.Fatal(e)
		}
		if _, e = os.Stat(filepath.Join(dir, ids[0]+".snapshot")); !errors.Is(e, os.ErrNotExist) {
			t.Fatalf("partial snapshot retained: %v", e)
		}
	})
	t.Run("corrupt-lineage-is-local", func(t *testing.T) {
		r := New(t.TempDir())
		for _, name := range []string{"alpha", "bravo"} {
			s, _ := r.Read(ctx, name)
			if _, e := r.Apply(ctx, CreateRequest{name, s.Revision, []byte(name)}); e != nil {
				t.Fatal(e)
			}
		}
		h, _ := r.History(ctx, HistorySelector{Name: "alpha"}, 100)
		dir := filepath.Join(r.acsHome, "profiles", "history", h.LineageID)
		if e := os.WriteFile(filepath.Join(dir, "pins.next"), []byte(`{"version":2,"events":[]}`), 0600); e != nil {
			t.Fatal(e)
		}
		a, _ := r.Read(ctx, "alpha")
		out, e := r.Apply(ctx, ReplaceRequest{"alpha", a.Revision, []byte("changed")})
		if e == nil || out.State != NotCommitted {
			t.Fatalf("affected lineage out=%+v err=%v", out, e)
		}
		b, _ := r.Read(ctx, "bravo")
		out, e = r.Apply(ctx, ReplaceRequest{"bravo", b.Revision, []byte("changed")})
		if e != nil || out.State != Committed {
			t.Fatalf("unrelated lineage out=%+v err=%v", out, e)
		}
	})
}

func TestCloneRecordsExplicitSourceLineage(t *testing.T) {
	r := New(t.TempDir())
	ctx := context.Background()
	src, _ := r.Read(ctx, "source")
	if _, e := r.Apply(ctx, CreateRequest{"source", src.Revision, []byte("source")}); e != nil {
		t.Fatal(e)
	}
	sourceHistory, _ := r.History(ctx, HistorySelector{Name: "source"}, 100)
	dst, _ := r.Read(ctx, "copy")
	src, _ = r.Read(ctx, "source")
	if _, e := r.Apply(ctx, CloneRequest{"source", "copy", src.Revision, dst.Revision, []byte("copy")}); e != nil {
		t.Fatal(e)
	}
	copyHistory, _ := r.History(ctx, HistorySelector{Name: "copy"}, 100)
	preservedSource, e := r.History(ctx, HistorySelector{Name: "source"}, 100)
	if e != nil || preservedSource.LineageID != sourceHistory.LineageID {
		t.Fatalf("clone changed source lineage binding: before=%s after=%+v err=%v", sourceHistory.LineageID, preservedSource, e)
	}
	src, _ = r.Read(ctx, "source")
	deleted, e := r.Apply(ctx, HistoryRequest{Request: DeleteRequest{"source", src.Revision}, Operation: "delete"})
	if e != nil || deleted.History == nil || deleted.History.LineageID != sourceHistory.LineageID {
		t.Fatalf("source delete after clone=%+v err=%v", deleted, e)
	}
	deletedHistory, e := r.History(ctx, HistorySelector{Lineage: sourceHistory.LineageID}, 1)
	if e != nil || len(deletedHistory.Events) != 1 || deletedHistory.Events[0].Profile.State != "deleted" {
		t.Fatalf("source lineage was not tombstoned after clone: %+v err=%v", deletedHistory, e)
	}
	d, e := r.open(false)
	if e != nil {
		t.Fatal(e)
	}
	defer d.close()
	root, e := openHistoryRoot(d, false)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	lineage, e := resolveLineage(root, HistorySelector{Lineage: copyHistory.LineageID})
	if e != nil {
		t.Fatal(e)
	}
	if len(lineage.records) != 1 || lineage.records[0].SourceLineage != sourceHistory.LineageID {
		t.Fatalf("records=%+v", lineage.records)
	}
}

func TestRenameDeleteAndNameReuseKeepDistinctLineages(t *testing.T) {
	r := New(t.TempDir())
	ctx := context.Background()
	a, _ := r.Read(ctx, "alpha")
	if _, e := r.Apply(ctx, CreateRequest{"alpha", a.Revision, []byte("alpha")}); e != nil {
		t.Fatal(e)
	}
	alphaHistory, _ := r.History(ctx, HistorySelector{Name: "alpha"}, 100)
	a, _ = r.Read(ctx, "alpha")
	b, _ := r.Read(ctx, "beta")
	if _, e := r.Apply(ctx, RenameRequest{"alpha", "beta", a.Revision, b.Revision, []byte("beta")}); e != nil {
		t.Fatal(e)
	}
	if h, e := r.History(ctx, HistorySelector{Name: "alpha"}, 100); e != nil || len(h.Events) != 0 {
		t.Fatalf("old name history=%+v err=%v", h, e)
	}
	renamed, e := r.History(ctx, HistorySelector{Name: "beta"}, 100)
	if e != nil || renamed.LineageID != alphaHistory.LineageID {
		t.Fatalf("renamed=%+v err=%v", renamed, e)
	}
	b, _ = r.Read(ctx, "beta")
	if _, e = r.Apply(ctx, DeleteRequest{"beta", b.Revision}); e != nil {
		t.Fatal(e)
	}
	deleted, e := r.History(ctx, HistorySelector{Lineage: renamed.LineageID}, 100)
	if e != nil || deleted.Events[0].Profile.State != "deleted" {
		t.Fatalf("deleted=%+v err=%v", deleted, e)
	}
	b, _ = r.Read(ctx, "beta")
	if _, e = r.Apply(ctx, CreateRequest{"beta", b.Revision, []byte("reused")}); e != nil {
		t.Fatal(e)
	}
	reused, e := r.History(ctx, HistorySelector{Name: "beta"}, 100)
	if e != nil || reused.LineageID == deleted.LineageID {
		t.Fatalf("reused=%+v old=%s err=%v", reused, deleted.LineageID, e)
	}
}

func TestAutomaticRetentionKeepsBoundedOrdinaryHistory(t *testing.T) {
	r := New(t.TempDir())
	ctx := context.Background()
	for i := 0; i < 105; i++ {
		s, e := r.Read(ctx, "alpha")
		if e != nil {
			t.Fatal(e)
		}
		body := []byte(fmt.Sprintf("revision-%03d", i))
		var request Request = ReplaceRequest{"alpha", s.Revision, body}
		if !s.Exists {
			request = CreateRequest{"alpha", s.Revision, body}
		}
		if out, e := r.Apply(ctx, request); e != nil || out.State != Committed {
			t.Fatalf("mutation %d: %+v %v", i, out, e)
		}
	}
	h, e := r.History(ctx, HistorySelector{Name: "alpha"}, 100)
	if e != nil || len(h.Events) != 100 {
		t.Fatalf("public history len=%d err=%v", len(h.Events), e)
	}
	d, e := r.open(false)
	if e != nil {
		t.Fatal(e)
	}
	defer d.close()
	root, e := openHistoryRoot(d, false)
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	lineage, e := resolveLineage(root, HistorySelector{Name: "alpha"})
	if e != nil {
		t.Fatal(e)
	}
	if len(lineage.records) > 101 {
		t.Fatalf("retained %d records", len(lineage.records))
	}
}

func assertNoHistoryTransactions(t *testing.T, r *Repository) {
	t.Helper()
	entries, e := os.ReadDir(filepath.Join(r.acsHome, "profiles", "history"))
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "txn_") {
			t.Fatalf("stranded history witness %q", entry.Name())
		}
	}
}

func TestPreDecisionHistoryWitnessRecoveryRemovesEveryOrphan(t *testing.T) {
	for _, process := range []bool{false, true} {
		t.Run(fmt.Sprintf("process-%v", process), func(t *testing.T) {
			r := seeded(t)
			if process {
				runKilled(t, r, "apply", "create", "pending.create.before")
			} else {
				failure := errors.New("pending failed")
				r.hook = func(point string) error {
					if point == "pending.create.before" {
						return failure
					}
					return nil
				}
				out, e := r.Apply(context.Background(), operation("create"))
				if !errors.Is(e, failure) || out.State != NotCommitted {
					t.Fatalf("out=%+v err=%v", out, e)
				}
				r.hook = nil
			}
			for i := 0; i < 2; i++ {
				out, e := r.Recover(context.Background())
				if e != nil || out.RecoveryRequired {
					t.Fatalf("recover %d: %+v %v", i, out, e)
				}
			}
			assertNoHistoryTransactions(t, r)
		})
	}
}

func TestInterruptedOrphanCleanupIsRepeatable(t *testing.T) {
	r := seeded(t)
	runKilled(t, r, "apply", "create", "pending.create.before")
	runKilled(t, r, "recover", "create", "history.orphan.remove.after")
	for i := 0; i < 2; i++ {
		out, e := r.Recover(context.Background())
		if e != nil || out.RecoveryRequired {
			t.Fatalf("recover %d: %+v %v", i, out, e)
		}
	}
	assertNoHistoryTransactions(t, r)
}
