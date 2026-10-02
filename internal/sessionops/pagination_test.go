package sessionops

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"
)

const formerRecordLimit = 4096

func paginationID(i int) string {
	var raw [16]byte
	binary.BigEndian.PutUint64(raw[8:], uint64(i))
	return "ses_" + idEncoding.EncodeToString(raw[:])
}

func paginationFixture(t *testing.T, count int) (Store, []string) {
	t.Helper()
	sessions := filepath.Join(t.TempDir(), ".acs", "sessions")
	store, err := (Store{SessionsDirectory: sessions}).bindStorage(true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.storage.close)
	now := time.Now().UTC().Truncate(time.Second)
	store.Now = func() time.Time { return now }
	old := formatTime(now.Add(-RemovedRetention - time.Hour))
	ids := make([]string, count)
	for i := range ids {
		ids[i] = paginationID(i)
		rec := record{Version: SchemaVersion, ID: ids[i], Revision: 1, State: StateRemoved, Target: "shell", CreatedAt: old, UpdatedAt: old, RemovedAt: old, RootToken: strings.Repeat("a", 64), Generation: 1, CompletionRoot: "session-" + ids[i], CompletionChallengeHash: strings.Repeat("b", 64)}
		data, err := json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(store.storage.records.path, ids[i]+".json"), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(ids)
	return store, ids
}

func TestIncrementalRetentionAboveOldCeiling(t *testing.T) {
	store, ids := paginationFixture(t, formerRecordLimit+17)
	// A full first page is permanently preserved, so restarts at the beginning
	// would starve all subsequent expired records.
	for _, id := range ids[:maintenancePageSize] {
		rec, _, _ := store.readRecord(id)
		rec.State, rec.RemovedAt, rec.CompletionRoot, rec.CompletionChallengeHash = StateUnproven, "", "", ""
		if err := store.writeRecord(rec); err != nil {
			t.Fatal(err)
		}
	}
	for pass := 0; pass < len(ids)/maintenancePageSize+3; pass++ {
		fresh, err := (Store{SessionsDirectory: store.SessionsDirectory, Now: store.Now}).bindStorage(false)
		if err != nil {
			t.Fatal(err)
		}
		if err := fresh.pruneRemoved(); err != nil {
			t.Fatal(err)
		}
		fresh.storage.close()
	}
	for i, id := range ids {
		_, exists, err := store.readRecord(id)
		if err != nil || exists != (i < maintenancePageSize) {
			t.Fatalf("record %d exists=%v err=%v", i, exists, err)
		}
	}
}

func TestRetentionPageBudgetAndCursorRecovery(t *testing.T) {
	for _, fault := range []string{"before cursor rename", "after cursor rename", "corrupt cursor", "stale cursor"} {
		t.Run(fault, func(t *testing.T) {
			store, ids := paginationFixture(t, maintenancePageSize*2+1)
			injected := errors.New("injected cursor fault")
			switch fault {
			case "before cursor rename":
				store.storage.base.beforeRename = func(string) error { return injected }
			case "after cursor rename":
				store.storage.base.afterRename = func(string) error { return injected }
			case "corrupt cursor":
				if err := os.WriteFile(filepath.Join(store.storage.base.path, retentionCursorName), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "stale cursor":
				if err := store.writeJSON(store.storage.base, retentionCursorName, retentionCursor{Version: SchemaVersion, After: "ses_" + strings.Repeat("z", 26)}); err != nil {
					t.Fatal(err)
				}
			}
			err := store.pruneRemoved()
			if strings.Contains(fault, "rename") && err == nil {
				t.Fatal("cursor fault not observed")
			}
			remaining := 0
			for _, id := range ids {
				_, exists, _ := store.readRecord(id)
				if exists {
					remaining++
				}
			}
			if remaining != len(ids)-maintenancePageSize {
				t.Fatalf("one pass retained %d", remaining)
			}
			store.storage.base.beforeRename, store.storage.base.afterRename = nil, nil
			for i := 0; i < 4; i++ {
				if err := store.pruneRemoved(); err != nil {
					t.Fatal(err)
				}
			}
			for _, id := range ids {
				if _, exists, _ := store.readRecord(id); exists {
					t.Fatal("restart left expired record")
				}
			}
		})
	}
}

func TestListPaginationAboveOldCeiling(t *testing.T) {
	store, ids := paginationFixture(t, formerRecordLimit+17)
	// Use public Store instances: each list closes its pinned descriptors.
	public := Store{SessionsDirectory: store.SessionsDirectory}
	after := ""
	seen := map[string]bool{}
	for {
		page, err := public.ListPage("", after, MaxListPageSize)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Sessions) > MaxListPageSize {
			t.Fatal("oversized page")
		}
		for _, item := range page.Sessions {
			if seen[item.ID] || item.ID <= after {
				t.Fatal("duplicate or backwards cursor")
			}
			seen[item.ID] = true
		}
		if page.NextAfter == "" {
			break
		}
		after = page.NextAfter
	}
	if len(seen) != len(ids) {
		t.Fatalf("listed %d want %d", len(seen), len(ids))
	}
	page, err := public.ListPage(StateActive, "", 1)
	if err != nil || len(page.Sessions) != 0 || page.NextAfter == "" {
		t.Fatalf("filtered page = (%+v,%v)", page, err)
	}
	listed, err := public.List(StateActive)
	if err != nil || len(listed.Sessions) != 0 {
		t.Fatalf("complete filtered scan = (%+v,%v)", listed, err)
	}
}

func TestCompleteListAboveOldCeilingWithoutTruncation(t *testing.T) {
	store, ids := paginationFixture(t, formerRecordLimit+1)
	for _, id := range ids {
		if err := os.WriteFile(filepath.Join(store.storage.records.path, id+".json"), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	result, err := (Store{SessionsDirectory: store.SessionsDirectory}).List("")
	if err != nil || len(result.Sessions) != len(ids) {
		t.Fatalf("complete list len=%d err=%v", len(result.Sessions), err)
	}
}

func TestRetentionAdvancesPastBusyCorruptAndRecentRecords(t *testing.T) {
	store, ids := paginationFixture(t, maintenancePageSize+3)
	busy, err := store.openFence(ids[0])
	if err != nil {
		t.Fatal(err)
	}
	defer closeLocked(busy)
	if err := os.WriteFile(filepath.Join(store.storage.records.path, ids[1]+".json"), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	rec, _, _ := store.readRecord(ids[2])
	rec.RemovedAt = formatTime(store.now().Add(-RemovedRetention + time.Second))
	rec.UpdatedAt = rec.RemovedAt
	if err := store.writeRecord(rec); err != nil {
		t.Fatal(err)
	}
	// Exactly the retention boundary remains eligible, matching the old policy.
	rec, _, _ = store.readRecord(ids[3])
	rec.RemovedAt = formatTime(store.now().Add(-RemovedRetention))
	rec.UpdatedAt = rec.RemovedAt
	if err := store.writeRecord(rec); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := store.pruneRemoved(); err != nil {
			t.Fatal(err)
		}
	}
	for i, id := range ids {
		_, err := os.Stat(filepath.Join(store.storage.records.path, id+".json"))
		if (err == nil) != (i < 3) {
			t.Fatalf("record %d existence %v", i, err)
		}
	}
	closeLocked(busy)
	busy = nil
	if err := store.pruneRemoved(); err != nil {
		t.Fatal(err)
	}
	if _, exists, _ := store.readRecord(ids[0]); exists {
		t.Fatal("busy candidate not revisited after wrap")
	}
}

func TestRetentionCursorDoesNotFollowLinksOrAuthorizeRemoval(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "valid later ID"} {
		t.Run(kind, func(t *testing.T) {
			store, ids := paginationFixture(t, 3)
			rec, _, _ := store.readRecord(ids[0])
			rec.State = StateUnproven
			rec.RemovedAt = ""
			rec.CompletionRoot = ""
			rec.CompletionChallengeHash = ""
			if err := store.writeRecord(rec); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "outside")
			original := []byte("preserve this file")
			if err := os.WriteFile(outside, original, 0600); err != nil {
				t.Fatal(err)
			}
			cursor := filepath.Join(store.storage.base.path, retentionCursorName)
			switch kind {
			case "symlink":
				if err := os.Symlink(outside, cursor); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(outside, cursor); err != nil {
					t.Fatal(err)
				}
			default:
				if err := store.writeJSON(store.storage.base, retentionCursorName, retentionCursor{Version: SchemaVersion, After: ids[1]}); err != nil {
					t.Fatal(err)
				}
			}
			for i := 0; i < 3; i++ {
				if err := store.pruneRemoved(); err != nil {
					t.Fatal(err)
				}
			}
			data, err := os.ReadFile(outside)
			if err != nil || string(data) != string(original) {
				t.Fatal("cursor followed external link")
			}
			if _, exists, err := store.readRecord(ids[0]); err != nil || !exists {
				t.Fatal("cursor authorized evidence deletion")
			}
			for _, id := range ids[1:] {
				if _, exists, _ := store.readRecord(id); exists {
					t.Fatal("cursor failed to wrap")
				}
			}
		})
	}
}

func TestListPaginationChangesAreNotSnapshotAndCountIsGlobal(t *testing.T) {
	store, ids := paginationFixture(t, 3)
	rootName := "session-tracked"
	if err := os.MkdirAll(filepath.Join(store.SessionsDirectory, rootName), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(store.SessionsDirectory, "session-untracked"), 0700); err != nil {
		t.Fatal(err)
	}
	rec, _, _ := store.readRecord(ids[2])
	cap := capability{Version: SchemaVersion, ID: rec.ID, RootName: rootName, RootToken: rec.RootToken, Generation: rec.Generation, Challenge: strings.Repeat("c", 64)}
	if err := store.writeCapability(cap); err != nil {
		t.Fatal(err)
	}
	// No root binding simulates legacy/incomplete metadata; count semantics
	// must still match the earlier global map of valid records/capabilities.
	public := Store{SessionsDirectory: store.SessionsDirectory}
	page, err := public.ListPage("", "", 1)
	if err != nil || page.UntrackedCount != 1 || page.NextAfter == "" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if err := store.storage.records.unlink(ids[1] + ".json"); err != nil {
		t.Fatal(err)
	}
	next, err := public.ListPage("", page.NextAfter, 1)
	if err != nil || len(next.Sessions) != 1 || next.Sessions[0].ID != ids[2] || next.UntrackedCount != 1 {
		t.Fatalf("next=%+v err=%v", next, err)
	}
}

func TestDefaultListOutputLimitReturnsNoPartialRows(t *testing.T) {
	store, _ := paginationFixture(t, 6000)
	public := Store{SessionsDirectory: store.SessionsDirectory}
	result, err := public.List("")
	if Diagnostic(err) != "session_output_limit" || len(result.Sessions) != 0 || result.UntrackedCount != 0 || result.NextAfter != "" {
		t.Fatalf("oversized list returned partial output: len=%d err=%v", len(result.Sessions), err)
	}
	page, err := public.ListPage("", "", MaxListPageSize)
	if err != nil || len(page.Sessions) != MaxListPageSize || page.NextAfter == "" {
		t.Fatalf("paged output len=%d err=%v", len(page.Sessions), err)
	}
}

func TestRetentionSerializesCursorAndAllocationProgress(t *testing.T) {
	store, ids := paginationFixture(t, formerRecordLimit+1)
	lock, err := store.storage.base.lock(".allocation.lock", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.pruneRemoved(); err == nil {
		t.Fatal("parallel cursor mutation ignored allocation lock")
	}
	closeLocked(lock)
	trigger, err := NewTracker(store.SessionsDirectory, filepath.Join(store.SessionsDirectory, "session-allocation-trigger"), "shell")
	if err != nil {
		t.Fatal(err)
	}
	if err := trigger.Removed(); err != nil {
		t.Fatal(err)
	}
	remaining := 0
	for _, id := range ids {
		if _, exists, _ := store.readRecord(id); exists {
			remaining++
		}
	}
	if remaining != len(ids)-maintenancePageSize {
		t.Fatalf("allocation retained %d records", remaining)
	}
}

func TestPageSelectionDeduplicatesRepeatedDirectoryEntries(t *testing.T) {
	store, want := paginationFixture(t, 3)
	entries, err := os.ReadDir(store.storage.records.path)
	if err != nil {
		t.Fatal(err)
	}
	ids, more, err := selectIDPage("", 2, func(visit func(os.DirEntry) error) error {
		for i := len(entries) - 1; i >= 0; i-- {
			for repeat := 0; repeat < 3; repeat++ {
				if err := visit(entries[i]); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil || !more || len(ids) != 2 || ids[0] != want[0] || ids[1] != want[1] {
		t.Fatalf("deduplicated page=%v more=%v err=%v", ids, more, err)
	}
}

func TestRetentionDeletionFailureAdvancesAndRetriesAfterWrap(t *testing.T) {
	store, ids := paginationFixture(t, maintenancePageSize+1)
	store.storage.records.beforeUnlink = func(name string) error {
		if name == ids[0]+".json" {
			return errors.New("injected record unlink failure")
		}
		return nil
	}
	if err := store.pruneRemoved(); err != nil {
		t.Fatal(err)
	}
	var cursor retentionCursor
	if exists, err := readStrict(store.storage.base, retentionCursorName, &cursor); err != nil || !exists || cursor.After == "" {
		t.Fatalf("cursor did not advance: %+v %v", cursor, err)
	}
	if _, exists, _ := store.readRecord(ids[0]); !exists {
		t.Fatal("failed deletion was not retained")
	}
	if err := store.pruneRemoved(); err != nil {
		t.Fatal(err)
	}
	if _, exists, _ := store.readRecord(ids[len(ids)-1]); exists {
		t.Fatal("failed first record starved later page")
	}
	store.storage.records.beforeUnlink = nil
	if err := store.pruneRemoved(); err != nil {
		t.Fatal(err)
	}
	if _, exists, _ := store.readRecord(ids[0]); exists {
		t.Fatal("failed deletion not retried on wrap")
	}
}

func TestRetentionCursorFIFOIsRejectedWithoutBlocking(t *testing.T) {
	store, _ := paginationFixture(t, 0)
	path := filepath.Join(store.storage.base.path, retentionCursorName)
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		tracker, err := NewTracker(store.SessionsDirectory, filepath.Join(store.SessionsDirectory, "session-review-trigger"), "shell")
		if tracker != nil {
			_ = tracker.Removed()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		// A writer releases the blocked open so the test can shut down cleanly.
		fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer syscall.Close(fd)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("did not exit after FIFO release")
		}
		t.Fatal("advisory FIFO blocked allocation until another process opened it for writing")
	}
}

func TestListPageRejectsInvalidArgumentsBeforeStorage(t *testing.T) {
	blocked := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocked, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	store := Store{SessionsDirectory: filepath.Join(blocked, "sessions")}
	for _, test := range []struct {
		after string
		limit int
	}{{"", 0}, {"", MaxListPageSize + 1}, {"bad", 1}, {"../escape", 1}} {
		if _, err := store.ListPage("", test.after, test.limit); Diagnostic(err) != "invalid_session_page" {
			t.Fatalf("arguments reached storage: %v", err)
		}
	}
}

func TestPaginatedUntrackedCountStreamsRootBatchesWithRegistry(t *testing.T) {
	store, ids := paginationFixture(t, 3)
	for i := 0; i < scanBatchSize*2+1; i++ {
		root := "session-" + paginationID(i)
		if err := os.MkdirAll(filepath.Join(store.SessionsDirectory, root), 0700); err != nil {
			t.Fatal(err)
		}
	}
	rec, _, _ := store.readRecord(ids[2])
	cap := capability{Version: SchemaVersion, ID: rec.ID, RootName: "session-" + paginationID(scanBatchSize*2), RootToken: rec.RootToken, Generation: rec.Generation, Challenge: strings.Repeat("c", 64)}
	if err := store.writeCapability(cap); err != nil {
		t.Fatal(err)
	}
	result, err := (Store{SessionsDirectory: store.SessionsDirectory}).ListPage("", "", 1)
	if err != nil || result.UntrackedCount != scanBatchSize*2 {
		t.Fatalf("global multibatch count=%d err=%v", result.UntrackedCount, err)
	}
}
