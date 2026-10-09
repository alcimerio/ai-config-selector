package sessionops

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func expiredRemovedFixture(t *testing.T) (Store, []string) {
	t.Helper()
	store, ids := paginationFixture(t, 3)
	return store, ids
}

func countRecords(t *testing.T, store Store, ids []string) int {
	t.Helper()
	remaining := 0
	for _, id := range ids {
		if _, exists, _ := store.readRecord(id); exists {
			remaining++
		}
	}
	return remaining
}

func allocate(t *testing.T, store Store, name string) {
	t.Helper()
	tracker, err := NewTracker(store.SessionsDirectory, filepath.Join(store.SessionsDirectory, name), "shell")
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Removed(); err != nil {
		t.Fatal(err)
	}
}

func TestAllocationSkipsRetentionWithinCheckInterval(t *testing.T) {
	store, ids := expiredRemovedFixture(t)
	cursor := filepath.Join(store.storage.base.path, retentionCursorName)
	if err := store.writeJSON(store.storage.base, retentionCursorName, retentionCursor{Version: SchemaVersion}); err != nil {
		t.Fatal(err)
	}
	recent := time.Now().Add(-time.Minute)
	if err := os.Chtimes(cursor, recent, recent); err != nil {
		t.Fatal(err)
	}
	allocate(t, store, "session-recent-cursor")
	if remaining := countRecords(t, store, ids); remaining != len(ids) {
		t.Fatalf("allocation ran retention within interval: %d of %d records remain", remaining, len(ids))
	}
	stale := time.Now().Add(-retentionCheckInterval - time.Minute)
	if err := os.Chtimes(cursor, stale, stale); err != nil {
		t.Fatal(err)
	}
	allocate(t, store, "session-stale-cursor")
	if remaining := countRecords(t, store, ids); remaining != 0 {
		t.Fatalf("allocation skipped due retention: %d records remain", remaining)
	}
}

func TestAllocationTreatsFutureCursorAsDue(t *testing.T) {
	store, ids := expiredRemovedFixture(t)
	cursor := filepath.Join(store.storage.base.path, retentionCursorName)
	if err := store.writeJSON(store.storage.base, retentionCursorName, retentionCursor{Version: SchemaVersion}); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(24 * time.Hour)
	if err := os.Chtimes(cursor, future, future); err != nil {
		t.Fatal(err)
	}
	allocate(t, store, "session-future-cursor")
	if remaining := countRecords(t, store, ids); remaining != 0 {
		t.Fatalf("future-dated cursor suppressed retention: %d records remain", remaining)
	}
}
