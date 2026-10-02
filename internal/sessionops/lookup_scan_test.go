package sessionops

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRecoveryLookupScansBeyondFormerEntryLimit(t *testing.T) {
	for _, kind := range []string{"capabilities", "completed records"} {
		for _, scenario := range []string{"match beyond limit", "ambiguous after first page", "malformed after first page"} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				store, ids, rootName, challenge := newLookupScanFixture(t, kind)
				defer store.storage.close()
				matchedID := ids[len(ids)-1]
				if scenario != "match beyond limit" {
					matchedID = ids[0]
				}
				writeLookupMatch(t, store, kind, matchedID, rootName, challenge)
				if scenario == "ambiguous after first page" {
					writeLookupMatch(t, store, kind, ids[len(ids)-1], rootName, challenge)
				}
				if scenario == "malformed after first page" {
					directory := store.storage.records
					if kind == "capabilities" {
						directory = store.storage.capabilities
					}
					if err := os.WriteFile(filepath.Join(directory.path, ids[len(ids)-1]+".json"), []byte("{}"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				removeCalls, finalizeCalls := 0, 0
				err := store.FinalizeRemoval(rootName, challenge, func() (bool, error) {
					removeCalls++
					return true, nil
				}, func() error {
					finalizeCalls++
					return nil
				})
				if scenario != "match beyond limit" {
					if err == nil || Diagnostic(err) != "session_registry_unavailable" || removeCalls != 0 || finalizeCalls != 0 {
						t.Fatalf("unsafe lookup proceeded: err=%v remove=%d finalize=%d", err, removeCalls, finalizeCalls)
					}
					return
				}
				wantRemove := 0
				if kind == "capabilities" {
					wantRemove = 1
				}
				if err != nil || removeCalls != wantRemove || finalizeCalls != 1 {
					t.Fatalf("complete lookup = err=%v remove=%d finalize=%d, want remove=%d finalize=1", err, removeCalls, finalizeCalls, wantRemove)
				}
				inspected, err := (Store{SessionsDirectory: store.SessionsDirectory}).Inspect(matchedID)
				if err != nil || inspected.Session.State != StateRemoved {
					t.Fatalf("completed record = %+v, %v", inspected, err)
				}
			})
		}
	}
}

// Discover the actual scan order before rewriting the first and last entries;
// filesystem ordering must not decide whether a case really crosses a page.
func newLookupScanFixture(t *testing.T, kind string) (Store, []string, string, string) {
	t.Helper()
	store, err := (Store{SessionsDirectory: filepath.Join(t.TempDir(), ".acs", "sessions")}).bindStorage(true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.storage.close)
	directory := store.storage.records
	if kind == "capabilities" {
		directory = store.storage.capabilities
	}
	challenge := strings.Repeat("6b", 32)
	for number := 0; number < formerRecordLimit+2; number++ {
		var raw [16]byte
		binary.BigEndian.PutUint64(raw[8:], uint64(number))
		id := "ses_" + idEncoding.EncodeToString(raw[:])
		cap := lookupScanCapability(id, "session-unrelated", challenge)
		var value any = cap
		if kind != "capabilities" {
			rec := lookupScanRecord(cap)
			rec.State, rec.RemovedAt = StateRemoved, rec.UpdatedAt
			setCompletionBinding(&rec, cap)
			value = rec
		}
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory.path, id+".json"), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	scan, err := directory.openScan()
	if err != nil {
		t.Fatal(err)
	}
	defer scan.Close()
	entries, err := scan.ReadDir(-1)
	if err != nil {
		t.Fatal(err)
	}
	ids := make([]string, len(entries))
	for i, entry := range entries {
		ids[i] = strings.TrimSuffix(entry.Name(), ".json")
	}
	return store, ids, "session-lookup-match", challenge
}

func lookupScanCapability(id, rootName, challenge string) capability {
	return capability{Version: SchemaVersion, ID: id, RootName: rootName, RootToken: strings.Repeat("5a", 32), Generation: 1, Challenge: challenge}
}

func lookupScanRecord(cap capability) record {
	now := formatTime(time.Now())
	return record{Version: SchemaVersion, ID: cap.ID, Revision: 1, State: StateActive, Target: "codex-auth", CreatedAt: now, UpdatedAt: now, RootToken: cap.RootToken, Generation: cap.Generation}
}

func writeLookupMatch(t *testing.T, store Store, kind, id, rootName, challenge string) {
	t.Helper()
	cap := lookupScanCapability(id, rootName, challenge)
	rec := lookupScanRecord(cap)
	if kind == "capabilities" {
		writeLookupJSON(t, store.storage.capabilities, id+".json", cap)
		if err := store.writeRootBinding(rootBinding{Version: SchemaVersion, ID: id, RootName: rootName, RootToken: cap.RootToken}); err != nil {
			t.Fatal(err)
		}
	} else {
		rec.State, rec.RemovedAt = StateRemoved, rec.UpdatedAt
		setCompletionBinding(&rec, cap)
	}
	writeLookupJSON(t, store.storage.records, id+".json", rec)
}

func writeLookupJSON(t *testing.T, directory *privateDirectory, name string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	// Rewrite in place to preserve the scan order established by the fixture.
	if err := os.WriteFile(filepath.Join(directory.path, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestWalkDirectoryEntriesHandlesReadResults(t *testing.T) {
	injected := errors.New("injected read failure")
	full := make([]os.DirEntry, scanBatchSize)
	for i := range full {
		full[i] = lookupScanEntry(fmt.Sprint(i))
	}
	type readResult struct {
		entries []os.DirEntry
		err     error
	}
	for _, test := range []struct {
		name    string
		reads   []readResult
		visited int
		wantErr error
	}{
		{name: "empty EOF", reads: []readResult{{err: io.EOF}}},
		{name: "partial EOF", reads: []readResult{{entries: full[:3], err: io.EOF}}, visited: 3},
		{name: "exact batch", reads: []readResult{{entries: full}, {err: io.EOF}}, visited: scanBatchSize},
		{name: "short batch is not EOF", reads: []readResult{{entries: full[:1]}, {entries: full[1:3], err: io.EOF}}, visited: 3},
		{name: "read error", reads: []readResult{{err: injected}}, wantErr: injected},
		{name: "partial read error", reads: []readResult{{entries: full[:1], err: injected}}, wantErr: injected},
		{name: "later read error", reads: []readResult{{entries: full}, {err: injected}}, visited: scanBatchSize, wantErr: injected},
		{name: "no progress", reads: []readResult{{}}, wantErr: io.ErrNoProgress},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls, visited := 0, 0
			err := walkDirectoryEntries(func(limit int) ([]os.DirEntry, error) {
				if limit != 256 {
					t.Fatalf("read size = %d, want 256", limit)
				}
				if calls >= len(test.reads) {
					t.Fatal("read after terminal result")
				}
				result := test.reads[calls]
				calls++
				return result.entries, result.err
			}, func() error { return nil }, func(os.DirEntry) error {
				visited++
				return nil
			})
			if !errors.Is(err, test.wantErr) || calls != len(test.reads) || visited != test.visited {
				t.Fatalf("walk = err=%v calls=%d visited=%d, want err=%v calls=%d visited=%d", err, calls, visited, test.wantErr, len(test.reads), test.visited)
			}
		})
	}
}

func TestWalkDirectoryEntriesPropagatesValidationAndVisitorErrors(t *testing.T) {
	injected := errors.New("injected scan failure")
	for _, failedValidation := range []int{1, 2, 3} {
		t.Run(fmt.Sprintf("validation %d", failedValidation), func(t *testing.T) {
			validations, visits := 0, 0
			err := walkDirectoryEntries(func(int) ([]os.DirEntry, error) {
				return []os.DirEntry{lookupScanEntry("one")}, io.EOF
			}, func() error {
				validations++
				if validations == failedValidation {
					return injected
				}
				return nil
			}, func(os.DirEntry) error {
				visits++
				return nil
			})
			wantVisits := 0
			if failedValidation == 3 {
				wantVisits = 1
			}
			if !errors.Is(err, injected) || visits != wantVisits {
				t.Fatalf("validation failure = err=%v visits=%d, want visits=%d", err, visits, wantVisits)
			}
		})
	}
	visits := 0
	err := walkDirectoryEntries(func(int) ([]os.DirEntry, error) {
		return []os.DirEntry{lookupScanEntry("one"), lookupScanEntry("two")}, io.EOF
	}, func() error { return nil }, func(os.DirEntry) error {
		visits++
		return injected
	})
	if !errors.Is(err, injected) || visits != 1 {
		t.Fatalf("visitor failure = err=%v visits=%d", err, visits)
	}
}

func TestPrivateDirectoryWalkRestartsAfterCompleteAndInterruptedScans(t *testing.T) {
	directory := newWalkDirectoryFixture(t, scanBatchSize+1)
	for attempt := 0; attempt < 2; attempt++ {
		count := 0
		if err := directory.walkEntries(func(os.DirEntry) error { count++; return nil }); err != nil || count != scanBatchSize+1 {
			t.Fatalf("walk %d = count=%d err=%v", attempt, count, err)
		}
	}
	injected := errors.New("stop walk")
	if err := directory.walkEntries(func(os.DirEntry) error { return injected }); !errors.Is(err, injected) {
		t.Fatalf("interrupted walk = %v", err)
	}
	count := 0
	if err := directory.walkEntries(func(os.DirEntry) error { count++; return nil }); err != nil || count != scanBatchSize+1 {
		t.Fatalf("restarted walk = count=%d err=%v", count, err)
	}
}

func TestPrivateDirectoryWalkRejectsReplacementDuringScan(t *testing.T) {
	directory := newWalkDirectoryFixture(t, 1)
	visits := 0
	err := directory.walkEntries(func(os.DirEntry) error {
		visits++
		if err := os.Rename(directory.path, directory.path+"-displaced"); err != nil {
			t.Fatal(err)
		}
		return os.Mkdir(directory.path, 0o700)
	})
	if err == nil || visits != 1 {
		t.Fatalf("replacement scan = err=%v visits=%d", err, visits)
	}
	if err := directory.walkEntries(func(os.DirEntry) error { t.Fatal("visited replacement"); return nil }); err == nil {
		t.Fatal("replacement accepted by subsequent scan")
	}
}

func newWalkDirectoryFixture(t *testing.T, entries int) *privateDirectory {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < entries; i++ {
		if err := os.WriteFile(filepath.Join(path, fmt.Sprint(i)), []byte("entry"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	directory, err := pinPrivateDirectory(path, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(directory.close)
	return directory
}

type lookupScanEntry string

func (entry lookupScanEntry) Name() string         { return string(entry) }
func (lookupScanEntry) IsDir() bool                { return false }
func (lookupScanEntry) Type() os.FileMode          { return 0 }
func (lookupScanEntry) Info() (os.FileInfo, error) { return nil, errors.New("unused entry info") }
