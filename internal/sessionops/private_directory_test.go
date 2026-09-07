package sessionops

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"golang.org/x/sys/unix"
)

func TestPrivateDirectoryScansUseAtomicCLOEXECIndependentDescriptions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two", "three"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	directory, err := pinPrivateDirectory(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	scan, err := directory.openScan()
	if err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(scan.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("scan descriptor is inheritable")
	}
	_ = scan.Close()
	first, err := directory.entries(16)
	if err != nil {
		t.Fatal(err)
	}
	second, err := directory.entries(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 || len(second) != 3 {
		t.Fatalf("repeated scans = %d, %d", len(first), len(second))
	}
}

func TestFinalizeRemovalRetriesFromDurableCompletionAfterRecordWriteFault(t *testing.T) {
	sessions := filepath.Join(t.TempDir(), ".acs", "sessions")
	store, err := (Store{SessionsDirectory: sessions}).bindStorage(true)
	if err != nil {
		t.Fatal(err)
	}
	id := "ses_abcd234567abcdef234567abcd"
	rootName := "session-fault-retry"
	token := hex.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	challenge := hex.EncodeToString(bytes.Repeat([]byte{0x6b}, 32))
	now := formatTime(time.Now())
	if err := store.writeRootBinding(rootBinding{Version: SchemaVersion, ID: id, RootName: rootName, RootToken: token}); err != nil {
		t.Fatal(err)
	}
	if err := store.writeCapability(capability{Version: SchemaVersion, ID: id, RootName: rootName, RootToken: token, Generation: 1, Challenge: challenge}); err != nil {
		t.Fatal(err)
	}
	if err := store.writeRecord(record{Version: SchemaVersion, ID: id, Revision: 1, State: StateActive, Target: "codex-auth", CreatedAt: now, UpdatedAt: now, RootToken: token, Generation: 1}); err != nil {
		t.Fatal(err)
	}
	fault := errors.New("injected record rename failure")
	store.storage.records.beforeRename = func(string) error { return fault }
	removeCalls, finalizeCalls := 0, 0
	err = store.FinalizeRemoval(rootName, challenge, func() (bool, error) {
		removeCalls++
		return true, nil
	}, func() error {
		finalizeCalls++
		return nil
	})
	if err == nil || removeCalls != 1 || finalizeCalls != 0 {
		t.Fatalf("faulted finalization = (%v, remove=%d, finalize=%d)", err, removeCalls, finalizeCalls)
	}
	inspection, err := (Store{SessionsDirectory: sessions}).Inspect(id)
	if err != nil || inspection.Session.State != StateUnknown {
		t.Fatalf("record fault changed public state = (%+v, %v)", inspection, err)
	}
	evidence, err := (Store{SessionsDirectory: sessions}).bindStorage(false)
	if err != nil {
		t.Fatal(err)
	}
	rec, exists, recErr := evidence.readRecord(id)
	cap, capExists, capErr := evidence.readCapability(id)
	evidence.storage.close()
	if recErr != nil || capErr != nil || !exists || !capExists || rec.State != StateActive || !cap.Removed {
		t.Fatalf("fault evidence = (record=%+v/%v/%v, capability=%+v/%v/%v)", rec, exists, recErr, cap, capExists, capErr)
	}
	retry := Store{SessionsDirectory: sessions, AuthRecovery: func() (AuthRecovery, error) {
		return faultRetryAuth{rootName: rootName, challenge: challenge, finalized: &finalizeCalls}, nil
	}}
	result, err := retry.Recover(id)
	if err != nil || result.Outcome != "removed" || removeCalls != 1 || finalizeCalls != 1 {
		t.Fatalf("general completion retry = (%+v, %v, remove=%d, finalize=%d)", result, err, removeCalls, finalizeCalls)
	}
	inspection, err = (Store{SessionsDirectory: sessions}).Inspect(id)
	if err != nil || inspection.Session.State != StateRemoved {
		t.Fatalf("retried public state = (%+v, %v)", inspection, err)
	}
}

func TestRecoverRetriesDurableCompletionAfterPostRemovalRecordFault(t *testing.T) {
	sessions := filepath.Join(t.TempDir(), ".acs", "sessions")
	lease, err := launch.CreateProtectedSession(sessions)
	if err != nil {
		t.Fatal(err)
	}
	tracker, err := NewTracker(sessions, lease.RootDir, "shell")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tracker.Arm(nil); err != nil {
		t.Fatal(err)
	}
	if err := lease.PreserveForRecovery(); err != nil {
		t.Fatal(err)
	}
	store, err := (Store{SessionsDirectory: sessions}).bindStorage(false)
	if err != nil {
		t.Fatal(err)
	}
	recordWrites := 0
	store.storage.records.beforeRename = func(string) error {
		recordWrites++
		if recordWrites == 2 {
			return errors.New("injected post-removal record fault")
		}
		return nil
	}
	result, err := store.Recover(tracker.ID())
	if err == nil || result.Outcome != "removal_failed" || recordWrites != 2 {
		t.Fatalf("faulted general recovery = (%+v, writes=%d, %v)", result, recordWrites, err)
	}
	retried, err := (Store{SessionsDirectory: sessions}).Recover(tracker.ID())
	if err != nil || retried.Outcome != "removed" || retried.State != StateRemoved {
		t.Fatalf("durable completion retry = (%+v, %v)", retried, err)
	}
}

func TestCompletedRemovalRetriesAfterPrivateUnlinkFaults(t *testing.T) {
	// Each row is a partial-success boundary in the durable finalization order:
	// capability completion, public record, typed marker, root binding, capability.
	// At these two unlink boundaries the durable completion and public removal
	// are already published, so either public recovery command must converge.
	for _, fault := range []string{"root binding", "capability"} {
		for _, retryCommand := range []string{"direct", "general"} {
			t.Run(fault+"/"+retryCommand, func(t *testing.T) {
				sessions := filepath.Join(t.TempDir(), ".acs", "sessions")
				store, id, rootName, token, challenge := newFinalizationFaultFixture(t, sessions)
				injected := errors.New("injected unlink failure")
				if fault == "root binding" {
					store.storage.locks.beforeUnlink = func(name string) error {
						if name == rootBindingName(rootName) {
							return injected
						}
						return nil
					}
				} else {
					store.storage.capabilities.beforeUnlink = func(name string) error {
						if name == id+".json" {
							return injected
						}
						return nil
					}
				}
				removeCalls, markerCalls := 0, 0
				err := store.FinalizeRemoval(rootName, challenge, func() (bool, error) {
					removeCalls++
					return true, nil
				}, func() error {
					markerCalls++
					return nil
				})
				if err == nil || removeCalls != 1 || markerCalls != 1 {
					t.Fatalf("faulted sequence = (%v, remove=%d, marker=%d)", err, removeCalls, markerCalls)
				}
				if retryCommand == "direct" {
					err = (Store{SessionsDirectory: sessions}).FinalizeRemoval(rootName, challenge, func() (bool, error) {
						t.Fatal("completed direct retry repeated physical removal")
						return false, nil
					}, func() error {
						markerCalls++
						return nil
					})
					if err != nil || markerCalls != 2 {
						t.Fatalf("completed direct retry = (%v, marker=%d), token=%s", err, markerCalls, token)
					}
				} else {
					retry := Store{SessionsDirectory: sessions, AuthRecovery: func() (AuthRecovery, error) {
						return missingFaultRetryAuth{}, nil
					}}
					result, recoverErr := retry.Recover(id)
					if recoverErr != nil || result.Outcome != "removed" {
						t.Fatalf("completed general retry = (%+v, %v), token=%s", result, recoverErr, token)
					}
				}
				if _, err := os.Stat(filepath.Join(sessionOperationsDirectoryForTest(sessions), "capabilities", id+".json")); !os.IsNotExist(err) {
					t.Fatalf("capability remains after retry: %v", err)
				}
			})
		}
	}
}

func newFinalizationFaultFixture(t *testing.T, sessions string) (Store, string, string, string, string) {
	t.Helper()
	store, err := (Store{SessionsDirectory: sessions}).bindStorage(true)
	if err != nil {
		t.Fatal(err)
	}
	id := "ses_abcd234567abcdef234567abcd"
	rootName := "session-fault-retry"
	token := hex.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	challenge := hex.EncodeToString(bytes.Repeat([]byte{0x6b}, 32))
	now := formatTime(time.Now())
	if err := store.writeRootBinding(rootBinding{Version: SchemaVersion, ID: id, RootName: rootName, RootToken: token}); err != nil {
		t.Fatal(err)
	}
	if err := store.writeCapability(capability{Version: SchemaVersion, ID: id, RootName: rootName, RootToken: token, Generation: 1, Challenge: challenge}); err != nil {
		t.Fatal(err)
	}
	if err := store.writeRecord(record{Version: SchemaVersion, ID: id, Revision: 1, State: StateActive, Target: "codex-auth", CreatedAt: now, UpdatedAt: now, RootToken: token, Generation: 1}); err != nil {
		t.Fatal(err)
	}
	return store, id, rootName, token, challenge
}

func sessionOperationsDirectoryForTest(sessions string) string {
	return filepath.Join(filepath.Dir(filepath.Clean(sessions)), "session-operations-v1")
}

type faultRetryAuth struct {
	rootName  string
	challenge string
	finalized *int
}

func (auth faultRetryAuth) AcquireBySession(_ context.Context, rootName string) (AuthRecoveryBinding, bool, error) {
	if rootName != auth.rootName {
		return nil, false, nil
	}
	return faultRetryBinding{challenge: auth.challenge, finalized: auth.finalized}, true, nil
}

type faultRetryBinding struct {
	challenge string
	finalized *int
}

func (binding faultRetryBinding) CleanupChallenge() string { return binding.challenge }
func (faultRetryBinding) Prepared() bool                   { return true }
func (faultRetryBinding) FinalizeRecovery(context.Context, string) error {
	return nil
}
func (binding faultRetryBinding) DeleteMarkerAfterProjectionRemoval(context.Context) error {
	*binding.finalized++
	return nil
}
func (faultRetryBinding) Release() error { return nil }

type missingFaultRetryAuth struct{}

func (missingFaultRetryAuth) AcquireBySession(context.Context, string) (AuthRecoveryBinding, bool, error) {
	return nil, false, nil
}

func TestPrivateDirectoryAppliesLimitBeforeReturningEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two", "three", "four"} {
		if err := os.WriteFile(filepath.Join(path, name), []byte(name), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	directory, err := pinPrivateDirectory(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	if entries, err := directory.entries(3); err == nil || entries != nil {
		t.Fatalf("over-limit scan = (%v, %v)", entries, err)
	}
}

func TestPrivateDirectoryLockRejectsHardLinkBeforeModeMutation(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "private")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("unchanged"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(victim, filepath.Join(path, "session.lock")); err != nil {
		t.Fatal(err)
	}
	directory, err := pinPrivateDirectory(path, false)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.close()
	if file, err := directory.lock("session.lock", true); err == nil {
		file.Close()
		t.Fatal("hard-linked lock accepted")
	}
	info, err := os.Stat(victim)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("victim mode mutated to %o", info.Mode().Perm())
	}
}

func TestPrivateChildRejectsParentReplacementWithoutFollowingNewPath(t *testing.T) {
	root := t.TempDir()
	basePath := filepath.Join(root, "private")
	if err := os.Mkdir(basePath, 0o700); err != nil {
		t.Fatal(err)
	}
	base, err := pinPrivateDirectory(basePath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer base.close()
	child, err := pinPrivateChild(base, "records", true)
	if err != nil {
		t.Fatal(err)
	}
	defer child.close()
	displaced := filepath.Join(root, "displaced")
	if err := os.Rename(basePath, displaced); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(basePath, "records"), 0o700); err != nil {
		t.Fatal(err)
	}
	decoy := filepath.Join(basePath, "records", "decoy")
	if err := os.WriteFile(decoy, []byte("must remain unread"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := child.entries(8); err == nil {
		t.Fatal("pinned child accepted a replaced parent path")
	}
	if got, err := os.ReadFile(decoy); err != nil || string(got) != "must remain unread" {
		t.Fatalf("replacement path changed = (%q, %v)", got, err)
	}
}
