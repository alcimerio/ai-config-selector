package sessionops_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
	"github.com/alcimerio/ai-config-selector/internal/sessionops"
)

type recoveryErrorAuth struct{ err error }

func (auth recoveryErrorAuth) AcquireBySession(context.Context, string) (sessionops.AuthRecoveryBinding, bool, error) {
	return nil, true, auth.err
}

func TestTypedRecoveryErrorsUseSemanticContentionClassification(t *testing.T) {
	tests := []struct {
		name, message, outcome string
		err                    error
	}{
		{name: "wrapped busy", err: fmt.Errorf("typed wrapper: %w", sessionops.ErrAuthBusy), outcome: "busy"},
		{name: "deadline", err: context.DeadlineExceeded, outcome: "busy"},
		{name: "cancelled", err: context.Canceled, outcome: "busy"},
		{name: "busy words are not semantics", err: errors.New("provider busy during timeout while identity is in use"), outcome: "not_recoverable"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			sessions := filepath.Join(home, ".acs", "sessions")
			created, err := session.CreateTracked(sessions, home, nil, "codex")
			if err != nil {
				t.Fatal(err)
			}
			defer created.Remove()
			if _, err := created.ArmOperation(nil); err != nil {
				t.Fatal(err)
			}
			result, err := (sessionops.Store{
				SessionsDirectory: sessions,
				AuthRecovery: func() (sessionops.AuthRecovery, error) {
					return recoveryErrorAuth{err: test.err}, nil
				},
			}).Recover(created.PublicID())
			if err == nil || result.Outcome != test.outcome || sessionops.Diagnostic(err) != test.outcome {
				t.Fatalf("recovery = (%+v, %v), want %s", result, err, test.outcome)
			}
		})
	}
}

type deferredProcess struct{ done chan struct{} }

func (process deferredProcess) Start() error                 { return nil }
func (process deferredProcess) Wait() error                  { return nil }
func (process deferredProcess) Signal(os.Signal) error       { return nil }
func (process deferredProcess) CleanupDone() <-chan struct{} { return process.done }

func TestTrackedSessionPublishesSanitizedRecordAndProofGatedRecovery(t *testing.T) {
	root := t.TempDir()
	sessions := filepath.Join(root, ".acs", "sessions")
	created, err := session.CreateTracked(sessions, root, nil, "shell")
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := created.ArmOperation(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(challenge) != launch.RecoveryProofChallengeSize {
		t.Fatalf("challenge length = %d", len(challenge))
	}
	store := sessionops.Store{SessionsDirectory: sessions}
	inspected, err := store.Inspect(created.PublicID())
	if err != nil {
		t.Fatal(err)
	}
	if inspected.Session.State != sessionops.StateActive || inspected.Session.Observation != "unverified" || !inspected.Session.Recovery.Allowed {
		t.Fatalf("active inspection = %+v", inspected.Session)
	}
	encoded, err := json.Marshal(inspected)
	if err != nil {
		t.Fatal(err)
	}
	private := string(encoded)
	if strings.Contains(private, filepath.Base(created.RootDirectory())) || strings.Contains(private, string(challenge)) || strings.Contains(private, "challenge") || strings.Contains(private, "rootToken") {
		t.Fatalf("public output exposed private binding: %s", private)
	}
	active, err := store.Recover(created.PublicID())
	if err == nil || active.Outcome != "active" {
		t.Fatalf("active recovery = %+v, %v", active, err)
	}
	if err := created.PreserveForRecovery(); err != nil {
		t.Fatal(err)
	}
	recovered, err := store.Recover(created.PublicID())
	if err != nil {
		t.Fatalf("recover: %v (%+v)", err, recovered)
	}
	if recovered.Outcome != "removed" || recovered.State != sessionops.StateRemoved {
		t.Fatalf("recovery = %+v", recovered)
	}
	if _, err := os.Stat(created.RootDirectory()); !os.IsNotExist(err) {
		t.Fatalf("root remains: %v", err)
	}
}

func TestRecoveryRejectsStaleGenerationProof(t *testing.T) {
	root := t.TempDir()
	sessions := filepath.Join(root, ".acs", "sessions")
	created, err := session.CreateTracked(sessions, root, nil, "devin")
	if err != nil {
		t.Fatal(err)
	}
	oldChallenge, err := created.ArmOperation(nil)
	if err != nil {
		t.Fatal(err)
	}
	newChallenge, err := created.ArmOperation(nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(oldChallenge, newChallenge) {
		t.Fatal("generation reused its challenge")
	}
	if err := launch.PrepareSessionCleanupProof(created.RootDirectory(), oldChallenge); err != nil {
		t.Fatal(err)
	}
	if err := created.PreserveForRecovery(); err != nil {
		t.Fatal(err)
	}
	result, err := (sessionops.Store{SessionsDirectory: sessions}).Recover(created.PublicID())
	if err == nil || result.Outcome != "unproven" {
		t.Fatalf("stale proof recovery = %+v, %v", result, err)
	}
	if _, err := os.Stat(created.RootDirectory()); err != nil {
		t.Fatalf("unproven root was not retained: %v", err)
	}
}

func TestArmRejectsUntrustedExistingRecordBeforeAnyMutation(t *testing.T) {
	tests := []struct {
		name  string
		alter func(*testing.T, string, []byte)
	}{
		{
			name: "malformed",
			alter: func(t *testing.T, path string, _ []byte) {
				if err := os.WriteFile(path, []byte(`{"version":`), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "duplicate key",
			alter: func(t *testing.T, path string, valid []byte) {
				duplicate := bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
				if err := os.WriteFile(path, duplicate, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hard link",
			alter: func(t *testing.T, path string, valid []byte) {
				victim := filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(path))), "record-victim")
				if err := os.WriteFile(victim, valid, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(victim, path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "mismatched binding",
			alter: func(t *testing.T, path string, valid []byte) {
				var object map[string]any
				if err := json.Unmarshal(valid, &object); err != nil {
					t.Fatal(err)
				}
				object["rootToken"] = strings.Repeat("0", 64)
				changed, err := json.Marshal(object)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, append(changed, '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			sessions := filepath.Join(root, ".acs", "sessions")
			created, err := session.CreateTracked(sessions, root, nil, "shell")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := created.ArmOperation(nil); err != nil {
				t.Fatal(err)
			}
			private := launch.SessionOperationsDirectory(sessions)
			recordPath := filepath.Join(private, "records", created.PublicID()+".json")
			capabilityPath := filepath.Join(private, "capabilities", created.PublicID()+".json")
			validRecord, err := os.ReadFile(recordPath)
			if err != nil {
				t.Fatal(err)
			}
			test.alter(t, recordPath, validRecord)
			beforeRecord, err := os.ReadFile(recordPath)
			if err != nil {
				t.Fatal(err)
			}
			beforeCapability, err := os.ReadFile(capabilityPath)
			if err != nil {
				t.Fatal(err)
			}
			beforeRoot := snapshotRegularFiles(t, created.RootDirectory())
			if _, err := created.ArmOperation(bytes.Repeat([]byte{0x7a}, launch.RecoveryProofChallengeSize)); err == nil {
				t.Fatal("second Arm accepted untrusted existing record")
			}
			afterRecord, _ := os.ReadFile(recordPath)
			afterCapability, _ := os.ReadFile(capabilityPath)
			afterRoot := snapshotRegularFiles(t, created.RootDirectory())
			if !bytes.Equal(afterRecord, beforeRecord) || !bytes.Equal(afterCapability, beforeCapability) || !reflect.DeepEqual(afterRoot, beforeRoot) {
				t.Fatal("rejected Arm mutated record, capability, or native proof")
			}
		})
	}
}

func snapshotRegularFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
	result := map[string][]byte{}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		result[relative] = data
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestDeferredCleanupDonePublishesRemovedFromLeaseOwner(t *testing.T) {
	root := t.TempDir()
	sessions := filepath.Join(root, ".acs", "sessions")
	created, err := session.CreateTracked(sessions, root, nil, "command")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := created.ArmOperation(nil); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	retained, err := created.RetainUntilProcessDone(deferredProcess{done: done})
	if err != nil {
		t.Fatal(err)
	}
	if err := retained.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := created.Remove(); err != nil {
		t.Fatal(err)
	}
	before, err := (sessionops.Store{SessionsDirectory: sessions}).Inspect(created.PublicID())
	if err != nil {
		t.Fatal(err)
	}
	if before.Session.State != sessionops.StateSettling {
		t.Fatalf("pending state = %s", before.Session.State)
	}
	close(done)
	deadline := time.Now().Add(2 * time.Second)
	for {
		after, inspectErr := (sessionops.Store{SessionsDirectory: sessions}).Inspect(created.PublicID())
		if inspectErr == nil && after.Session.State == sessionops.StateRemoved {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("deferred cleanup did not publish removed: %+v, %v", after, inspectErr)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestFinalizeRemovalDoesNotTreatTrackedRootAbsenceAsCleanupProof(t *testing.T) {
	root := t.TempDir()
	sessions := filepath.Join(root, ".acs", "sessions")
	created, err := session.CreateTracked(sessions, root, nil, "codex-auth")
	if err != nil {
		t.Fatal(err)
	}
	challenge, err := created.ArmOperation(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.PreserveForRecovery(); err != nil {
		t.Fatal(err)
	}
	recovered, exists, err := launch.RecoverSession(sessions, filepath.Base(created.RootDirectory()))
	if err != nil || !exists {
		t.Fatalf("acquire physical cleanup = (%v, %v)", exists, err)
	}
	if err := recovered.Remove(); err != nil {
		t.Fatal(err)
	}
	private := launch.SessionOperationsDirectory(sessions)
	recordPath := filepath.Join(private, "records", created.PublicID()+".json")
	capabilityPath := filepath.Join(private, "capabilities", created.PublicID()+".json")
	beforeRecord, _ := os.ReadFile(recordPath)
	beforeCapability, _ := os.ReadFile(capabilityPath)
	store := sessionops.Store{SessionsDirectory: sessions}
	err = store.FinalizeRemoval(filepath.Base(created.RootDirectory()), hex.EncodeToString(challenge), func() (bool, error) {
		return false, nil
	}, func() error {
		t.Fatal("typed marker finalized without physical cleanup evidence")
		return nil
	})
	if err == nil {
		t.Fatal("tracked missing root was accepted as physical cleanup proof")
	}
	afterRecord, _ := os.ReadFile(recordPath)
	afterCapability, _ := os.ReadFile(capabilityPath)
	if !bytes.Equal(afterRecord, beforeRecord) || !bytes.Equal(afterCapability, beforeCapability) {
		t.Fatal("missing-root rejection mutated durable recovery evidence")
	}
	inspected, inspectErr := store.Inspect(created.PublicID())
	if inspectErr != nil || inspected.Session.State != sessionops.StateUnknown {
		t.Fatalf("missing-root inspection = (%+v, %v)", inspected, inspectErr)
	}
}

func TestPassiveMissingStoreDoesNotCreateState(t *testing.T) {
	root := t.TempDir()
	sessions := filepath.Join(root, ".acs", "sessions")
	store := sessionops.Store{SessionsDirectory: sessions}
	listed, err := store.List("")
	if err != nil {
		t.Fatal(err)
	}
	if listed.Sessions == nil || len(listed.Sessions) != 0 || listed.UntrackedCount != 0 {
		t.Fatalf("missing list = %+v", listed)
	}
	if _, err := os.Stat(filepath.Join(root, ".acs")); !os.IsNotExist(err) {
		t.Fatalf("passive list created storage: %v", err)
	}
}

func TestListRejectsBoundedUntrackedEnumerationWithoutPartialCounts(t *testing.T) {
	sessions := filepath.Join(t.TempDir(), ".acs", "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index <= sessionops.MaxScannedEntries; index++ {
		if err := os.Mkdir(filepath.Join(sessions, fmt.Sprintf("session-untracked-%04d", index)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	result, err := (sessionops.Store{SessionsDirectory: sessions}).List("")
	if sessionops.Diagnostic(err) != "session_registry_limit" || len(result.Sessions) != 0 || result.UntrackedCount != 0 {
		t.Fatalf("bounded list = (%+v, %v)", result, err)
	}
}

func TestRemovedRetentionPrunesMetadataButKeepsPermanentFenceInode(t *testing.T) {
	root := t.TempDir()
	sessions := filepath.Join(root, ".acs", "sessions")
	created, err := session.CreateTracked(sessions, root, nil, "shell")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := created.ArmOperation(nil); err != nil {
		t.Fatal(err)
	}
	if err := created.PreserveForRecovery(); err != nil {
		t.Fatal(err)
	}
	store := sessionops.Store{SessionsDirectory: sessions}
	if result, err := store.Recover(created.PublicID()); err != nil || result.State != sessionops.StateRemoved {
		t.Fatalf("initial recovery = (%+v, %v)", result, err)
	}
	private := launch.SessionOperationsDirectory(sessions)
	recordPath := filepath.Join(private, "records", created.PublicID()+".json")
	data, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatal(err)
	}
	old := time.Now().UTC().Add(-sessionops.RemovedRetention - time.Hour).Truncate(time.Second).Format(time.RFC3339)
	object["removedAt"], object["updatedAt"] = old, old
	data, err = json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	trigger, err := sessionops.NewTracker(sessions, filepath.Join(sessions, "session-retention-trigger"), "shell")
	if err != nil {
		t.Fatal(err)
	}
	if err := trigger.Removed(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Inspect(created.PublicID()); err == nil || sessionops.Diagnostic(err) != "session_not_found" {
		t.Fatalf("expired removed record remains: %v", err)
	}
	lockPath := filepath.Join(private, "locks", created.PublicID()+".lock")
	info, err := os.Stat(lockPath)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("retention removed permanent fence inode: (%v, %v)", info, err)
	}
}

func TestCorruptRecordIsInspectableWithoutMalformedBytes(t *testing.T) {
	root := t.TempDir()
	sessions := filepath.Join(root, ".acs", "sessions")
	id := "ses_abcd234567abcdef234567abcd"
	records := filepath.Join(launch.SessionOperationsDirectory(sessions), "records")
	for _, directory := range []string{records, filepath.Join(launch.SessionOperationsDirectory(sessions), "capabilities"), filepath.Join(launch.SessionOperationsDirectory(sessions), "locks")} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	secret := "PRIVATE-MALFORMED-CONTENT"
	if err := os.WriteFile(filepath.Join(records, id+".json"), []byte(`{"version":1,"secret":"`+secret+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	inspected, err := (sessionops.Store{SessionsDirectory: sessions}).Inspect(id)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(inspected)
	if inspected.Session.State != sessionops.StateCorrupt || strings.Contains(string(encoded), secret) {
		t.Fatalf("corrupt inspection = %s", encoded)
	}
}

func TestRecoveryRejectsDuplicateCapabilityWithoutRemovingRoot(t *testing.T) {
	root := t.TempDir()
	sessions := filepath.Join(root, ".acs", "sessions")
	created, err := session.CreateTracked(sessions, root, nil, "shell")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := created.ArmOperation(nil); err != nil {
		t.Fatal(err)
	}
	capabilityPath := filepath.Join(launch.SessionOperationsDirectory(sessions), "capabilities", created.PublicID()+".json")
	valid, err := os.ReadFile(capabilityPath)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(valid, []byte(`"version":1`), []byte(`"version":1,"version":1`), 1)
	if err := os.WriteFile(capabilityPath, duplicate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := created.PreserveForRecovery(); err != nil {
		t.Fatal(err)
	}
	result, err := (sessionops.Store{SessionsDirectory: sessions}).Recover(created.PublicID())
	if err == nil || result.Outcome != "unproven" || result.State != sessionops.StateUnproven {
		t.Fatalf("duplicate capability recovery = (%+v, %v)", result, err)
	}
	if _, err := os.Stat(created.RootDirectory()); err != nil {
		t.Fatalf("duplicate capability removed root: %v", err)
	}
	after, err := os.ReadFile(capabilityPath)
	if err != nil || !bytes.Equal(after, duplicate) {
		t.Fatalf("duplicate capability evidence changed: (%q, %v)", after, err)
	}
}

func TestCompletionCannotBypassGenerationTokenOrRootBinding(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, string, string)
	}{
		{
			name: "generation",
			mutate: func(t *testing.T, capabilityPath, _ string) {
				mutateSessionJSON(t, capabilityPath, func(value map[string]any) {
					value["generation"] = value["generation"].(float64) + 1
					value["removed"] = true
				})
			},
		},
		{
			name: "root token",
			mutate: func(t *testing.T, capabilityPath, _ string) {
				mutateSessionJSON(t, capabilityPath, func(value map[string]any) {
					value["rootToken"] = strings.Repeat("0", 64)
					value["removed"] = true
				})
			},
		},
		{
			name: "root binding",
			mutate: func(t *testing.T, capabilityPath, locks string) {
				mutateSessionJSON(t, capabilityPath, func(value map[string]any) { value["removed"] = true })
				entries, err := os.ReadDir(locks)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".root-") {
						mutateSessionJSON(t, filepath.Join(locks, entry.Name()), func(value map[string]any) { value["rootToken"] = strings.Repeat("1", 64) })
						return
					}
				}
				t.Fatal("root binding fixture not found")
			},
		},
		{
			name: "missing root binding before completion",
			mutate: func(t *testing.T, capabilityPath, locks string) {
				mutateSessionJSON(t, capabilityPath, func(value map[string]any) { value["removed"] = true })
				entries, err := os.ReadDir(locks)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					if strings.HasPrefix(entry.Name(), ".root-") {
						if err := os.Remove(filepath.Join(locks, entry.Name())); err != nil {
							t.Fatal(err)
						}
						return
					}
				}
				t.Fatal("root binding fixture not found")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			sessions := filepath.Join(home, ".acs", "sessions")
			created, err := session.CreateTracked(sessions, home, nil, "command")
			if err != nil {
				t.Fatal(err)
			}
			defer created.Remove()
			if _, err := created.ArmOperation(nil); err != nil {
				t.Fatal(err)
			}
			private := launch.SessionOperationsDirectory(sessions)
			capabilityPath := filepath.Join(private, "capabilities", created.PublicID()+".json")
			test.mutate(t, capabilityPath, filepath.Join(private, "locks"))
			result, err := (sessionops.Store{SessionsDirectory: sessions}).Recover(created.PublicID())
			if err == nil || result.Outcome == "removed" {
				t.Fatalf("mismatched completion authorized recovery: result=%+v err=%v", result, err)
			}
			if _, err := os.Stat(created.RootDirectory()); err != nil {
				t.Fatalf("live root lost: %v", err)
			}
			if _, err := os.Stat(capabilityPath); err != nil {
				t.Fatalf("mismatched evidence discarded: %v", err)
			}
		})
	}
}

func mutateSessionJSON(t *testing.T, path string, mutate func(map[string]any)) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	data, err = json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}
