package sessionops_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
	"github.com/alcimerio/ai-config-selector/internal/sessionops"
)

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

func TestCorruptRecordIsInspectableWithoutMalformedBytes(t *testing.T) {
	root := t.TempDir()
	sessions := filepath.Join(root, ".acs", "sessions")
	id := "ses_abcd234567abcdef234567abcd"
	records := filepath.Join(launch.SessionOperationsDirectory(sessions), "records")
	if err := os.MkdirAll(records, 0o700); err != nil {
		t.Fatal(err)
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
