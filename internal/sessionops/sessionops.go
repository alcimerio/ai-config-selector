// Package sessionops owns the bounded durable index and recovery authority for
// ACS Sessions. Public records are descriptive; only the separate private
// capability plus the native cleanup proof can authorize removal.
package sessionops

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

const (
	SchemaVersion      = 1
	MaxRecordBytes     = 16 << 10
	MaxScannedEntries  = 4096
	MaxPublicJSONBytes = 1 << 20
	RemovedRetention   = 720 * time.Hour
)

var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

type State string

const (
	StateActive    State = "active"
	StateSettling  State = "settling"
	StateRetryable State = "retryable"
	StateUnproven  State = "unproven"
	StateRemovable State = "removable"
	StateRemoved   State = "removed"
	StateUnknown   State = "unknown"
	StateCorrupt   State = "corrupt"
)

type Recovery struct {
	Allowed bool   `json:"allowed"`
	Action  string `json:"action"`
}

type PublicSession struct {
	ID          string   `json:"id"`
	State       State    `json:"state"`
	Observation string   `json:"observation"`
	Target      string   `json:"target,omitempty"`
	CreatedAt   string   `json:"createdAt,omitempty"`
	UpdatedAt   string   `json:"updatedAt,omitempty"`
	Revision    uint64   `json:"revision,omitempty"`
	Recovery    Recovery `json:"recovery"`
}

type ListResult struct {
	SchemaVersion  int             `json:"schemaVersion"`
	Sessions       []PublicSession `json:"sessions"`
	UntrackedCount int             `json:"untrackedCount"`
}

type InspectResult struct {
	SchemaVersion int           `json:"schemaVersion"`
	Session       PublicSession `json:"session"`
}

type RecoverResult struct {
	SchemaVersion int    `json:"schemaVersion"`
	ID            string `json:"id"`
	Outcome       string `json:"outcome"`
	State         State  `json:"state,omitempty"`
	Revision      uint64 `json:"revision,omitempty"`
}

type record struct {
	Version    int    `json:"version"`
	ID         string `json:"id"`
	Revision   uint64 `json:"revision"`
	State      State  `json:"state"`
	Target     string `json:"target"`
	CreatedAt  string `json:"createdAt"`
	UpdatedAt  string `json:"updatedAt"`
	RemovedAt  string `json:"removedAt,omitempty"`
	RootToken  string `json:"rootToken"`
	Generation uint64 `json:"generation"`
}

type capability struct {
	Version    int    `json:"version"`
	ID         string `json:"id"`
	RootName   string `json:"rootName"`
	RootToken  string `json:"rootToken"`
	Generation uint64 `json:"generation"`
	Challenge  string `json:"challenge"`
}

type Store struct {
	SessionsDirectory string
	Now               func() time.Time
	AuthRecovery      func() (AuthRecovery, error)
}

type AuthRecovery interface {
	AcquireBySession(context.Context, string) (AuthRecoveryBinding, bool, error)
}

type AuthRecoveryBinding interface {
	CleanupChallenge() string
	Prepared() bool
	FinalizeRecovery(context.Context, string) error
	DeleteMarkerAfterProjectionRemoval(context.Context) error
	Release() error
}

type Tracker struct {
	store      Store
	id         string
	root       string
	rootToken  string
	target     string
	generation uint64
}

func NewTracker(sessionsDirectory, root, target string) (*Tracker, error) {
	if !validTarget(target) || filepath.Dir(root) != filepath.Clean(sessionsDirectory) || filepath.Base(root) == "." {
		return nil, errors.New("track ACS Session: invalid binding")
	}
	store := Store{SessionsDirectory: filepath.Clean(sessionsDirectory)}
	if err := store.ensureStorage(); err != nil {
		return nil, errors.New("track ACS Session: registry unavailable")
	}
	allocation, err := openLocked(filepath.Join(store.baseDirectory(), ".allocation.lock"), false)
	if err != nil {
		return nil, errors.New("track ACS Session: coordination failed")
	}
	defer closeLocked(allocation)
	_ = store.pruneRemoved()
	var id string
	for attempt := 0; attempt < 8; attempt++ {
		idBytes := make([]byte, 16)
		if _, err := rand.Read(idBytes); err != nil {
			return nil, errors.New("track ACS Session: random allocation failed")
		}
		id = "ses_" + idEncoding.EncodeToString(idBytes)
		if _, err := os.Lstat(store.recordPath(id)); os.IsNotExist(err) {
			break
		}
		id = ""
	}
	if id == "" {
		return nil, errors.New("track ACS Session: identifier allocation failed")
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, errors.New("track ACS Session: random allocation failed")
	}
	return &Tracker{store: store, id: id, root: filepath.Clean(root), rootToken: hex.EncodeToString(tokenBytes), target: target}, nil
}

func (tracker *Tracker) ID() string {
	if tracker == nil {
		return ""
	}
	return tracker.id
}

// Arm advances the private generation before preparing the exact native proof.
// A caller-supplied challenge is used for typed Codex operations so there is
// never a second cleanup authority for the same contained process.
func (tracker *Tracker) Arm(challenge []byte) ([]byte, error) {
	if tracker == nil {
		return nil, errors.New("arm ACS Session: tracker unavailable")
	}
	if challenge == nil {
		challenge = make([]byte, launch.RecoveryProofChallengeSize)
		if _, err := rand.Read(challenge); err != nil {
			return nil, errors.New("arm ACS Session: random allocation failed")
		}
	}
	if len(challenge) != launch.RecoveryProofChallengeSize {
		return nil, errors.New("arm ACS Session: invalid challenge")
	}
	fence, err := tracker.store.openFence(tracker.id)
	if err != nil {
		return nil, errors.New("arm ACS Session: coordination failed")
	}
	defer closeLocked(fence)
	tracker.generation++
	now := tracker.store.now()
	capability := capability{Version: SchemaVersion, ID: tracker.id, RootName: filepath.Base(tracker.root), RootToken: tracker.rootToken, Generation: tracker.generation, Challenge: hex.EncodeToString(challenge)}
	if err := tracker.store.writeCapability(capability); err != nil {
		return nil, err
	}
	if err := launch.PrepareSessionCleanupProof(tracker.root, challenge); err != nil {
		return nil, errors.New("arm ACS Session: proof persistence failed")
	}
	current, exists, _ := tracker.store.readRecord(tracker.id)
	created := formatTime(now)
	revision := uint64(1)
	if exists {
		created, revision = current.CreatedAt, current.Revision+1
	}
	next := record{Version: SchemaVersion, ID: tracker.id, Revision: revision, State: StateActive, Target: tracker.target, CreatedAt: created, UpdatedAt: formatTime(now), RootToken: tracker.rootToken, Generation: tracker.generation}
	if err := tracker.store.writeRecord(next); err != nil {
		return nil, err
	}
	return append([]byte(nil), challenge...), nil
}

func (tracker *Tracker) Settling() error  { return tracker.transition(StateSettling, "") }
func (tracker *Tracker) Retryable() error { return tracker.transition(StateRetryable, "") }
func (tracker *Tracker) Removed() error {
	if tracker == nil || tracker.generation == 0 {
		return nil
	}
	if err := tracker.store.removeCapability(tracker.id); err != nil {
		return err
	}
	return tracker.transition(StateRemoved, formatTime(tracker.store.now()))
}

func (tracker *Tracker) transition(state State, removedAt string) error {
	if tracker == nil || tracker.generation == 0 {
		return nil
	}
	fence, err := tracker.store.openFence(tracker.id)
	if err != nil {
		return errors.New("update ACS Session: coordination failed")
	}
	defer closeLocked(fence)
	current, exists, err := tracker.store.readRecord(tracker.id)
	if err != nil || !exists || current.RootToken != tracker.rootToken || current.Generation != tracker.generation {
		return errors.New("update ACS Session: binding changed")
	}
	current.Revision++
	current.State, current.UpdatedAt, current.RemovedAt = state, formatTime(tracker.store.now()), removedAt
	return tracker.store.writeRecord(current)
}

func (store Store) List(filter State) (ListResult, error) {
	result := ListResult{SchemaVersion: SchemaVersion, Sessions: []PublicSession{}}
	entries, err := os.ReadDir(store.recordsDirectory())
	if os.IsNotExist(err) {
		result.UntrackedCount = store.countUntracked(nil)
		return result, nil
	}
	if err != nil {
		return result, errors.New("session_registry_unavailable")
	}
	if err := validateDirectory(store.baseDirectory()); err != nil {
		return result, errors.New("session_registry_unavailable")
	}
	if err := validateDirectory(store.recordsDirectory()); err != nil {
		return result, errors.New("session_registry_unavailable")
	}
	if len(entries) > MaxScannedEntries {
		return result, errors.New("session_registry_limit")
	}
	trackedRoots := map[string]bool{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !ValidID(id) {
			continue
		}
		rec, exists, readErr := store.readRecord(id)
		if readErr != nil {
			item := corruptPublic(id)
			if filter == "" || filter == StateCorrupt {
				result.Sessions = append(result.Sessions, item)
			}
			continue
		}
		if !exists {
			continue
		}
		cap, capExists, _ := store.readCapability(id)
		if capExists && cap.RootToken == rec.RootToken {
			trackedRoots[cap.RootName] = true
		}
		item := store.public(rec, cap, capExists)
		if filter == "" || item.State == filter {
			result.Sessions = append(result.Sessions, item)
		}
	}
	sort.Slice(result.Sessions, func(i, j int) bool { return result.Sessions[i].ID < result.Sessions[j].ID })
	result.UntrackedCount = store.countUntracked(trackedRoots)
	encoded, _ := json.Marshal(result)
	if len(encoded) > MaxPublicJSONBytes {
		return ListResult{SchemaVersion: SchemaVersion, Sessions: []PublicSession{}}, errors.New("session_output_limit")
	}
	return result, nil
}

func (store Store) Inspect(id string) (InspectResult, error) {
	if !ValidID(id) {
		return InspectResult{}, errors.New("invalid_session_id")
	}
	rec, exists, err := store.readRecord(id)
	if err != nil {
		return InspectResult{SchemaVersion: SchemaVersion, Session: corruptPublic(id)}, nil
	}
	if !exists {
		return InspectResult{}, errors.New("session_not_found")
	}
	cap, capExists, _ := store.readCapability(id)
	return InspectResult{SchemaVersion: SchemaVersion, Session: store.public(rec, cap, capExists)}, nil
}

func (store Store) Recover(id string) (RecoverResult, error) {
	result := RecoverResult{SchemaVersion: SchemaVersion, ID: id}
	if !ValidID(id) {
		return result, errors.New("invalid_session_id")
	}
	fence, err := store.openFence(id)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		result.Outcome = "busy"
		return result, errors.New("busy")
	}
	if err != nil {
		return result, errors.New("session_registry_unavailable")
	}
	defer closeLocked(fence)
	rec, exists, err := store.readRecord(id)
	if err != nil {
		result.Outcome, result.State = "not_recoverable", StateCorrupt
		return result, errors.New("not_recoverable")
	}
	if !exists {
		return result, errors.New("session_not_found")
	}
	result.State, result.Revision = rec.State, rec.Revision
	if rec.State == StateRemoved {
		result.Outcome = "removed"
		return result, nil
	}
	cap, capExists, capErr := store.readCapability(id)
	if capErr != nil || !capExists || !validBinding(rec, cap) {
		result.Outcome, result.State = "unproven", StateUnproven
		_ = store.restrict(rec, StateUnproven)
		return result, errors.New("unproven")
	}
	recovered, rootExists, recoverErr := launch.RecoverSession(store.SessionsDirectory, cap.RootName)
	if errors.Is(recoverErr, launch.ErrSessionStillActive) {
		result.Outcome, result.State = "active", StateActive
		return result, errors.New("active")
	}
	if recoverErr != nil {
		result.Outcome = "not_recoverable"
		return result, errors.New("not_recoverable")
	}
	if !rootExists {
		result.Outcome, result.State = "not_recoverable", StateUnknown
		_ = store.restrict(rec, StateUnknown)
		return result, errors.New("not_recoverable")
	}
	defer recovered.Preserve()
	// Ownership is held now; reread both sides before consulting the proof.
	fresh, freshExists, freshErr := store.readRecord(id)
	freshCap, freshCapExists, freshCapErr := store.readCapability(id)
	if freshErr != nil || freshCapErr != nil || !freshExists || !freshCapExists || fresh.Revision != rec.Revision || !validBinding(fresh, freshCap) || freshCap.RootName != filepath.Base(recovered.RootDir) {
		result.Outcome = "busy"
		return result, errors.New("busy")
	}
	var authBinding AuthRecoveryBinding
	if fresh.Target == "codex" || fresh.Target == "codex-auth" {
		if store.AuthRecovery == nil {
			result.Outcome = "not_recoverable"
			return result, errors.New("not_recoverable")
		}
		authStore, err := store.AuthRecovery()
		if err != nil {
			result.Outcome = "not_recoverable"
			return result, errors.New("not_recoverable")
		}
		bounded, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
		authBinding, exists, err = authStore.AcquireBySession(bounded, freshCap.RootName)
		cancel()
		if err != nil || !exists || authBinding == nil || authBinding.CleanupChallenge() != freshCap.Challenge {
			if authBinding != nil {
				_ = authBinding.Release()
			}
			result.Outcome = "not_recoverable"
			return result, errors.New("not_recoverable")
		}
		defer authBinding.Release()
	}
	challenge, decodeErr := hex.DecodeString(freshCap.Challenge)
	proven, proofErr := launch.VerifySessionCleanupProof(recovered.RootDir, challenge)
	if decodeErr != nil || proofErr != nil || !proven {
		result.Outcome, result.State = "unproven", StateUnproven
		_ = store.restrict(fresh, StateUnproven)
		return result, errors.New("unproven")
	}
	fresh.Revision++
	fresh.State, fresh.UpdatedAt = StateRemovable, formatTime(store.now())
	if err := store.writeRecord(fresh); err != nil {
		result.Outcome = "removal_failed"
		return result, errors.New("removal_failed")
	}
	if authBinding != nil && !authBinding.Prepared() {
		if err := authBinding.FinalizeRecovery(context.Background(), recovered.RootDir); err != nil {
			result.Outcome, result.State = "removal_failed", StateRemovable
			return result, errors.New("removal_failed")
		}
	}
	if err := recovered.Remove(); err != nil {
		result.Outcome, result.State, result.Revision = "removal_failed", StateRemovable, fresh.Revision
		return result, errors.New("removal_failed")
	}
	if authBinding != nil {
		if err := authBinding.DeleteMarkerAfterProjectionRemoval(context.Background()); err != nil {
			result.Outcome, result.State = "removal_failed", StateUnknown
			return result, errors.New("removal_failed")
		}
	}
	if err := store.removeCapability(id); err != nil {
		result.Outcome, result.State = "removal_failed", StateUnknown
		return result, errors.New("removal_failed")
	}
	fresh.Revision++
	fresh.State, fresh.UpdatedAt, fresh.RemovedAt = StateRemoved, formatTime(store.now()), formatTime(store.now())
	if err := store.writeRecord(fresh); err != nil {
		result.Outcome, result.State = "removal_failed", StateUnknown
		return result, errors.New("removal_failed")
	}
	result.Outcome, result.State, result.Revision = "removed", StateRemoved, fresh.Revision
	return result, nil
}

func (store Store) restrict(rec record, state State) error {
	rec.Revision++
	rec.State, rec.UpdatedAt = state, formatTime(store.now())
	return store.writeRecord(rec)
}

func (store Store) public(rec record, cap capability, capExists bool) PublicSession {
	state := rec.State
	if state != StateRemoved && (!capExists || !validBinding(rec, cap)) {
		state = StateUnknown
	}
	if state != StateRemoved && capExists {
		if _, err := os.Lstat(filepath.Join(store.SessionsDirectory, cap.RootName)); os.IsNotExist(err) {
			state = StateUnknown
		}
	}
	observation := "durable"
	if state == StateActive || state == StateSettling {
		observation = "unverified"
	}
	action := "none"
	allowed := false
	if state == StateRetryable || state == StateUnproven || state == StateActive || state == StateSettling {
		action = "verify-proof"
		allowed = capExists && validBinding(rec, cap)
	}
	if state == StateRemovable {
		action, allowed = "remove", true
	}
	return PublicSession{ID: rec.ID, State: state, Observation: observation, Target: rec.Target, CreatedAt: rec.CreatedAt, UpdatedAt: rec.UpdatedAt, Revision: rec.Revision, Recovery: Recovery{Allowed: allowed, Action: action}}
}

func corruptPublic(id string) PublicSession {
	return PublicSession{ID: id, State: StateCorrupt, Observation: "durable", Recovery: Recovery{Allowed: false, Action: "none"}}
}

func (store Store) countUntracked(tracked map[string]bool) int {
	entries, err := os.ReadDir(store.SessionsDirectory)
	if err != nil {
		return 0
	}
	count := 0
	for index, entry := range entries {
		if index >= MaxScannedEntries {
			break
		}
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "session-") && !tracked[entry.Name()] {
			count++
		}
	}
	return count
}

func (store Store) readRecord(id string) (record, bool, error) {
	var value record
	if err := validateDirectoryIfPresent(store.recordsDirectory()); err != nil {
		return value, false, err
	}
	exists, err := readStrict(store.recordPath(id), &value)
	if err != nil || !exists {
		return value, exists, err
	}
	if value.Version != SchemaVersion || value.ID != id || value.Revision == 0 || !validState(value.State) || !validTarget(value.Target) || !validTimestamp(value.CreatedAt) || !validTimestamp(value.UpdatedAt) || len(value.RootToken) != 64 || value.Generation == 0 {
		return value, true, errors.New("invalid record")
	}
	return value, true, nil
}

func (store Store) readCapability(id string) (capability, bool, error) {
	var value capability
	if err := validateDirectoryIfPresent(store.capabilitiesDirectory()); err != nil {
		return value, false, err
	}
	exists, err := readStrict(store.capabilityPath(id), &value)
	if err != nil || !exists {
		return value, exists, err
	}
	challenge, challengeErr := hex.DecodeString(value.Challenge)
	if value.Version != SchemaVersion || value.ID != id || !strings.HasPrefix(value.RootName, "session-") || filepath.Base(value.RootName) != value.RootName || len(value.RootToken) != 64 || value.Generation == 0 || challengeErr != nil || len(challenge) != launch.RecoveryProofChallengeSize {
		return value, true, errors.New("invalid capability")
	}
	return value, true, nil
}

func readStrict(path string, value any) (bool, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, syscall.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return false, errors.New("invalid record")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > MaxRecordBytes {
		return false, errors.New("invalid record")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) || native.Nlink != 1 {
		return false, errors.New("invalid record")
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxRecordBytes+1))
	if err != nil || len(data) > MaxRecordBytes {
		return false, errors.New("invalid record")
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return false, errors.New("invalid record")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return false, errors.New("invalid record")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return false, errors.New("invalid record")
	}
	return true, nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return errors.New("invalid object")
	}
	seen := map[string]bool{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return errors.New("duplicate object key")
		}
		seen[key] = true
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return err
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return errors.New("invalid object")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

func (store Store) writeRecord(value record) error {
	return store.writeJSON(store.recordsDirectory(), store.recordPath(value.ID), value)
}
func (store Store) writeCapability(value capability) error {
	return store.writeJSON(store.capabilitiesDirectory(), store.capabilityPath(value.ID), value)
}

func (store Store) writeJSON(directory, path string, value any) error {
	if err := store.ensureStorage(); err != nil {
		return errors.New("session_registry_unavailable")
	}
	if err := secureDirectory(directory); err != nil {
		return errors.New("session_registry_unavailable")
	}
	data, err := json.Marshal(value)
	if err != nil || len(data) > MaxRecordBytes {
		return errors.New("session_registry_limit")
	}
	data = append(data, '\n')
	temporary, err := os.CreateTemp(directory, ".session-write-*")
	if err != nil {
		return errors.New("session_registry_unavailable")
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return errors.New("session_registry_unavailable")
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return errors.New("session_registry_unavailable")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errors.New("session_registry_unavailable")
	}
	if err := temporary.Close(); err != nil {
		return errors.New("session_registry_unavailable")
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return errors.New("session_registry_unavailable")
	}
	if err := syncDirectory(directory); err != nil {
		return errors.New("session_registry_unavailable")
	}
	return nil
}

func (store Store) removeCapability(id string) error {
	if err := os.Remove(store.capabilityPath(id)); err != nil && !os.IsNotExist(err) {
		return errors.New("session_registry_unavailable")
	}
	if _, err := os.Stat(store.capabilitiesDirectory()); err == nil {
		return syncDirectory(store.capabilitiesDirectory())
	}
	return nil
}

func (store Store) openFence(id string) (*os.File, error) {
	if err := store.ensureStorage(); err != nil {
		return nil, err
	}
	return openLocked(filepath.Join(store.locksDirectory(), id+".lock"), true)
}

func openLocked(path string, nonblocking bool) (*os.File, error) {
	descriptor, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("lock unavailable")
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		file.Close()
		return nil, errors.New("invalid lock")
	}
	if native, ok := info.Sys().(*syscall.Stat_t); !ok || native.Uid != uint32(os.Geteuid()) || native.Nlink != 1 {
		file.Close()
		return nil, errors.New("invalid lock")
	}
	operation := syscall.LOCK_EX
	if nonblocking {
		operation |= syscall.LOCK_NB
	}
	if err := syscall.Flock(descriptor, operation); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func closeLocked(file *os.File) {
	if file != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}
}

func secureDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid private directory")
	}
	if native, ok := info.Sys().(*syscall.Stat_t); !ok || native.Uid != uint32(os.Geteuid()) {
		return errors.New("invalid private directory")
	}
	return os.Chmod(path, 0o700)
}

func validateDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("invalid private directory")
	}
	if native, ok := info.Sys().(*syscall.Stat_t); !ok || native.Uid != uint32(os.Geteuid()) {
		return errors.New("invalid private directory")
	}
	return nil
}

func validateDirectoryIfPresent(path string) error {
	err := validateDirectory(path)
	if os.IsNotExist(err) {
		return nil
	}
	if _, statErr := os.Lstat(path); os.IsNotExist(statErr) {
		return nil
	}
	return err
}

func (store Store) ensureStorage() error {
	for _, directory := range []string{store.baseDirectory(), store.recordsDirectory(), store.capabilitiesDirectory(), store.locksDirectory()} {
		if err := secureDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func (store Store) pruneRemoved() error {
	entries, err := os.ReadDir(store.recordsDirectory())
	if err != nil {
		return err
	}
	if len(entries) > MaxScannedEntries {
		entries = entries[:MaxScannedEntries]
	}
	cutoff := store.now().Add(-RemovedRetention)
	for _, entry := range entries {
		id := strings.TrimSuffix(entry.Name(), ".json")
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || !ValidID(id) {
			continue
		}
		rec, exists, err := store.readRecord(id)
		if err != nil || !exists || rec.State != StateRemoved || rec.RemovedAt == "" {
			continue
		}
		removedAt, err := time.Parse(time.RFC3339, rec.RemovedAt)
		if err != nil || removedAt.After(cutoff) {
			continue
		}
		fence, err := store.openFence(id)
		if err != nil {
			continue
		}
		fresh, freshExists, freshErr := store.readRecord(id)
		if freshErr == nil && freshExists && fresh.Revision == rec.Revision && fresh.State == StateRemoved {
			if err := os.Remove(store.recordPath(id)); err == nil {
				_ = syncDirectory(store.recordsDirectory())
			}
		}
		closeLocked(fence)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
func (store Store) baseDirectory() string {
	return launch.SessionOperationsDirectory(store.SessionsDirectory)
}
func (store Store) recordsDirectory() string { return filepath.Join(store.baseDirectory(), "records") }
func (store Store) capabilitiesDirectory() string {
	return filepath.Join(store.baseDirectory(), "capabilities")
}
func (store Store) locksDirectory() string { return filepath.Join(store.baseDirectory(), "locks") }
func (store Store) recordPath(id string) string {
	return filepath.Join(store.recordsDirectory(), id+".json")
}
func (store Store) capabilityPath(id string) string {
	return filepath.Join(store.capabilitiesDirectory(), id+".json")
}
func (store Store) now() time.Time {
	if store.Now != nil {
		return store.Now().UTC()
	}
	return time.Now().UTC()
}
func formatTime(value time.Time) string {
	return value.UTC().Truncate(time.Second).Format(time.RFC3339)
}
func validTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339, value)
	return err == nil && value == formatTime(parsed)
}
func validBinding(rec record, cap capability) bool {
	return rec.ID == cap.ID && rec.RootToken == cap.RootToken && rec.Generation == cap.Generation
}

func ValidID(id string) bool {
	if len(id) != 30 || !strings.HasPrefix(id, "ses_") {
		return false
	}
	for _, character := range id[4:] {
		if !(character >= 'a' && character <= 'z' || character >= '2' && character <= '7') {
			return false
		}
	}
	return true
}

func ParseState(value string) (State, bool) { state := State(value); return state, validState(state) }
func validState(state State) bool {
	switch state {
	case StateActive, StateSettling, StateRetryable, StateUnproven, StateRemovable, StateRemoved, StateUnknown, StateCorrupt:
		return true
	}
	return false
}
func validTarget(target string) bool {
	switch target {
	case "shell", "devin", "codex", "codex-auth", "command":
		return true
	}
	return false
}

func Diagnostic(err error) string {
	if err == nil {
		return ""
	}
	allowed := []string{"active", "busy", "still_retryable", "unproven", "not_recoverable", "removal_failed", "session_registry_unavailable", "session_registry_limit", "session_output_limit", "session_not_found", "invalid_session_id"}
	for _, token := range allowed {
		if errors.Is(err, errors.New(token)) || err.Error() == token {
			return token
		}
	}
	return "session_operation_failed"
}

func (result RecoverResult) String() string {
	return fmt.Sprintf("Session %s: %s", result.ID, result.Outcome)
}
