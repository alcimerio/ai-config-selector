package codexauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
)

const maximumQuarantineMarkerSize = 16 * 1024

var sessionIDPattern = regexp.MustCompile(`^session-[A-Za-z0-9._-]{1,128}$`)
var proofChallengePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type quarantinePhase string

const (
	quarantineCleanupPending quarantinePhase = "cleanup_pending"
	quarantineRecoverable    quarantinePhase = "recoverable"
)

type quarantineMarker struct {
	Version        int             `json:"version"`
	Name           CredentialRef   `json:"name"`
	SessionID      string          `json:"sessionId"`
	Phase          quarantinePhase `json:"phase"`
	ProofChallenge string          `json:"proofChallenge"`
}

type bindingQuarantine interface {
	Inspect(context.Context, CredentialRef) (quarantineMarker, bool, error)
	Create(context.Context, quarantineMarker) error
	MarkRecoverable(context.Context, CredentialRef) error
	Delete(context.Context, CredentialRef) error
}

type noBindingQuarantine struct{}

func (noBindingQuarantine) Inspect(context.Context, CredentialRef) (quarantineMarker, bool, error) {
	return quarantineMarker{}, false, nil
}

func (noBindingQuarantine) Create(context.Context, quarantineMarker) error       { return nil }
func (noBindingQuarantine) MarkRecoverable(context.Context, CredentialRef) error { return nil }
func (noBindingQuarantine) Delete(context.Context, CredentialRef) error          { return nil }

type fileBindingQuarantine struct{ directory string }

func newFileBindingQuarantine(directory string) *fileBindingQuarantine {
	return &fileBindingQuarantine{directory: filepath.Clean(directory)}
}

func (store *fileBindingQuarantine) Inspect(
	ctx context.Context,
	name CredentialRef,
) (quarantineMarker, bool, error) {
	if err := ctx.Err(); err != nil {
		return quarantineMarker{}, false, err
	}
	contents, err := readPrivateRegularFile(store.path(name), maximumQuarantineMarkerSize)
	if os.IsNotExist(err) {
		return quarantineMarker{}, false, nil
	}
	if err != nil {
		return quarantineMarker{}, false, ErrProviderUnavailable
	}
	defer clearBytes(contents)
	marker, err := decodeQuarantineMarker(contents)
	if err != nil || marker.Name != name {
		return quarantineMarker{}, false, ErrProviderUnavailable
	}
	return marker, true, nil
}

func (store *fileBindingQuarantine) Create(ctx context.Context, marker quarantineMarker) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateQuarantineMarker(marker); err != nil {
		return ErrProviderUnavailable
	}
	if err := store.secureDirectory(); err != nil {
		return ErrProviderUnavailable
	}
	contents, err := json.Marshal(marker)
	if err != nil {
		return ErrProviderUnavailable
	}
	defer clearBytes(contents)
	temporary, err := os.CreateTemp(store.directory, ".marker-*")
	if err != nil {
		return ErrProviderUnavailable
	}
	temporaryPath := temporary.Name()
	cleanup := func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}
	defer cleanup()
	if err := temporary.Chmod(0o600); err != nil {
		return ErrProviderUnavailable
	}
	if _, err := temporary.Write(contents); err != nil {
		return ErrProviderUnavailable
	}
	if err := temporary.Sync(); err != nil {
		return ErrProviderUnavailable
	}
	if err := temporary.Close(); err != nil {
		return ErrProviderUnavailable
	}
	if err := os.Link(temporaryPath, store.path(marker.Name)); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrIdentityBusy
		}
		return ErrProviderUnavailable
	}
	if err := os.Remove(temporaryPath); err != nil {
		_ = os.Remove(store.path(marker.Name))
		return ErrProviderUnavailable
	}
	temporaryPath = ""
	if err := syncDirectory(store.directory); err != nil {
		return ErrBindingQuarantined
	}
	return nil
}

func (store *fileBindingQuarantine) MarkRecoverable(ctx context.Context, name CredentialRef) error {
	marker, exists, err := store.Inspect(ctx, name)
	if err != nil {
		return err
	}
	if !exists {
		return ErrBindingQuarantined
	}
	if marker.Phase == quarantineRecoverable {
		return nil
	}
	marker.Phase = quarantineRecoverable
	contents, err := json.Marshal(marker)
	if err != nil {
		return ErrProviderUnavailable
	}
	defer clearBytes(contents)
	temporary, err := os.CreateTemp(store.directory, ".marker-*")
	if err != nil {
		return ErrProviderUnavailable
	}
	temporaryPath := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(temporaryPath)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return ErrProviderUnavailable
	}
	if _, err := temporary.Write(contents); err != nil {
		return ErrProviderUnavailable
	}
	if err := temporary.Sync(); err != nil {
		return ErrProviderUnavailable
	}
	if err := temporary.Close(); err != nil {
		return ErrProviderUnavailable
	}
	if err := os.Rename(temporaryPath, store.path(name)); err != nil {
		return ErrProviderUnavailable
	}
	temporaryPath = ""
	if err := syncDirectory(store.directory); err != nil {
		return ErrBindingQuarantined
	}
	return nil
}

func (store *fileBindingQuarantine) Delete(ctx context.Context, name CredentialRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Remove(store.path(name)); err != nil && !os.IsNotExist(err) {
		return ErrProviderUnavailable
	}
	if err := syncDirectory(store.directory); err != nil && !os.IsNotExist(err) {
		return ErrProviderUnavailable
	}
	return nil
}

func (store *fileBindingQuarantine) secureDirectory() error {
	info, err := os.Lstat(store.directory)
	if os.IsNotExist(err) {
		if err := os.MkdirAll(store.directory, 0o700); err != nil {
			return err
		}
		info, err = os.Lstat(store.directory)
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid quarantine directory")
	}
	if native, ok := info.Sys().(*syscall.Stat_t); !ok || native.Uid != uint32(os.Geteuid()) {
		return errors.New("invalid quarantine directory")
	}
	if err := os.Chmod(store.directory, 0o700); err != nil {
		return err
	}
	return nil
}

func (store *fileBindingQuarantine) path(name CredentialRef) string {
	return filepath.Join(store.directory, string(name)+".json")
}

func decodeQuarantineMarker(contents []byte) (quarantineMarker, error) {
	if err := rejectDuplicateJSONKeys(contents); err != nil {
		return quarantineMarker{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var marker quarantineMarker
	if err := decoder.Decode(&marker); err != nil {
		return quarantineMarker{}, err
	}
	var additional any
	if err := decoder.Decode(&additional); !errors.Is(err, io.EOF) {
		return quarantineMarker{}, errors.New("invalid quarantine marker")
	}
	if err := validateQuarantineMarker(marker); err != nil {
		return quarantineMarker{}, err
	}
	return marker, nil
}

func validateQuarantineMarker(marker quarantineMarker) error {
	if marker.Version != recordVersion {
		return errors.New("invalid quarantine marker version")
	}
	if _, err := ParseCredentialRef(string(marker.Name)); err != nil {
		return err
	}
	if !sessionIDPattern.MatchString(marker.SessionID) {
		return fmt.Errorf("invalid quarantine Session identifier")
	}
	if marker.Phase != quarantineCleanupPending && marker.Phase != quarantineRecoverable {
		return errors.New("invalid quarantine phase")
	}
	if !proofChallengePattern.MatchString(marker.ProofChallenge) {
		return errors.New("invalid quarantine cleanup proof challenge")
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
