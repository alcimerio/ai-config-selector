package codexauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"

	"golang.org/x/sys/unix"
)

const maximumQuarantineMarkerSize = 16 * 1024

var sessionIDPattern = regexp.MustCompile(`^session-[A-Za-z0-9._-]{1,128}$`)
var proofChallengePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type quarantinePhase string

const (
	quarantinePrepared       quarantinePhase = "prepared"
	quarantineCleanupPending quarantinePhase = "cleanup_pending"
	quarantineRecoverable    quarantinePhase = "recoverable"
)

type quarantineMarker struct {
	Version        int             `json:"version"`
	Name           CredentialRef   `json:"name"`
	SessionID      string          `json:"sessionId"`
	Phase          quarantinePhase `json:"phase"`
	ProofChallenge string          `json:"proofChallenge"`
	RefreshAllowed bool            `json:"refreshAllowed,omitempty"`
}

type bindingQuarantine interface {
	Inspect(context.Context, CredentialRef) (quarantineMarker, bool, error)
	Create(context.Context, quarantineMarker) error
	MarkCleanupPending(context.Context, CredentialRef) error
	MarkRefreshAllowed(context.Context, CredentialRef) error
	MarkRecoverable(context.Context, CredentialRef) error
	Delete(context.Context, CredentialRef) error
}

type noBindingQuarantine struct{}

func (noBindingQuarantine) Inspect(context.Context, CredentialRef) (quarantineMarker, bool, error) {
	return quarantineMarker{}, false, nil
}

func (noBindingQuarantine) Create(context.Context, quarantineMarker) error { return nil }
func (noBindingQuarantine) MarkCleanupPending(context.Context, CredentialRef) error {
	return nil
}
func (noBindingQuarantine) MarkRefreshAllowed(context.Context, CredentialRef) error {
	return nil
}
func (noBindingQuarantine) MarkRecoverable(context.Context, CredentialRef) error { return nil }
func (noBindingQuarantine) Delete(context.Context, CredentialRef) error          { return nil }

type fileBindingQuarantine struct {
	directory *privateDirectory
	initErr   error
}

func newFileBindingQuarantine(directory string) *fileBindingQuarantine {
	pinned, err := pinPrivateDirectory(directory)
	return &fileBindingQuarantine{directory: pinned, initErr: err}
}

func (store *fileBindingQuarantine) Inspect(
	ctx context.Context,
	name CredentialRef,
) (quarantineMarker, bool, error) {
	if err := ctx.Err(); err != nil {
		return quarantineMarker{}, false, err
	}
	if store == nil || store.initErr != nil {
		return quarantineMarker{}, false, ErrProviderUnavailable
	}
	file, err := store.directory.open(store.name(name), unix.O_RDONLY, 0)
	if os.IsNotExist(err) {
		return quarantineMarker{}, false, nil
	}
	if err != nil {
		return quarantineMarker{}, false, ErrProviderUnavailable
	}
	contents, err := readPrivateRegularDescriptor(file, maximumQuarantineMarkerSize)
	_ = file.Close()
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
	if store == nil || store.initErr != nil {
		return ErrProviderUnavailable
	}
	contents, err := json.Marshal(marker)
	if err != nil {
		return ErrProviderUnavailable
	}
	defer clearBytes(contents)
	temporary, temporaryName, err := store.directory.createTemporary(".marker-")
	if err != nil {
		return ErrProviderUnavailable
	}
	cleanup := func() {
		_ = temporary.Close()
		if temporaryName != "" {
			_ = store.directory.unlink(temporaryName)
		}
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
	if err := store.directory.renameNoReplace(temporaryName, store.name(marker.Name)); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return ErrIdentityBusy
		}
		return ErrProviderUnavailable
	}
	temporaryName = ""
	if err := store.directory.sync(); err != nil {
		return ErrBindingQuarantined
	}
	return nil
}

func (store *fileBindingQuarantine) MarkRecoverable(ctx context.Context, name CredentialRef) error {
	return store.transition(ctx, name, quarantineRecoverable)
}

func (store *fileBindingQuarantine) MarkCleanupPending(ctx context.Context, name CredentialRef) error {
	return store.transition(ctx, name, quarantineCleanupPending)
}

func (store *fileBindingQuarantine) MarkRefreshAllowed(ctx context.Context, name CredentialRef) error {
	return store.update(ctx, name, func(marker *quarantineMarker) (bool, error) {
		if marker.Phase == quarantinePrepared {
			return false, ErrBindingQuarantined
		}
		if marker.RefreshAllowed {
			return false, nil
		}
		marker.RefreshAllowed = true
		return true, nil
	})
}

func (store *fileBindingQuarantine) transition(
	ctx context.Context,
	name CredentialRef,
	phase quarantinePhase,
) error {
	return store.update(ctx, name, func(marker *quarantineMarker) (bool, error) {
		if marker.Phase == phase {
			return false, nil
		}
		if phase == quarantineCleanupPending && marker.Phase != quarantinePrepared {
			return false, ErrBindingQuarantined
		}
		marker.Phase = phase
		return true, nil
	})
}

func (store *fileBindingQuarantine) update(
	ctx context.Context,
	name CredentialRef,
	mutate func(*quarantineMarker) (bool, error),
) error {
	marker, exists, err := store.Inspect(ctx, name)
	if err != nil {
		return err
	}
	if !exists {
		return ErrBindingQuarantined
	}
	changed, err := mutate(&marker)
	if err != nil || !changed {
		return err
	}
	contents, err := json.Marshal(marker)
	if err != nil {
		return ErrProviderUnavailable
	}
	defer clearBytes(contents)
	temporary, temporaryName, err := store.directory.createTemporary(".marker-")
	if err != nil {
		return ErrProviderUnavailable
	}
	defer func() {
		_ = temporary.Close()
		if temporaryName != "" {
			_ = store.directory.unlink(temporaryName)
		}
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
	if err := store.directory.rename(temporaryName, store.name(name)); err != nil {
		return ErrProviderUnavailable
	}
	temporaryName = ""
	if err := store.directory.sync(); err != nil {
		return ErrBindingQuarantined
	}
	return nil
}

func (store *fileBindingQuarantine) Delete(ctx context.Context, name CredentialRef) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store == nil || store.initErr != nil {
		return ErrProviderUnavailable
	}
	if err := store.directory.unlink(store.name(name)); err != nil && !errors.Is(err, unix.ENOENT) {
		return ErrProviderUnavailable
	}
	if err := store.directory.sync(); err != nil {
		return ErrProviderUnavailable
	}
	return nil
}

func (store *fileBindingQuarantine) name(name CredentialRef) string { return string(name) + ".json" }

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
	if marker.Phase != quarantinePrepared && marker.Phase != quarantineCleanupPending && marker.Phase != quarantineRecoverable {
		return errors.New("invalid quarantine phase")
	}
	if !proofChallengePattern.MatchString(marker.ProofChallenge) {
		return errors.New("invalid quarantine cleanup proof challenge")
	}
	return nil
}
