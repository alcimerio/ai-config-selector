package codexauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

type bindingPreparationStage uint8

const (
	bindingSessionCreation bindingPreparationStage = iota
	bindingMarkerCreation
	bindingRecoveryProtection
)

// prepareBinding centralizes the create-marker-protect order shared by login
// and status. No credential bytes or contained process exist before it returns.
func (registry *Registry) prepareBinding(
	ctx context.Context,
	name CredentialRef,
) (*session.Session, string, bindingPreparationStage, error) {
	proofChallenge := make([]byte, launch.RecoveryProofChallengeSize)
	if _, err := rand.Read(proofChallenge); err != nil {
		return nil, "", bindingSessionCreation, err
	}
	encodedChallenge := hex.EncodeToString(proofChallenge)
	created, err := session.Create(registry.sessionsDirectory, registry.workingDirectory, nil)
	if err != nil {
		return nil, "", bindingSessionCreation, err
	}
	marker := quarantineMarker{
		Version: recordVersion, Name: name, SessionID: filepath.Base(created.RootDirectory()),
		Phase: quarantinePrepared, ProofChallenge: encodedChallenge,
	}
	if err := registry.quarantine.Create(ctx, marker); err != nil {
		if errors.Is(err, ErrBindingQuarantined) && registry.preservePublishedBinding(ctx, created, marker) {
			return nil, "", bindingMarkerCreation, ErrBindingQuarantined
		}
		_ = created.Remove()
		return nil, "", bindingMarkerCreation, err
	}
	if err := created.ProtectForRecovery(); err != nil {
		_ = registry.quarantine.MarkRecoverable(ctx, name)
		if cleanupErr := registry.removeCreatedBinding(ctx, created, name); cleanupErr != nil {
			return nil, "", bindingRecoveryProtection, ErrBindingQuarantined
		}
		return nil, "", bindingRecoveryProtection, err
	}
	return created, encodedChallenge, bindingRecoveryProtection, nil
}

// preservePublishedBinding repairs the live state after marker publication was
// visible but its directory sync could not be confirmed. Since no process or
// credential exists yet, the Session can become immediately recoverable.
func (registry *Registry) preservePublishedBinding(
	ctx context.Context,
	created *session.Session,
	want quarantineMarker,
) bool {
	marker, exists, err := registry.quarantine.Inspect(ctx, want.Name)
	if err != nil {
		_ = created.Remove()
		return true
	}
	if !exists {
		return false
	}
	if marker != want {
		_ = created.Remove()
		return true
	}
	if err := created.ProtectForRecovery(); err != nil {
		_ = registry.quarantine.Delete(ctx, want.Name)
		_ = created.Remove()
		return false
	}
	if err := registry.quarantine.MarkRecoverable(ctx, want.Name); err != nil {
		return registry.removeCreatedBinding(ctx, created, want.Name) != nil
	}
	if err := created.PreserveForRecovery(); err != nil {
		return true
	}
	return true
}

// settleBinding either proves the process reference is gone and enables
// recovery, or transfers the still-pending lifecycle to durable quarantine.
func (registry *Registry) settleBinding(
	ctx context.Context,
	created *session.Session,
	name CredentialRef,
	cleanupProven bool,
	cleanupProcess launch.Process,
) error {
	if !cleanupProven {
		registry.transferPendingBinding(created, name, cleanupProcess)
		return ErrBindingQuarantined
	}
	if err := registry.quarantine.MarkRecoverable(ctx, name); err != nil {
		_ = created.PreserveForRecovery()
		return ErrBindingQuarantined
	}
	return nil
}
