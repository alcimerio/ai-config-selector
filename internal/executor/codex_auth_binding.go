package executor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

// Status acquires one durable identity before executable preparation, projects
// it into a private Session, and delegates every record decision to the opaque
// lower binding.
func (registry *CodexAuthService) Status(ctx context.Context, value string) (IdentityStatus, error) {
	if registry.status == nil || registry.sessionsDirectory == "" {
		return IdentityStatus{}, ErrProviderUnavailable
	}
	binding, metadata, err := registry.resources.AcquireStatus(ctx, value)
	if err != nil {
		return IdentityStatus{}, err
	}
	defer binding.Release()
	result := IdentityStatus{Metadata: metadata}
	preparation, err := registry.status.Prepare(ctx)
	if err != nil {
		return result, sanitizeStatusError(err)
	}
	defer preparation.Close()
	created, challenge, err := registry.createStatusBinding(ctx, binding, metadata.Name)
	if err != nil {
		if errors.Is(err, ErrBindingQuarantined) {
			result.Disposition = QuarantinedUncertain
		}
		return result, err
	}
	remove := func() error {
		if err := created.Remove(); err != nil {
			_ = created.PreserveForRecovery()
			return ErrBindingQuarantined
		}
		if err := binding.DeleteMarkerAfterProjectionRemoval(ctx); err != nil {
			return ErrBindingQuarantined
		}
		return nil
	}
	if err := binding.Project(created.HomeDirectory()); err != nil {
		_ = binding.MarkRecoverable(ctx)
		if cleanupErr := remove(); cleanupErr != nil {
			result.Disposition = QuarantinedUncertain
			return result, ErrBindingQuarantined
		}
		result.Disposition = DiscardedProjection
		return result, ErrProjectedAuthInvalid
	}
	run := preparation.Run(ctx, created, metadata.Workspace, challenge, binding)
	run.err = sanitizeStatusError(run.err)
	if run.err == nil {
		if err := binding.MarkRefreshAllowed(ctx); err != nil {
			if !run.cleanupProven {
				registry.transferResourcePendingBinding(created, binding, challenge, run.cleanupProcess)
			} else {
				_ = created.PreserveForRecovery()
			}
			result.Disposition = QuarantinedUncertain
			return result, ErrBindingQuarantined
		}
	}
	if !run.cleanupProven {
		registry.transferResourcePendingBinding(created, binding, challenge, run.cleanupProcess)
		result.Disposition = QuarantinedUncertain
		return result, ErrBindingQuarantined
	}
	if err := binding.MarkRecoverable(ctx); err != nil {
		_ = created.PreserveForRecovery()
		result.Disposition = QuarantinedUncertain
		return result, ErrBindingQuarantined
	}
	if run.err != nil {
		if err := remove(); err != nil {
			result.Disposition = QuarantinedUncertain
			return result, ErrBindingQuarantined
		}
		result.Disposition = DiscardedProjection
		return result, run.err
	}
	disposition, err := binding.FinalizeStatus(ctx, created.RootDirectory())
	result.Disposition = BindingDisposition(disposition)
	if err != nil {
		if errors.Is(err, codexauthresource.ErrProjectedAuthInvalid) || errors.Is(err, ErrProjectedAuthInvalid) {
			if cleanupErr := remove(); cleanupErr != nil {
				result.Disposition = QuarantinedUncertain
				return result, ErrBindingQuarantined
			}
			result.Disposition = DiscardedProjection
			return result, ErrProjectedAuthInvalid
		}
		_ = created.PreserveForRecovery()
		result.Disposition = QuarantinedUncertain
		return result, ErrBindingQuarantined
	}
	if err := remove(); err != nil {
		result.Disposition = QuarantinedUncertain
		return result, ErrBindingQuarantined
	}
	return result, nil
}

func (registry *CodexAuthService) createStatusBinding(ctx context.Context, binding loginResourceBinding, name CredentialRef) (*session.Session, string, error) {
	return registry.createResourceBinding(ctx, binding, name, nil, ErrStatusFailed)
}

func (registry *CodexAuthService) createResourceBinding(ctx context.Context, binding loginResourceBinding, name CredentialRef, materializer session.Materializer, operationFailure error) (*session.Session, string, error) {
	challenge := make([]byte, launch.RecoveryProofChallengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return nil, "", ErrStatusFailed
	}
	encoded := hex.EncodeToString(challenge)
	created, err := session.Create(registry.sessionsDirectory, registry.workingDirectory, materializer)
	if err != nil {
		return nil, "", operationFailure
	}
	remove := func() error {
		if err := created.Remove(); err != nil {
			_ = created.PreserveForRecovery()
			return ErrBindingQuarantined
		}
		if err := binding.DeleteMarkerAfterProjectionRemoval(ctx); err != nil {
			return ErrBindingQuarantined
		}
		return nil
	}
	if err := binding.PublishPrepared(ctx, created.RootDirectory(), encoded); err != nil {
		published, inspectErr := binding.Published(ctx, filepath.Base(created.RootDirectory()), encoded)
		if inspectErr != nil {
			if protectErr := created.ProtectForRecovery(); protectErr == nil {
				_ = created.PreserveForRecovery()
			}
			return nil, "", ErrBindingQuarantined
		}
		if published {
			if protectErr := created.ProtectForRecovery(); protectErr != nil {
				if cleanupErr := remove(); cleanupErr != nil {
					return nil, "", cleanupErr
				}
				return nil, "", fmt.Errorf("record Codex authentication binding %q: %w", name, err)
			}
			_ = binding.MarkRecoverable(ctx)
			_ = created.PreserveForRecovery()
			return nil, "", ErrBindingQuarantined
		}
		if removeErr := created.Remove(); removeErr != nil {
			return nil, "", ErrBindingQuarantined
		}
		return nil, "", fmt.Errorf("record Codex authentication binding %q: %w", name, err)
	}
	if err := created.ProtectForRecovery(); err != nil {
		_ = binding.MarkRecoverable(ctx)
		if cleanupErr := remove(); cleanupErr != nil {
			return nil, "", cleanupErr
		}
		return nil, "", operationFailure
	}
	return created, encoded, nil
}

// Recover finalizes one exact durable marker generation. Session ownership and
// supervisor proof verification remain above the non-executing resource layer.
func (registry *CodexAuthService) Recover(ctx context.Context, value string) (BindingDisposition, error) {
	binding, err := registry.resources.AcquireRecovery(ctx, value)
	if err != nil {
		if _, changed := err.(interface{ RecoveryGenerationChanged() }); changed {
			return QuarantinedUncertain, err
		}
		return "", err
	}
	if binding == nil {
		return DiscardedProjection, nil
	}
	defer binding.Release()
	recoverSession := launch.RecoverSession
	if binding.Prepared() {
		recoverSession = launch.RecoverPreparedSession
	}
	recovered, exists, err := recoverSession(registry.sessionsDirectory, binding.SessionID())
	if errors.Is(err, launch.ErrSessionStillActive) {
		return QuarantinedUncertain, fmt.Errorf("%w: %q", ErrIdentityBusy, value)
	}
	if err != nil {
		return QuarantinedUncertain, ErrBindingQuarantined
	}
	if !exists {
		if err := binding.DeleteMarkerAfterProjectionRemoval(ctx); err != nil {
			return QuarantinedUncertain, ErrBindingQuarantined
		}
		return DiscardedProjection, nil
	}
	defer recovered.Preserve()
	if binding.Prepared() {
		if err := recovered.Remove(); err != nil {
			return QuarantinedUncertain, ErrBindingQuarantined
		}
		if err := binding.DeleteMarkerAfterProjectionRemoval(ctx); err != nil {
			return QuarantinedUncertain, ErrBindingQuarantined
		}
		return DiscardedProjection, nil
	}
	if binding.CleanupPending() {
		challenge, decodeErr := hex.DecodeString(binding.CleanupChallenge())
		proven, proofErr := registry.verifyCleanup(recovered.RootDir, challenge)
		if decodeErr != nil || proofErr != nil || !proven {
			return QuarantinedUncertain, fmt.Errorf("%w: %q", ErrIdentityBusy, value)
		}
	}
	disposition, err := binding.FinalizeRecovery(ctx, recovered.RootDir)
	if err != nil {
		return QuarantinedUncertain, ErrBindingQuarantined
	}
	if err := recovered.Remove(); err != nil {
		return QuarantinedUncertain, ErrBindingQuarantined
	}
	if err := binding.DeleteMarkerAfterProjectionRemoval(ctx); err != nil {
		return QuarantinedUncertain, ErrBindingQuarantined
	}
	return BindingDisposition(disposition), nil
}
