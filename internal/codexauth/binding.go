package codexauth

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

// Status acquires one durable identity before Session creation, projects it
// into a private synthetic home, runs contained Codex status, and finalizes the
// projection through one typed disposition.
func (registry *Registry) Status(ctx context.Context, value string) (IdentityStatus, error) {
	if registry.status == nil || registry.sessionsDirectory == "" {
		return IdentityStatus{}, ErrProviderUnavailable
	}
	name, err := ParseCredentialRef(value)
	if err != nil {
		return IdentityStatus{}, err
	}
	locked, err := registry.tryLock(ctx, name, false)
	if err != nil {
		return IdentityStatus{}, err
	}

	record, exists, err := registry.provider.Load(ctx, name)
	if err != nil {
		_ = locked.Release()
		return IdentityStatus{}, fmt.Errorf("load Codex authentication identity %q: %w", name, err)
	}
	if !exists {
		_ = locked.Release()
		return IdentityStatus{}, fmt.Errorf("%w: %q", ErrIdentityNotFound, name)
	}
	defer clearBytes(record.Auth)
	result := IdentityStatus{Metadata: record.Metadata}

	if err := registry.status.Check(ctx); err != nil {
		_ = locked.Release()
		return result, sanitizeStatusError(err)
	}
	created, proofChallenge, stage, err := registry.prepareBinding(ctx, name)
	if err != nil {
		_ = locked.Release()
		if errors.Is(err, ErrBindingQuarantined) {
			result.Disposition = QuarantinedUncertain
			return result, ErrBindingQuarantined
		}
		if stage == bindingMarkerCreation {
			return result, fmt.Errorf("record Codex authentication binding %q: %w", name, err)
		}
		return result, ErrStatusFailed
	}
	defer locked.Release()
	if err := projectCredential(created.HomeDirectory(), record); err != nil {
		_ = registry.quarantine.MarkRecoverable(ctx, name)
		if cleanupErr := registry.removeCreatedBinding(ctx, created, name); cleanupErr != nil {
			result.Disposition = QuarantinedUncertain
			return result, ErrBindingQuarantined
		}
		result.Disposition = DiscardedProjection
		return result, ErrProjectedAuthInvalid
	}

	run := registry.status.Run(ctx, created, record.Metadata.Workspace, proofChallenge)
	run.err = sanitizeStatusError(run.err)
	if err := registry.settleBinding(ctx, created, name, run.cleanupProven, run.cleanupProcess); err != nil {
		result.Disposition = QuarantinedUncertain
		return result, ErrBindingQuarantined
	}
	return registry.finalizeStatus(ctx, result, record, created, run.err)
}

// Recover finalizes one durable quarantine marker. It is idempotent when no
// marker exists and never exposes projected credential bytes.
func (registry *Registry) Recover(ctx context.Context, value string) (BindingDisposition, error) {
	name, err := ParseCredentialRef(value)
	if err != nil {
		return "", err
	}
	locked, err := registry.tryLock(ctx, name, true)
	if err != nil {
		return "", err
	}
	defer locked.Release()
	marker, exists, err := registry.quarantine.Inspect(ctx, name)
	if err != nil {
		return QuarantinedUncertain, err
	}
	if !exists {
		return DiscardedProjection, nil
	}
	recovered, sessionExists, err := launch.RecoverSession(registry.sessionsDirectory, marker.SessionID)
	if errors.Is(err, launch.ErrSessionStillActive) {
		return QuarantinedUncertain, fmt.Errorf("%w: %q", ErrIdentityBusy, name)
	}
	if err != nil {
		return QuarantinedUncertain, ErrBindingQuarantined
	}
	if !sessionExists {
		if err := registry.quarantine.Delete(ctx, name); err != nil {
			return QuarantinedUncertain, ErrBindingQuarantined
		}
		return DiscardedProjection, nil
	}
	defer recovered.Preserve()
	if marker.Phase == quarantineCleanupPending {
		challenge, decodeErr := hex.DecodeString(marker.ProofChallenge)
		proven, proofErr := registry.verifyCleanup(recovered.RootDir, challenge)
		if decodeErr != nil || proofErr != nil || !proven {
			return QuarantinedUncertain, fmt.Errorf("%w: %q", ErrIdentityBusy, name)
		}
	}

	record, recordExists, err := registry.provider.Load(ctx, name)
	if err != nil {
		return QuarantinedUncertain, ErrBindingQuarantined
	}
	disposition := DiscardedProjection
	if recordExists {
		defer clearBytes(record.Auth)
		projected, readErr := readPrivateAuthFile(filepath.Join(recovered.RootDir, "home", ".codex", "auth.json"))
		if readErr == nil {
			defer clearBytes(projected)
			metadata, validationErr := validateAuthJSON(name, projected)
			if validationErr == nil && metadata == record.Metadata && !bytes.Equal(projected, record.Auth) {
				if err := registry.provider.Replace(ctx, credentialRecord{Metadata: metadata, Auth: projected}); err != nil {
					return QuarantinedUncertain, ErrBindingQuarantined
				}
				disposition = CommittedSameIdentityRefresh
			}
		}
	}
	if err := recovered.Remove(); err != nil {
		return QuarantinedUncertain, ErrBindingQuarantined
	}
	if err := registry.quarantine.Delete(ctx, name); err != nil {
		return QuarantinedUncertain, ErrBindingQuarantined
	}
	return disposition, nil
}

func (registry *Registry) transferPendingBinding(
	created *session.Session,
	name CredentialRef,
	process launch.Process,
) {
	if process == nil {
		_ = created.PreserveForRecovery()
		return
	}
	go func() {
		if err := launch.AwaitRetainedSessionCleanup(process); err != nil {
			return
		}
		if err := created.PreserveForRecovery(); err != nil {
			return
		}
		_ = registry.quarantine.MarkRecoverable(context.Background(), name)
	}()
}

func (registry *Registry) finalizeStatus(
	ctx context.Context,
	result IdentityStatus,
	record credentialRecord,
	created *session.Session,
	runErr error,
) (IdentityStatus, error) {
	if runErr != nil {
		if err := registry.removeCreatedBinding(ctx, created, record.Metadata.Name); err != nil {
			result.Disposition = QuarantinedUncertain
			return result, ErrBindingQuarantined
		}
		result.Disposition = DiscardedProjection
		return result, runErr
	}

	projected, err := readPrivateAuthFile(filepath.Join(created.HomeDirectory(), ".codex", "auth.json"))
	if err != nil {
		if cleanupErr := registry.removeCreatedBinding(ctx, created, record.Metadata.Name); cleanupErr != nil {
			result.Disposition = QuarantinedUncertain
			return result, ErrBindingQuarantined
		}
		result.Disposition = DiscardedProjection
		return result, ErrProjectedAuthInvalid
	}
	defer clearBytes(projected)
	metadata, err := validateAuthJSON(record.Metadata.Name, projected)
	if err != nil || metadata != record.Metadata {
		if cleanupErr := registry.removeCreatedBinding(ctx, created, record.Metadata.Name); cleanupErr != nil {
			result.Disposition = QuarantinedUncertain
			return result, ErrBindingQuarantined
		}
		result.Disposition = DiscardedProjection
		return result, ErrProjectedAuthInvalid
	}

	disposition := DiscardedProjection
	if !bytes.Equal(projected, record.Auth) {
		if err := registry.provider.Replace(ctx, credentialRecord{Metadata: metadata, Auth: projected}); err != nil {
			_ = created.PreserveForRecovery()
			result.Disposition = QuarantinedUncertain
			return result, ErrBindingQuarantined
		}
		disposition = CommittedSameIdentityRefresh
	}
	if err := registry.removeCreatedBinding(ctx, created, record.Metadata.Name); err != nil {
		result.Disposition = QuarantinedUncertain
		return result, ErrBindingQuarantined
	}
	result.Disposition = disposition
	return result, nil
}

func (registry *Registry) removeCreatedBinding(
	ctx context.Context,
	created *session.Session,
	name CredentialRef,
) error {
	if err := created.Remove(); err != nil {
		_ = created.PreserveForRecovery()
		return ErrBindingQuarantined
	}
	if err := registry.quarantine.Delete(ctx, name); err != nil {
		return ErrBindingQuarantined
	}
	return nil
}

func projectCredential(home string, record credentialRecord) error {
	if err := validateMetadata(record.Metadata); err != nil {
		return ErrProjectedAuthInvalid
	}
	validated, err := validateAuthJSON(record.Metadata.Name, record.Auth)
	if err != nil || validated != record.Metadata {
		return ErrProjectedAuthInvalid
	}
	codexHome := filepath.Join(home, ".codex")
	if err := os.Mkdir(codexHome, 0o700); err != nil {
		return ErrProjectedAuthInvalid
	}
	configuration := "cli_auth_credentials_store = \"file\"\nforced_login_method = \"chatgpt\"\n"
	if record.Metadata.Workspace != "" {
		configuration += fmt.Sprintf("forced_chatgpt_workspace_id = %q\n", record.Metadata.Workspace)
	}
	if err := writeExclusivePrivateFile(filepath.Join(codexHome, "config.toml"), []byte(configuration)); err != nil {
		return ErrProjectedAuthInvalid
	}
	if err := writeExclusivePrivateFile(filepath.Join(codexHome, "auth.json"), record.Auth); err != nil {
		return ErrProjectedAuthInvalid
	}
	return nil
}

func writeExclusivePrivateFile(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	remove := true
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	remove = false
	return nil
}
