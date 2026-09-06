package codexauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

// loginWithResource leaves executable and Session ownership in the facade, but
// every durable decision is made by the opaque resource binding.
func (registry *Registry) loginWithResource(ctx context.Context, request LoginRequest) (IdentityMetadata, error) {
	binding, err := registry.resources.AcquireLogin(ctx, request.Name)
	if err != nil {
		return IdentityMetadata{}, err
	}
	defer binding.Release()
	if registry.sessionsDirectory == "" || registry.workingDirectory == "" {
		return IdentityMetadata{}, ErrProviderUnavailable
	}
	preparation, err := registry.login.Prepare(ctx)
	if err != nil {
		return IdentityMetadata{}, err
	}
	defer preparation.Close()
	challenge := make([]byte, launch.RecoveryProofChallengeSize)
	if _, err := rand.Read(challenge); err != nil {
		return IdentityMetadata{}, ErrLoginFailed
	}
	encoded := hex.EncodeToString(challenge)
	created, err := session.Create(registry.sessionsDirectory, registry.workingDirectory, nil)
	if err != nil {
		return IdentityMetadata{}, ErrLoginFailed
	}
	remove := func() error {
		if err := created.Remove(); err != nil {
			_ = created.PreserveForRecovery()
			return ErrLoginCleanupUncertain
		}
		if err := binding.DeleteMarkerAfterProjectionRemoval(ctx); err != nil {
			return ErrLoginCleanupUncertain
		}
		return nil
	}
	if err := binding.PublishPrepared(ctx, filepath.Base(created.RootDirectory()), encoded); err != nil {
		_ = created.Remove()
		return IdentityMetadata{}, err
	}
	if err := created.ProtectForRecovery(); err != nil {
		_ = binding.MarkRecoverable(ctx)
		if cleanupErr := remove(); cleanupErr != nil {
			return IdentityMetadata{}, cleanupErr
		}
		return IdentityMetadata{}, ErrLoginFailed
	}
	run := preparation.Run(ctx, created, encoded, func() error { return binding.MarkCleanupPending(ctx) }, request.DeviceAuth, request.Terminal)
	if !run.cleanupProven {
		_ = created.PreserveForRecovery()
		return IdentityMetadata{}, ErrLoginCleanupUncertain
	}
	if err := binding.MarkRecoverable(ctx); err != nil {
		_ = created.PreserveForRecovery()
		return IdentityMetadata{}, ErrLoginCleanupUncertain
	}
	if run.err != nil {
		clearBytes(run.auth)
		if err := remove(); err != nil {
			return IdentityMetadata{}, err
		}
		return IdentityMetadata{}, run.err
	}
	defer clearBytes(run.auth)
	metadata, err := binding.CommitLogin(ctx, run.auth)
	if err != nil {
		if cleanupErr := remove(); cleanupErr != nil {
			return IdentityMetadata{}, cleanupErr
		}
		if errors.Is(err, codexauthresource.ErrUnsupportedAuth) {
			return IdentityMetadata{}, ErrUnsupportedAuth
		}
		return IdentityMetadata{}, err
	}
	if err := remove(); err != nil {
		return IdentityMetadata{}, err
	}
	return metadata, nil
}
