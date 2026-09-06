package codexauth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

// loginResourceStore is deliberately narrow: Login orchestration can acquire
// one opaque binding but cannot obtain providers, locks, markers, or auth.
// Production wraps the concrete lower Store; package tests replace only this
// fixed capability while exercising the same Registry.Login sequence.
type loginResourceStore interface {
	AcquireLogin(context.Context, string) (loginResourceBinding, error)
}

type loginResourceBinding interface {
	Release() error
	PublishPrepared(context.Context, string, string) error
	Published(context.Context, string, string) (bool, error)
	MarkCleanupPending(context.Context) error
	MarkRecoverable(context.Context) error
	SettlePending(context.Context, string, string) error
	DeleteMarkerAfterProjectionRemoval(context.Context) error
	CommitLogin(context.Context, string) (codexauthresource.IdentityMetadata, error)
}

type productionLoginResources struct{ store *codexauthresource.Store }

func (resources productionLoginResources) AcquireLogin(ctx context.Context, name string) (loginResourceBinding, error) {
	if resources.store == nil {
		return nil, ErrProviderUnavailable
	}
	return resources.store.AcquireLogin(ctx, name)
}

type unavailableLoginResources struct{}

func (unavailableLoginResources) AcquireLogin(context.Context, string) (loginResourceBinding, error) {
	return nil, ErrProviderUnavailable
}

func (registry *Registry) transferResourcePendingBinding(created *session.Session, binding loginResourceBinding, challenge string, process launch.Process) {
	if process == nil {
		_ = created.PreserveForRecovery()
		return
	}
	sessionID := filepath.Base(created.RootDirectory())
	go func() {
		// The foreground path already performed the required bounded wait.  Once
		// ownership has moved to durable quarantine, wait for the backend's actual
		// cleanup notification instead of applying a second timeout that could
		// abandon a cleanup which completes later.
		if cleanup, ok := process.(launch.ProcessCleanup); ok && cleanup.CleanupDone() != nil {
			<-cleanup.CleanupDone()
		}
		if err := launch.AwaitRetainedSessionCleanup(process); err != nil {
			return
		}
		if err := created.PreserveForRecovery(); err != nil {
			return
		}
		// The resource operation re-acquires its own lock and verifies all
		// generation authority before changing the durable marker.
		for {
			err := binding.SettlePending(context.Background(), sessionID, challenge)
			if err == nil {
				return
			}
			if !errors.Is(err, codexauthresource.ErrIdentityBusy) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
}

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
		// Create may have durably published its marker before reporting a
		// directory-sync failure.  Preserve the projection: Recover can consume
		// the unchanged marker format, while deleting it here could orphan a
		// live or recoverable Session.
		published, inspectErr := binding.Published(ctx, filepath.Base(created.RootDirectory()), encoded)
		if inspectErr != nil {
			// Inspection cannot prove that publication did not happen.  Protect and
			// preserve the Session while leaving any marker unchanged; old Recover
			// understands the prepared phase and can reconcile it later.
			if protectErr := created.ProtectForRecovery(); protectErr == nil {
				_ = created.PreserveForRecovery()
			}
		} else if published {
			if protectErr := created.ProtectForRecovery(); protectErr != nil {
				if cleanupErr := remove(); cleanupErr != nil {
					return IdentityMetadata{}, cleanupErr
				}
				return IdentityMetadata{}, err
			} else {
				// A transition can itself publish before reporting a durability
				// error, so any failure after protection retains both marker and
				// projection for recovery.
				_ = binding.MarkRecoverable(ctx)
				_ = created.PreserveForRecovery()
			}
		} else {
			if removeErr := created.Remove(); removeErr != nil {
				return IdentityMetadata{}, ErrLoginCleanupUncertain
			}
			return IdentityMetadata{}, err
		}
		return IdentityMetadata{}, ErrLoginCleanupUncertain
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
		registry.transferResourcePendingBinding(created, binding, encoded, run.cleanupProcess)
		return IdentityMetadata{}, ErrLoginCleanupUncertain
	}
	if err := binding.MarkRecoverable(ctx); err != nil {
		_ = created.PreserveForRecovery()
		return IdentityMetadata{}, ErrLoginCleanupUncertain
	}
	if run.err != nil {
		if err := remove(); err != nil {
			return IdentityMetadata{}, err
		}
		return IdentityMetadata{}, run.err
	}
	metadata, err := binding.CommitLogin(ctx, created.RootDirectory())
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
