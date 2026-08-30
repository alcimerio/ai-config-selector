package codexauth

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

type credentialRecord struct {
	Metadata IdentityMetadata
	Auth     []byte
}

type credentialProvider interface {
	Metadata(context.Context, CredentialRef) (IdentityMetadata, bool, error)
	Create(context.Context, credentialRecord) error
	Replace(context.Context, credentialRecord) error
	List(context.Context) ([]IdentityMetadata, error)
	Load(context.Context, CredentialRef) (credentialRecord, bool, error)
	Delete(context.Context, CredentialRef) error
}

type loginRunResult struct {
	auth []byte
	containedRunResult
}

type loginRunner interface {
	Check(context.Context) error
	Run(context.Context, *session.Session, string, bool, launch.Terminal) loginRunResult
}

type identityLocker interface {
	TryLock(CredentialRef) (identityLock, error)
}

type identityLock interface {
	Release() error
}

// Config contains production paths and the version-pinned Codex executable.
type Config struct {
	BinaryPath        string
	SupportedVersion  string
	RuntimeInputs     []string
	ACSHome           string
	SessionsDirectory string
	WorkingDirectory  string
}

// LoginRequest selects one new named identity and the supported interactive
// login flow. Credential bytes are never accepted from callers.
type LoginRequest struct {
	Name       string
	DeviceAuth bool
	Terminal   launch.Terminal
}

// Registry is the deep named-auth module used by the CLI. Provider records,
// login Sessions, credential bytes, and identity locks stay behind this seam.
type Registry struct {
	provider          credentialProvider
	login             loginRunner
	locks             identityLocker
	status            statusRunner
	quarantine        bindingQuarantine
	verifyCleanup     func(string, []byte) (bool, error)
	sessionsDirectory string
	workingDirectory  string
}

// New constructs the production registry with macOS Keychain storage and the
// mandatory native Process Sandbox for Codex login.
func New(config Config) (*Registry, error) {
	if config.BinaryPath == "" {
		return nil, errors.New("create Codex authentication registry: binary path is required")
	}
	if config.SupportedVersion == "" {
		config.SupportedVersion = SupportedCodexVersion
	}
	for label, path := range map[string]string{
		"ACS home": config.ACSHome, "Sessions directory": config.SessionsDirectory,
		"working directory": config.WorkingDirectory,
	} {
		if path == "" || !filepath.IsAbs(path) {
			return nil, fmt.Errorf("create Codex authentication registry: %s must be absolute", label)
		}
	}
	workingDirectory, err := filepath.EvalSymlinks(config.WorkingDirectory)
	if err != nil {
		return nil, errors.New("create Codex authentication registry: working directory must exist")
	}
	acsHome := filepath.Clean(config.ACSHome)
	if resolved, err := filepath.EvalSymlinks(acsHome); err == nil {
		acsHome = resolved
	}
	if pathsOverlap(workingDirectory, acsHome) {
		return nil, errors.New("create Codex authentication registry: working directory must not overlap ACS home")
	}
	sandbox := launch.NewProcessSandbox()
	registry, err := newRegistry(
		newKeychainProvider(),
		newCodexLoginRunner(codexLoginConfig{
			BinaryPath: config.BinaryPath, SupportedVersion: config.SupportedVersion,
			RuntimeInputs: config.RuntimeInputs, SessionsDirectory: config.SessionsDirectory,
			WorkingDirectory: config.WorkingDirectory,
		}, sandbox),
		newFileIdentityLocker(filepath.Join(config.ACSHome, "locks", "codex-auth")),
	)
	if err != nil {
		return nil, err
	}
	registry.status = newCodexStatusRunner(codexLoginConfig{
		BinaryPath: config.BinaryPath, SupportedVersion: config.SupportedVersion,
		RuntimeInputs: config.RuntimeInputs, SessionsDirectory: config.SessionsDirectory,
		WorkingDirectory: config.WorkingDirectory,
	}, sandbox)
	registry.quarantine = newFileBindingQuarantine(filepath.Join(config.ACSHome, "quarantine", "codex-auth"))
	registry.sessionsDirectory = config.SessionsDirectory
	registry.workingDirectory = config.WorkingDirectory
	return registry, nil
}

func newRegistry(provider credentialProvider, login loginRunner, locks identityLocker) (*Registry, error) {
	if provider == nil || login == nil || locks == nil {
		return nil, errors.New("create Codex authentication registry: provider, login runner, and identity locker are required")
	}
	return &Registry{
		provider: provider, login: login, locks: locks, quarantine: noBindingQuarantine{},
		verifyCleanup: launch.VerifySessionCleanupProof,
	}, nil
}

// Login creates one new identity. An existing name is never replaced.
func (registry *Registry) Login(ctx context.Context, request LoginRequest) (IdentityMetadata, error) {
	name, err := ParseCredentialRef(request.Name)
	if err != nil {
		return IdentityMetadata{}, err
	}
	locked, err := registry.tryLock(ctx, name, false)
	if err != nil {
		return IdentityMetadata{}, err
	}
	defer locked.Release()

	if _, exists, err := registry.provider.Metadata(ctx, name); err != nil {
		return IdentityMetadata{}, fmt.Errorf("inspect Codex authentication identity %q: %w", name, err)
	} else if exists {
		return IdentityMetadata{}, fmt.Errorf("%w: %q", ErrIdentityExists, name)
	}

	if registry.sessionsDirectory == "" || registry.workingDirectory == "" {
		return IdentityMetadata{}, ErrProviderUnavailable
	}
	if err := registry.login.Check(ctx); err != nil {
		return IdentityMetadata{}, err
	}
	created, proofChallenge, stage, err := registry.prepareBinding(ctx, name)
	if err != nil {
		if errors.Is(err, ErrBindingQuarantined) {
			return IdentityMetadata{}, ErrLoginCleanupUncertain
		}
		if stage == bindingMarkerCreation {
			return IdentityMetadata{}, err
		}
		return IdentityMetadata{}, ErrLoginFailed
	}

	run := registry.login.Run(ctx, created, proofChallenge, request.DeviceAuth, request.Terminal)
	if err := registry.settleBinding(ctx, created, name, run.cleanupProven, run.cleanupProcess); err != nil {
		clearBytes(run.auth)
		return IdentityMetadata{}, ErrLoginCleanupUncertain
	}
	if run.err != nil {
		clearBytes(run.auth)
		if cleanupErr := registry.removeCreatedBinding(ctx, created, name); cleanupErr != nil {
			return IdentityMetadata{}, ErrLoginCleanupUncertain
		}
		return IdentityMetadata{}, run.err
	}
	defer clearBytes(run.auth)
	metadata, err := validateAuthJSON(name, run.auth)
	if err != nil {
		if cleanupErr := registry.removeCreatedBinding(ctx, created, name); cleanupErr != nil {
			return IdentityMetadata{}, ErrLoginCleanupUncertain
		}
		return IdentityMetadata{}, ErrUnsupportedAuth
	}
	if err := registry.provider.Create(ctx, credentialRecord{Metadata: metadata, Auth: run.auth}); err != nil {
		if cleanupErr := registry.removeCreatedBinding(ctx, created, name); cleanupErr != nil {
			return IdentityMetadata{}, ErrLoginCleanupUncertain
		}
		return IdentityMetadata{}, fmt.Errorf("store Codex authentication identity %q: %w", name, err)
	}
	if err := registry.removeCreatedBinding(ctx, created, name); err != nil {
		return IdentityMetadata{}, ErrLoginCleanupUncertain
	}
	return metadata, nil
}

// List returns only provider attributes; it does not retrieve credential
// payloads from Keychain.
func (registry *Registry) List(ctx context.Context) ([]IdentityMetadata, error) {
	identities, err := registry.provider.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list Codex authentication identities: %w", err)
	}
	sort.Slice(identities, func(left, right int) bool { return identities[left].Name < identities[right].Name })
	return identities, nil
}

// Logout removes only the selected ACS-owned identity. Absence is idempotent.
func (registry *Registry) Logout(ctx context.Context, value string) error {
	name, err := ParseCredentialRef(value)
	if err != nil {
		return err
	}
	locked, err := registry.tryLock(ctx, name, false)
	if err != nil {
		return err
	}
	defer locked.Release()
	if err := registry.provider.Delete(ctx, name); err != nil {
		return fmt.Errorf("remove Codex authentication identity %q: %w", name, err)
	}
	return nil
}

func (registry *Registry) tryLock(
	ctx context.Context,
	name CredentialRef,
	allowQuarantine bool,
) (identityLock, error) {
	locked, err := registry.locks.TryLock(name)
	if err != nil {
		return nil, err
	}
	if allowQuarantine {
		return locked, nil
	}
	_, exists, err := registry.quarantine.Inspect(ctx, name)
	if err != nil {
		_ = locked.Release()
		return nil, fmt.Errorf("inspect Codex authentication binding %q: %w", name, err)
	}
	if exists {
		_ = locked.Release()
		return nil, fmt.Errorf("%w: %q", ErrIdentityBusy, name)
	}
	return locked, nil
}
