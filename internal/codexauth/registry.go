package codexauth

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

type loginRunResult struct {
	containedRunResult
}

type loginPreparation struct {
	run       func(context.Context, *session.Session, string, func() error, bool, launch.Terminal) loginRunResult
	operation *containedOperationPreparation
}

func (preparation loginPreparation) Run(
	ctx context.Context,
	created *session.Session,
	proofChallenge string,
	beginProcess func() error,
	deviceAuth bool,
	terminal launch.Terminal,
) loginRunResult {
	if preparation.run == nil {
		return loginRunResult{containedRunResult: containedRunResult{err: ErrLoginFailed, cleanupProven: true}}
	}
	return preparation.run(ctx, created, proofChallenge, beginProcess, deviceAuth, terminal)
}

func (preparation loginPreparation) Close() {
	preparation.operation.Close()
}

type loginRunner interface {
	Prepare(context.Context) (loginPreparation, error)
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
	resources         authResourceStore
	login             loginRunner
	status            statusRunner
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
	requestedACSHome := filepath.Clean(config.ACSHome)
	acsHome, err := securePrivateRoot(requestedACSHome)
	if err != nil {
		return nil, errors.New("create Codex authentication registry: ACS home must be a private owned directory")
	}
	locksRoot, err := securePrivateChild(acsHome, "locks")
	if err != nil {
		return nil, errors.New("create Codex authentication registry: locks directory must be private")
	}
	locksDirectory, err := securePrivateChild(locksRoot, "codex-auth")
	if err != nil {
		return nil, errors.New("create Codex authentication registry: authentication locks directory must be private")
	}
	quarantineRoot, err := securePrivateChild(acsHome, "quarantine")
	if err != nil {
		return nil, errors.New("create Codex authentication registry: quarantine directory must be private")
	}
	quarantineDirectory, err := securePrivateChild(quarantineRoot, "codex-auth")
	if err != nil {
		return nil, errors.New("create Codex authentication registry: authentication quarantine directory must be private")
	}
	resources, err := codexauthresource.New(locksDirectory, quarantineDirectory)
	if err != nil {
		return nil, errors.New("create Codex authentication registry: authentication resource directories must be private")
	}
	if filepath.Clean(config.SessionsDirectory) == filepath.Join(requestedACSHome, "sessions") {
		config.SessionsDirectory = filepath.Join(acsHome, "sessions")
	}
	sandbox := launch.NewProcessSandbox()
	registry := &Registry{
		resources: productionAuthResources{store: resources},
		login: newCodexLoginRunner(codexLoginConfig{
			BinaryPath: config.BinaryPath, SupportedVersion: config.SupportedVersion,
			RuntimeInputs: config.RuntimeInputs, SessionsDirectory: config.SessionsDirectory,
			WorkingDirectory: config.WorkingDirectory, PrivateRoot: acsHome,
		}, sandbox),
		verifyCleanup: launch.VerifySessionCleanupProof,
	}
	registry.status = newCodexStatusRunner(codexLoginConfig{
		BinaryPath: config.BinaryPath, SupportedVersion: config.SupportedVersion,
		RuntimeInputs: config.RuntimeInputs, SessionsDirectory: config.SessionsDirectory,
		WorkingDirectory: config.WorkingDirectory, PrivateRoot: acsHome,
	}, sandbox)
	registry.sessionsDirectory = config.SessionsDirectory
	registry.workingDirectory = config.WorkingDirectory
	return registry, nil
}

// Login creates one new identity. An existing name is never replaced.
func (registry *Registry) Login(ctx context.Context, request LoginRequest) (IdentityMetadata, error) {
	return registry.loginWithResource(ctx, request)
}

// List returns only provider attributes; it does not retrieve credential
// payloads from Keychain.
func (registry *Registry) List(ctx context.Context) ([]IdentityMetadata, error) {
	return registry.resources.List(ctx)
}

// Logout removes only the selected ACS-owned identity. Absence is idempotent.
func (registry *Registry) Logout(ctx context.Context, value string) error {
	return registry.resources.Logout(ctx, value)
}
