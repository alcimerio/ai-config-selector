package executor

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

const SupportedCodexVersion = codexauthresource.SupportedCodexVersion

var (
	ErrInvalidCredentialRef  = codexauthresource.ErrInvalidCredentialRef
	ErrIdentityExists        = codexauthresource.ErrIdentityExists
	ErrIdentityNotFound      = codexauthresource.ErrIdentityNotFound
	ErrIdentityBusy          = codexauthresource.ErrIdentityBusy
	ErrProviderUnavailable   = codexauthresource.ErrProviderUnavailable
	ErrLoginFailed           = codexauthresource.ErrLoginFailed
	ErrLoginCleanupUncertain = codexauthresource.ErrLoginCleanupUncertain
	ErrUnsupportedVersion    = codexauthresource.ErrUnsupportedVersion
	ErrUnsupportedAuth       = codexauthresource.ErrUnsupportedAuth
	ErrStatusFailed          = codexauthresource.ErrStatusFailed
	ErrProjectedAuthInvalid  = codexauthresource.ErrProjectedAuthInvalid
	ErrBindingQuarantined    = codexauthresource.ErrBindingQuarantined
	ErrCodexFailed           = errors.New("contained interactive Codex failed")
	ErrCodexCleanupUncertain = errors.New("contained interactive Codex cleanup is uncertain")
)

type CredentialRef = codexauthresource.CredentialRef
type IdentityMetadata = codexauthresource.IdentityMetadata
type BindingDisposition = codexauthresource.BindingDisposition
type IdentityStatus = codexauthresource.IdentityStatus

const (
	CommittedSameIdentityRefresh = codexauthresource.CommittedSameIdentityRefresh
	DiscardedProjection          = codexauthresource.DiscardedProjection
	QuarantinedUncertain         = codexauthresource.QuarantinedUncertain
)

func ParseCredentialRef(value string) (CredentialRef, error) {
	return codexauthresource.ParseCredentialRef(value)
}

type CodexAuthConfig struct {
	BinaryPath        string
	SupportedVersion  string
	RuntimeInputs     []string
	ACSHome           string
	SessionsDirectory string
	WorkingDirectory  string
}

type CodexLoginRequest struct {
	Name       string
	DeviceAuth bool
	Terminal   launch.Terminal
}

// CodexRequest is the fixed interactive recipe input. The resolved plan owns
// all materialization, workspace, target and opaque identity authority.
type CodexRequest struct {
	ResolvedPlan *authority.Plan
	Terminal     launch.Terminal
}

type CodexAuthService struct {
	resources         authResourceStore
	login             loginRunner
	status            statusRunner
	execution         *codexExecutionRunner
	verifyCleanup     func(string, []byte) (bool, error)
	sessionsDirectory string
	workingDirectory  string
}

type loginRunResult struct{ containedRunResult }

type loginPreparation struct {
	run       func(context.Context, *session.Session, string, loginResourceBinding, bool, launch.Terminal) loginRunResult
	operation *containedOperationPreparation
}

func (preparation loginPreparation) Run(ctx context.Context, created *session.Session, proofChallenge string, binding loginResourceBinding, deviceAuth bool, terminal launch.Terminal) loginRunResult {
	if preparation.run == nil {
		return loginRunResult{containedRunResult: containedRunResult{err: ErrLoginFailed, cleanupProven: true}}
	}
	return preparation.run(ctx, created, proofChallenge, binding, deviceAuth, terminal)
}
func (preparation loginPreparation) Close() { preparation.operation.Close() }

type loginRunner interface {
	Prepare(context.Context) (loginPreparation, error)
}

func NewCodexAuth(config CodexAuthConfig) (*CodexAuthService, error) {
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
	service := &CodexAuthService{
		resources: productionAuthResources{store: resources},
		login: newCodexLoginRunner(codexLoginConfig{
			BinaryPath: config.BinaryPath, SupportedVersion: config.SupportedVersion,
			RuntimeInputs: config.RuntimeInputs, SessionsDirectory: config.SessionsDirectory,
			WorkingDirectory: config.WorkingDirectory, PrivateRoot: acsHome,
		}, sandbox),
		verifyCleanup: launch.VerifySessionCleanupProof,
	}
	service.status = newCodexStatusRunner(codexLoginConfig{
		BinaryPath: config.BinaryPath, SupportedVersion: config.SupportedVersion,
		RuntimeInputs: config.RuntimeInputs, SessionsDirectory: config.SessionsDirectory,
		WorkingDirectory: config.WorkingDirectory, PrivateRoot: acsHome,
	}, sandbox)
	service.execution = newCodexExecutionRunner(codexLoginConfig{
		BinaryPath: config.BinaryPath, SupportedVersion: config.SupportedVersion,
		RuntimeInputs: config.RuntimeInputs, SessionsDirectory: config.SessionsDirectory,
		WorkingDirectory: config.WorkingDirectory, PrivateRoot: acsHome,
	}, sandbox)
	service.sessionsDirectory = config.SessionsDirectory
	service.workingDirectory = config.WorkingDirectory
	return service, nil
}

func (service *CodexAuthService) Login(ctx context.Context, request CodexLoginRequest) (IdentityMetadata, error) {
	return service.loginWithResource(ctx, request)
}
func (service *CodexAuthService) List(ctx context.Context) ([]IdentityMetadata, error) {
	return service.resources.List(ctx)
}
func (service *CodexAuthService) Logout(ctx context.Context, name string) error {
	return service.resources.Logout(ctx, name)
}
