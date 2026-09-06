package codexauth

import (
	"context"

	"github.com/alcimerio/ai-config-selector/internal/executor"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

type Config struct {
	BinaryPath        string
	SupportedVersion  string
	RuntimeInputs     []string
	ACSHome           string
	SessionsDirectory string
	WorkingDirectory  string
}

type LoginRequest struct {
	Name       string
	DeviceAuth bool
	Terminal   launch.Terminal
}

// Registry is the public typed Codex authentication facade. The executor owns
// the complete operation and recovery lifecycle; no backend or Session handle
// crosses this boundary.
type Registry struct{ service *executor.CodexAuthService }

func New(config Config) (*Registry, error) {
	service, err := executor.NewCodexAuth(executor.CodexAuthConfig{
		BinaryPath: config.BinaryPath, SupportedVersion: config.SupportedVersion,
		RuntimeInputs: config.RuntimeInputs, ACSHome: config.ACSHome,
		SessionsDirectory: config.SessionsDirectory, WorkingDirectory: config.WorkingDirectory,
	})
	if err != nil {
		return nil, err
	}
	return &Registry{service: service}, nil
}

func (registry *Registry) Login(ctx context.Context, request LoginRequest) (IdentityMetadata, error) {
	return registry.service.Login(ctx, executor.CodexLoginRequest{
		Name: request.Name, DeviceAuth: request.DeviceAuth, Terminal: request.Terminal,
	})
}
func (registry *Registry) Status(ctx context.Context, name string) (IdentityStatus, error) {
	return registry.service.Status(ctx, name)
}
func (registry *Registry) Recover(ctx context.Context, name string) (BindingDisposition, error) {
	return registry.service.Recover(ctx, name)
}
func (registry *Registry) List(ctx context.Context) ([]IdentityMetadata, error) {
	return registry.service.List(ctx)
}
func (registry *Registry) Logout(ctx context.Context, name string) error {
	return registry.service.Logout(ctx, name)
}
