package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/environmentresource"
	"github.com/alcimerio/ai-config-selector/internal/grokcompat"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

var (
	ErrGrokUnsupportedVersion        = errors.New("Grok version is not the reviewed release")
	ErrGrokAuthenticationUnavailable = errors.New("Grok authentication is unavailable")
	ErrGrokControlEnvironment        = errors.New("Grok control environment destination is reserved")
)

// GrokRequest is the fixed Grok Build lifecycle input. Command shape, credential
// destination, probe order, and sandbox choice are not adapter-controlled.
type GrokRequest struct {
	SessionsDirectory string
	WorkingDirectory  string
	ResolvedPlan      *authority.Plan
	Terminal          launch.Terminal

	executable           string
	runtimeInputs        []string
	existingHome         string
	runtimeAuthority     launch.RuntimeAuthority
	filesystemGrants     []launch.FilesystemGrant
	filesystemExclusions []launch.FilesystemExclusion
	executableGrants     []launch.ExecutableGrant
	sessionProtections   []launch.SessionProtection
}

type grokExitError int

func (e grokExitError) Error() string { return "Grok exited" }
func (e grokExitError) ExitCode() int { return int(e) }

// RunGrok launches interactive Grok inside the required sandbox. The version
// probe runs before any credential is copied and receives no selected environment.
func (e *Executor) RunGrok(ctx context.Context, request GrokRequest) (exitCode int, resultErr error) {
	if e == nil || e.sandbox == nil {
		return 1, errors.New("contained Grok executor is unavailable")
	}
	if request.ResolvedPlan == nil {
		return 1, errors.New("resolved authority does not select the Grok execution recipe")
	}
	requirements := request.ResolvedPlan.Requirements()
	if requirements.Recipe != authority.RecipeGrok || !requirements.Semantics.Supports(authority.RecipeGrok) {
		return 1, errors.New("resolved authority does not select the Grok execution recipe")
	}
	if requirements.Semantics.CredentialProjection != "optional-allowlisted-value-omitted" {
		return 1, errors.New("resolved authority has unsupported Grok credential projection")
	}
	request.executable, request.runtimeInputs, request.existingHome = requirements.Executable, requirements.RuntimeInputs, requirements.ExistingHomeDirectory
	runtimeAuthority, exclusions, grants, executableGrants, executable, err := resolvePlannedExecution(request.ResolvedPlan, request.WorkingDirectory, request.SessionsDirectory, request.executable)
	if err != nil {
		return 1, err
	}
	request.runtimeAuthority, request.filesystemExclusions, request.filesystemGrants, request.executableGrants, request.executable = runtimeAuthority, exclusions, grants, executableGrants, executable
	intents := request.ResolvedPlan.EnvironmentIntents()
	for _, intent := range intents {
		if grokControlDestination(intent.Destination) {
			return 1, ErrGrokControlEnvironment
		}
	}
	requiresEnvironment := len(intents) != 0
	if err := e.sandbox.Check(ctx, launch.SandboxCheck{
		Workspace: request.WorkingDirectory, WorkspaceAccess: request.ResolvedPlan.WorkspaceAccess(), SessionsDirectory: request.SessionsDirectory,
		Executable: request.executable, RuntimeInputs: request.runtimeInputs, RuntimeAuthority: request.runtimeAuthority,
		FilesystemExclusions: request.filesystemExclusions, FilesystemGrants: request.filesystemGrants, ExecutableGrants: request.executableGrants,
		RequiresEnvironment: requiresEnvironment,
	}); err != nil {
		return 1, err
	}
	environment, err := resolvePlanEnvironment(request.ResolvedPlan, e.environmentLookup)
	if err != nil {
		return 1, err
	}
	releaseEnvironment := environment != nil
	defer func() {
		if releaseEnvironment && environment != nil {
			environment.Release()
		}
	}()
	created, err := session.CreateTracked(request.SessionsDirectory, request.WorkingDirectory, *request.ResolvedPlan, "grok")
	if err != nil {
		return 1, err
	}
	defer func() {
		if removeErr := created.Remove(); removeErr != nil {
			resultErr = cleanupPrecedence(resultErr, removeErr)
			exitCode = 1
		}
	}()
	_, protections, err := projectGrokSession(created, request)
	if err != nil {
		return 1, err
	}
	request.sessionProtections = append(protections, launch.SessionProtection{Path: filepath.Join(created.HomeDirectory(), ".grok", "trusted_folders.toml")})
	versionOutput := boundedBuffer{limit: maximumVersionOutputSize}
	version, err := e.prepareGrok(ctx, created, request, []string{"--version"}, launch.Terminal{Output: &versionOutput, ErrorOutput: io.Discard}, nil)
	if err != nil {
		return 1, err
	}
	versionErr, cleanupErr := settleRetainedProcess(version, retainedProbe, nil)
	if cleanupErr != nil {
		return 1, cleanupPrecedence(versionErr, cleanupErr)
	}
	if ctx.Err() != nil {
		return 1, errors.New("Grok launch interrupted before the interactive process started")
	}
	if versionErr != nil || versionOutput.overflow || !grokcompat.AcceptsOutput(versionOutput.String()) {
		return 1, ErrGrokUnsupportedVersion
	}
	if err := copyAllowlistedCredential(filepath.Join(request.existingHome, ".grok", "auth.json"), filepath.Join(created.HomeDirectory(), ".grok", "auth.json")); err != nil {
		return 1, err
	}
	if !grokAuthenticationReady(created.HomeDirectory(), intents) {
		return 1, ErrGrokAuthenticationUnavailable
	}
	process, err := e.prepareGrok(ctx, created, request, nil, request.Terminal, environment)
	if err != nil {
		return 1, err
	}
	if releaseEnvironmentAfterCleanup(process, environment) {
		releaseEnvironment = false
	}
	runErr, cleanupErr := settleRetainedProcess(process, retainedAttached, nil)
	if cleanupErr != nil {
		return 1, cleanupPrecedence(runErr, cleanupErr)
	}
	if runErr == nil {
		return 0, nil
	}
	if ctx.Err() != nil {
		return 1, fmt.Errorf("Grok launch interrupted: %w", ctx.Err())
	}
	var exitError *exec.ExitError
	if errors.As(runErr, &exitError) {
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			code := 128 + int(status.Signal())
			return code, grokExitError(code)
		}
		if code := exitError.ExitCode(); code >= 0 {
			return code, grokExitError(code)
		}
	}
	return 1, fmt.Errorf("start Grok: %w", runErr)
}

func (e *Executor) prepareGrok(ctx context.Context, created *session.Session, request GrokRequest, arguments []string, terminal launch.Terminal, environment *environmentresource.Lease) (launch.Process, error) {
	return e.prepareRetainedProcess(ctx, created, launch.ProcessRequest{
		Workspace: created.WorkingDirectory(), WorkspaceAccess: request.ResolvedPlan.WorkspaceAccess(),
		SessionsDirectory: created.SessionsDirectory(), SessionDirectory: created.RootDirectory(), SessionHome: created.HomeDirectory(),
		TemporaryDirectory: created.TemporaryDirectory(), Executable: request.executable, RuntimeInputs: request.runtimeInputs,
		Arguments: arguments, Terminal: terminal, RuntimeAuthority: request.runtimeAuthority,
		FilesystemExclusions: request.filesystemExclusions, FilesystemGrants: request.filesystemGrants, ExecutableGrants: request.executableGrants,
		SessionProtections: request.sessionProtections, Environment: environment,
	})
}

func projectGrokSession(created *session.Session, request GrokRequest) (string, []launch.SessionProtection, error) {
	servers := request.ResolvedPlan.MCPServerIntents()
	recipes, recipeDirectory, launcher, err := prepareMCPRecipes(created.HomeDirectory(), servers, request.executableGrants, request.filesystemGrants, request.ResolvedPlan.EnvironmentIntents())
	if err != nil {
		return "", nil, errors.New("selected MCP bindings could not be compiled")
	}
	if launcher == "" && len(recipes) != 0 {
		return "", nil, errors.New("MCP target projection is unavailable")
	}
	configPath, err := writeGrokUserConfig(created.HomeDirectory(), launcher, recipes)
	if err != nil {
		return "", nil, err
	}
	trustPath := filepath.Join(created.HomeDirectory(), ".grok", "trusted_folders.toml")
	if err := writeSessionProjection(trustPath, []byte("# ACS does not grant folder trust.\n")); err != nil {
		return "", nil, err
	}
	return configPath, mcpSessionProtections(recipeDirectory, configPath), nil
}

func writeGrokUserConfig(home, launcher string, recipes []launch.MCPRecipe) (string, error) {
	if !filepath.IsAbs(home) {
		return "", errors.New("Grok user config Session HOME is invalid")
	}
	canonicalHome, err := canonicalMCPProjectionHome(home)
	if err != nil {
		return "", err
	}
	body := grokUserConfiguration(recipes, launcher, canonicalHome)
	path := filepath.Join(canonicalHome, ".grok", "config.toml")
	if err := mkdirSessionConfigParents(canonicalHome, filepath.Dir(path)); err != nil {
		return "", err
	}
	if err := writeSessionProjection(path, []byte(body)); err != nil {
		return "", err
	}
	return path, nil
}

func grokUserConfiguration(recipes []launch.MCPRecipe, launcher, home string) string {
	body := `[cli]
auto_update = false

[sandbox]
profile = "off"

[plugins]
enabled = []

[compat.cursor]
skills = false
rules = false
agents = false
mcps = false
hooks = false
sessions = false

[compat.claude]
skills = false
rules = false
agents = false
mcps = false
hooks = false
sessions = false

[compat.codex]
skills = false
rules = false
agents = false
mcps = false
hooks = false
sessions = false
`
	if len(recipes) == 0 {
		return body
	}
	ordered := append([]launch.MCPRecipe(nil), recipes...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	for _, recipe := range ordered {
		body += "\n[mcp_servers." + quoteTOMLString(recipe.ID) + "]\n"
		body += "command = " + quoteTOMLString(launcher) + "\n"
		body += "args = [\"--acs-mcp-launch\", " + quoteTOMLString(home) + ", " + quoteTOMLString(recipe.ID) + "]\n"
		body += "enabled = true\n"
	}
	disabled := ""
	for _, recipe := range ordered {
		if len(recipe.Disabled) > 0 {
			disabled += quoteTOMLString(recipe.ID) + " = " + quoteTOMLArray(recipe.Disabled) + "\n"
		}
	}
	if disabled != "" {
		body += "\n[disabled_mcp_tools]\n" + disabled
	}
	return body
}

func grokAuthenticationReady(home string, intents []launch.EnvironmentIntent) bool {
	info, err := os.Lstat(filepath.Join(home, ".grok", "auth.json"))
	if err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0 {
		return true
	}
	for _, intent := range intents {
		if intent.Destination == "XAI_API_KEY" {
			return true
		}
	}
	return false
}

func grokControlDestination(name string) bool {
	switch name {
	case "GROK_HOME", "GROK_FOLDER_TRUST", "GROK_DISABLE_AUTOUPDATER", "GROK_SANDBOX", "GROK_SANDBOX_AUTO_ALLOW_BASH", "GROK_DEPLOYMENT_KEY":
		return true
	}
	return strings.HasPrefix(name, "GROK_CURSOR_") || strings.HasPrefix(name, "GROK_CLAUDE_") || strings.HasPrefix(name, "GROK_CODEX_")
}
