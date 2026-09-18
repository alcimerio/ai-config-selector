// Package executor owns the contained-process lifecycle for ACS's registered
// targets. Target adapters supply validated declarative inputs; this package
// owns checks, Sessions, contained processes, and cleanup.
package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"github.com/alcimerio/ai-config-selector/internal/environmentresource"
	"github.com/alcimerio/ai-config-selector/internal/instructions"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/runcommand"
	"github.com/alcimerio/ai-config-selector/internal/session"
	"github.com/alcimerio/ai-config-selector/internal/skills"
	"golang.org/x/sys/unix"
)

const systemShell = "/bin/zsh"

const maxDevinProbeOutput = 2 << 20

const devinRuleSeparator = "────────────────────────────────────────────────────────────"

var errDevinProbeOutputLimit = errors.New("Devin probe output exceeds its limit")

// ShellRequest contains the target-independent inputs needed to create a
// credential-free Session and attach ACS's fixed interactive shell.
type ShellRequest struct {
	SessionsDirectory string
	WorkingDirectory  string
	WorkspaceAccess   launch.WorkspaceAccess
	Materializer      session.Materializer
	ResolvedPlan      *authority.Plan
	Terminal          launch.Terminal
}

// DevinRequest is the fixed registered Devin lifecycle input. Its command
// shapes, credential destination, probe ordering, and sandbox choice are not
// adapter-controlled.
type DevinRequest struct {
	SessionsDirectory     string
	WorkingDirectory      string
	WorkspaceAccess       launch.WorkspaceAccess
	Materializer          session.Materializer
	Terminal              launch.Terminal
	Executable            string
	RuntimeInputs         []string
	ExistingHomeDirectory string
	ExpectedCatalog       []skills.SkillReference
	ExpectedInstructions  []instructions.Bundle
	ResolvedPlan          *authority.Plan
	RuntimeAuthority      launch.RuntimeAuthority
	FilesystemGrants      []launch.FilesystemGrant
	ExecutableGrants      []launch.ExecutableGrant
	sessionProtections    []launch.SessionProtection
	selectedMCPConfig     string
	reserveMCPConfigNames bool
}

// CommandRequest contains one already-resolved literal command and the common
// Profile authority under which the shared executor must run it.
type CommandRequest struct {
	SessionsDirectory string
	WorkingDirectory  string
	ResolvedPlan      *authority.Plan
	Command           runcommand.Command
	Terminal          launch.Terminal
}

func (request ShellRequest) resolvedInputs() (launch.WorkspaceAccess, session.Materializer, launch.RuntimeAuthority) {
	if request.ResolvedPlan != nil {
		return request.ResolvedPlan.WorkspaceAccess(), *request.ResolvedPlan, request.ResolvedPlan.RuntimeAuthority()
	}
	return request.WorkspaceAccess, request.Materializer, launch.DefaultRuntimeAuthority()
}
func (request DevinRequest) resolvedInputs() (launch.WorkspaceAccess, session.Materializer, []skills.SkillReference, authority.TargetRequirements) {
	if request.ResolvedPlan != nil {
		return request.ResolvedPlan.WorkspaceAccess(), *request.ResolvedPlan, request.ResolvedPlan.DevinExpectedCatalog(), request.ResolvedPlan.Requirements()
	}
	return request.WorkspaceAccess, request.Materializer, request.ExpectedCatalog, authority.TargetRequirements{
		Recipe: authority.RecipeDevin, Executable: request.Executable,
		RuntimeInputs: request.RuntimeInputs, ExistingHomeDirectory: request.ExistingHomeDirectory, Semantics: authority.DevinSemantics(),
	}
}

// Executor owns the fixed shell's sandbox check, Session lifecycle, and
// process settlement. Its backend is selected by ACS, never by an adapter.
type Executor struct {
	sandbox           launch.ProcessSandbox
	environmentLookup environmentresource.Lookup
}

type retainedSignalMode uint8

const (
	retainedProbe retainedSignalMode = iota
	retainedAttached
	retainedDevinReserved
)

var errRetainPreparedProcess = errors.New("retain prepared process")
var errInvalidPreparedProcess = &launch.SandboxError{Category: launch.SandboxSetupFailed}

func isNilProcess(process launch.Process) bool {
	if process == nil {
		return true
	}
	value := reflect.ValueOf(process)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func (e *Executor) prepareRetainedProcess(ctx context.Context, created *session.Session, request launch.ProcessRequest) (launch.Process, error) {
	challenge, err := created.ConsumeOrArmOperation(request.RecoveryProofChallenge)
	if err != nil {
		return nil, err
	}
	request.RecoveryProofChallenge = challenge
	process, err := e.sandbox.Prepare(ctx, request)
	if err != nil {
		return nil, err
	}
	if isNilProcess(process) {
		return nil, errInvalidPreparedProcess
	}
	retained, err := created.RetainUntilProcessDone(process)
	if err != nil {
		return nil, errors.Join(errRetainPreparedProcess, err)
	}
	return retained, nil
}

func settleRetainedProcess(process launch.Process, mode retainedSignalMode, devinSupervisor *devinSignalSupervisor) (error, error) {
	var runErr error
	switch mode {
	case retainedProbe:
		runErr = process.Start()
		if runErr == nil {
			runErr = process.Wait()
		}
	case retainedAttached:
		runErr = launch.RunAttached(process)
	case retainedDevinReserved:
		if devinSupervisor == nil {
			runErr = errors.New("contained Devin signal supervisor is unavailable")
		} else {
			runErr = runDevinAttachedReserved(process, devinSupervisor)
		}
	default:
		runErr = errors.New("contained process signal mode is invalid")
	}
	return runErr, launch.AwaitRetainedSessionCleanup(process)
}

func hasWritableFilesystemGrant(grants []launch.FilesystemGrant) bool {
	for _, grant := range grants {
		if grant.Access == launch.PathAccessReadWrite {
			return true
		}
	}
	return false
}

// New returns the production executor using ACS's required native sandbox.
func New() *Executor { return newExecutor(launch.NewProcessSandbox()) }

// newExecutor exists only for executor package tests. Production callers must
// use New so they cannot choose a sandbox backend.
func newExecutor(sandbox launch.ProcessSandbox) *Executor {
	return &Executor{sandbox: sandbox, environmentLookup: hostEnvironmentLookup}
}

// Readiness reports the fixed shell backend's passive readiness. It neither
// creates a Session nor prepares a process.
func (e *Executor) Readiness(ctx context.Context) (launch.SandboxReadiness, error) {
	if e == nil || e.sandbox == nil {
		return launch.SandboxReadiness{}, errors.New("contained shell executor is unavailable")
	}
	return e.sandbox.Readiness(ctx)
}

// RunShell creates and materializes a Session, then runs exactly /bin/zsh -f.
// A Session is retained until backend cleanup proves the whole process tree is
// gone; cleanup uncertainty and finalization failures outrank an ordinary exit.
func (e *Executor) RunShell(ctx context.Context, request ShellRequest) (resultErr error) {
	if e == nil || e.sandbox == nil {
		return errors.New("contained shell executor is unavailable")
	}
	workspaceAccess, materializer, runtimeAuthority := request.resolvedInputs()
	if request.ResolvedPlan != nil && request.ResolvedPlan.Requirements().Recipe != authority.RecipeShell {
		return errors.New("resolved authority does not select the shell execution recipe")
	}
	resultErr, _ = e.runAttached(ctx, attachedRecipe{
		sessionsDirectory: request.SessionsDirectory, workingDirectory: request.WorkingDirectory,
		workspaceAccess: workspaceAccess, materializer: materializer, runtimeAuthority: runtimeAuthority,
		resolvedPlan: request.ResolvedPlan,
		executable:   systemShell, arguments: []string{"-f"}, terminal: request.Terminal,
	})
	return resultErr
}

type attachedRecipe struct {
	sessionsDirectory string
	workingDirectory  string
	workspaceAccess   launch.WorkspaceAccess
	materializer      session.Materializer
	executable        string
	arguments         []string
	command           *runcommand.Command
	terminal          launch.Terminal
	runtimeAuthority  launch.RuntimeAuthority
	resolvedPlan      *authority.Plan
}

// runAttached is the one Session/process lifecycle for the fixed shell and an
// explicit generic command. Command identity validation is declarative and
// remains inside this shared lifecycle; there are no adapter callbacks.
func (e *Executor) runAttached(ctx context.Context, recipe attachedRecipe) (resultErr error, cleanupFailed bool) {
	executable, arguments := recipe.executable, append([]string(nil), recipe.arguments...)
	if recipe.command != nil {
		var err error
		executable, arguments, err = recipe.command.Revalidate(recipe.workingDirectory)
		if err != nil {
			return err, false
		}
	}
	var filesystemGrants []launch.FilesystemGrant
	var executableGrants []launch.ExecutableGrant
	requiresEnvironment := false
	if recipe.resolvedPlan != nil {
		requiresEnvironment = len(recipe.resolvedPlan.EnvironmentIntents()) != 0
		var err error
		filesystemGrants, err = recipe.resolvedPlan.ResolveFilesystemGrantsForExecutable(recipe.workingDirectory, recipe.sessionsDirectory, executable)
		if err != nil {
			return &launch.SandboxError{Category: launch.SandboxUnsafePath}, false
		}
		executableGrants, err = recipe.resolvedPlan.ResolveExecutableGrants(recipe.workingDirectory, recipe.sessionsDirectory)
		if err != nil {
			return &launch.SandboxError{Category: launch.SandboxUnsafePath}, false
		}
	}
	if err := e.sandbox.Check(ctx, launch.SandboxCheck{Workspace: recipe.workingDirectory,
		WorkspaceAccess: recipe.workspaceAccess, SessionsDirectory: recipe.sessionsDirectory,
		Executable: executable, RuntimeAuthority: recipe.runtimeAuthority, FilesystemGrants: filesystemGrants, ExecutableGrants: executableGrants, RequiresEnvironment: requiresEnvironment}); err != nil {
		return err, false
	}
	environment, err := resolvePlanEnvironment(recipe.resolvedPlan, e.environmentLookup)
	if err != nil {
		return err, false
	}
	releaseEnvironment := environment != nil
	defer func() {
		if releaseEnvironment {
			environment.Release()
		}
	}()
	target := "shell"
	if recipe.command != nil {
		target = "command"
	}
	created, err := session.CreateTracked(recipe.sessionsDirectory, recipe.workingDirectory, recipe.materializer, target)
	if err != nil {
		return err, false
	}
	defer func() {
		if removeErr := created.Remove(); removeErr != nil {
			resultErr = cleanupPrecedence(resultErr, removeErr)
			cleanupFailed = true
		}
	}()
	if recipe.command != nil {
		executable, arguments, err = recipe.command.Revalidate(created.WorkingDirectory())
		if err != nil {
			return err, false
		}
	}
	process, err := e.prepareRetainedProcess(ctx, created, launch.ProcessRequest{
		Workspace: created.WorkingDirectory(), WorkspaceAccess: recipe.workspaceAccess,
		SessionsDirectory: created.SessionsDirectory(), SessionDirectory: created.RootDirectory(),
		SessionHome: created.HomeDirectory(), TemporaryDirectory: created.TemporaryDirectory(),
		Executable: executable, Arguments: arguments, Terminal: recipe.terminal, RuntimeAuthority: recipe.runtimeAuthority,
		FilesystemGrants: filesystemGrants,
		ExecutableGrants: executableGrants,
		Environment:      environment,
	})
	if err != nil {
		return err, false
	}
	if releaseEnvironmentAfterCleanup(process, environment) {
		releaseEnvironment = false
	}
	runErr, cleanupErr := settleRetainedProcess(process, retainedAttached, nil)
	if cleanupErr != nil {
		return cleanupPrecedence(runErr, cleanupErr), true
	}
	return runErr, false
}

// RunCommand executes one literal argv through the same mandatory Session,
// sandbox, attachment, settlement, and cleanup lifecycle as fixed targets.
func (e *Executor) RunCommand(ctx context.Context, request CommandRequest) (exitCode int, resultErr error) {
	if e == nil || e.sandbox == nil {
		return 1, errors.New("contained command executor is unavailable")
	}
	if request.ResolvedPlan == nil || request.ResolvedPlan.Requirements().Recipe != authority.RecipeCommand {
		return 1, errors.New("resolved authority does not select the command execution recipe")
	}
	runErr, cleanupFailed := e.runAttached(ctx, attachedRecipe{
		sessionsDirectory: request.SessionsDirectory, workingDirectory: request.WorkingDirectory,
		workspaceAccess: request.ResolvedPlan.WorkspaceAccess(), materializer: *request.ResolvedPlan,
		command: &request.Command, terminal: request.Terminal, runtimeAuthority: request.ResolvedPlan.RuntimeAuthority(),
		resolvedPlan: request.ResolvedPlan,
	})
	if cleanupFailed {
		return 1, runErr
	}
	if ctx.Err() != nil {
		return 130, context.Canceled
	}
	if runErr == nil {
		return 0, nil
	}
	var exitError *exec.ExitError
	if errors.As(runErr, &exitError) {
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			code := 128 + int(status.Signal())
			return code, exitCodeError(code)
		}
		if code := exitError.ExitCode(); code >= 0 {
			return code, exitCodeError(code)
		}
	}
	return 1, runErr
}

// RunDevin performs the complete fixed Devin lifecycle. It captures signals
// before Check so a termination during either preflight cannot become an
// interactive launch, and it never permits a caller-owned Session lease.
func (e *Executor) RunDevin(ctx context.Context, request DevinRequest) (exitCode int, resultErr error) {
	if e == nil || e.sandbox == nil {
		return 1, errors.New("contained Devin executor is unavailable")
	}
	workspaceAccess, materializer, expectedCatalog, requirements := request.resolvedInputs()
	if requirements.Recipe != authority.RecipeDevin || !requirements.Semantics.Supports(authority.RecipeDevin) {
		return 1, errors.New("resolved authority does not select the Devin execution recipe")
	}
	request.WorkspaceAccess, request.Materializer, request.ExpectedCatalog = workspaceAccess, materializer, expectedCatalog
	if request.ResolvedPlan != nil {
		request.ExpectedInstructions = request.ResolvedPlan.DevinExpectedInstructions()
	}
	request.Executable, request.RuntimeInputs, request.ExistingHomeDirectory = requirements.Executable, requirements.RuntimeInputs, requirements.ExistingHomeDirectory
	if request.ResolvedPlan != nil {
		request.RuntimeAuthority = request.ResolvedPlan.RuntimeAuthority()
		var err error
		request.FilesystemGrants, err = request.ResolvedPlan.ResolveFilesystemGrantsForPreflight(request.WorkingDirectory, request.SessionsDirectory)
		if err == nil {
			request.ExecutableGrants, err = request.ResolvedPlan.ResolveExecutableGrants(request.WorkingDirectory, request.SessionsDirectory)
		}
		if err == nil && hasWritableFilesystemGrant(request.FilesystemGrants) {
			request.Executable, err = launch.ResolveExecutablePath(request.Executable)
		}
		if err == nil && hasWritableFilesystemGrant(request.FilesystemGrants) {
			request.FilesystemGrants, err = request.ResolvedPlan.ResolveFilesystemGrantsForExecutable(request.WorkingDirectory, request.SessionsDirectory, request.Executable)
		}
		if err != nil {
			return 1, &launch.SandboxError{Category: launch.SandboxUnsafePath}
		}
	}
	preflightContext, cancelPreflight := context.WithCancel(ctx)
	defer cancelPreflight()
	supervisor := newDevinSignalSupervisor(cancelPreflight)
	defer supervisor.stop()
	requiresEnvironment := request.ResolvedPlan != nil && len(request.ResolvedPlan.EnvironmentIntents()) != 0
	if err := e.sandbox.Check(preflightContext, launch.SandboxCheck{Workspace: request.WorkingDirectory, WorkspaceAccess: request.WorkspaceAccess, SessionsDirectory: request.SessionsDirectory, Executable: request.Executable, RuntimeInputs: request.RuntimeInputs, RuntimeAuthority: request.RuntimeAuthority, FilesystemGrants: request.FilesystemGrants, ExecutableGrants: request.ExecutableGrants, RequiresEnvironment: requiresEnvironment}); err != nil {
		return 1, err
	}
	environment, err := resolvePlanEnvironment(request.ResolvedPlan, e.environmentLookup)
	if err != nil {
		return 1, err
	}
	releaseEnvironment := environment != nil
	defer func() {
		if releaseEnvironment {
			environment.Release()
		}
	}()
	created, err := session.CreateTracked(request.SessionsDirectory, request.WorkingDirectory, request.Materializer, "devin")
	if err != nil {
		return 1, err
	}
	defer func() {
		if err := created.Remove(); err != nil {
			resultErr = cleanupPrecedence(resultErr, err)
			exitCode = 1
		}
	}()
	servers := []launch.MCPServerIntent{}
	environmentIntents := []launch.EnvironmentIntent{}
	if request.ResolvedPlan != nil {
		servers = request.ResolvedPlan.MCPServerIntents()
		environmentIntents = request.ResolvedPlan.EnvironmentIntents()
	}
	recipes, recipeDirectory, launcher, err := prepareMCPRecipes(created.HomeDirectory(), servers, request.ExecutableGrants, request.FilesystemGrants, environmentIntents)
	if err != nil {
		return 1, errors.New("selected MCP bindings could not be compiled")
	}
	if launcher == "" {
		launcher, err = os.Executable()
		if err == nil {
			launcher, err = filepath.EvalSymlinks(launcher)
		}
		if err != nil {
			return 1, errors.New("MCP target projection is unavailable")
		}
	}
	devinUserConfig, err := writeDevinUserConfig(created.HomeDirectory())
	if err != nil {
		return 1, err
	}
	selectedMCPConfig := ""
	if len(recipes) != 0 {
		selectedMCPConfig, err = writeDevinMCPConfig(created.HomeDirectory(), launcher, recipes)
		if err != nil {
			return 1, err
		}
	}
	request.selectedMCPConfig = selectedMCPConfig
	request.reserveMCPConfigNames = true
	request.sessionProtections = mcpSessionProtections(recipeDirectory, selectedMCPConfig)
	request.sessionProtections = append(request.sessionProtections, launch.SessionProtection{Path: devinUserConfig})
	if requirements.Semantics.CredentialProjection != "optional-allowlisted-value-omitted" {
		return 1, errors.New("resolved authority has unsupported Devin credential projection")
	}
	if err := copyDevinCredentialIfPresent(filepath.Join(request.ExistingHomeDirectory, ".local", "share", "devin", "credentials.toml"), filepath.Join(created.HomeDirectory(), ".local", "share", "devin", "credentials.toml")); err != nil {
		return 1, err
	}
	if err := e.runDevinPreflights(preflightContext, created, request, requirements.Semantics); err != nil {
		return 1, err
	}
	if preflightContext.Err() != nil {
		return 1, errors.New("Devin launch interrupted before the interactive process started")
	}
	process, err := e.prepareDevinInteractive(preflightContext, created, request, supervisor, environment)
	if err != nil {
		return 1, err
	}
	if releaseEnvironmentAfterCleanup(process, environment) {
		releaseEnvironment = false
	}
	runErr, cleanupErr := settleRetainedProcess(process, retainedDevinReserved, supervisor)
	if cleanupErr != nil {
		return 1, cleanupPrecedence(runErr, cleanupErr)
	}
	if runErr == nil {
		return 0, nil
	}
	if ctx.Err() != nil {
		return 1, fmt.Errorf("Devin launch interrupted: %w", ctx.Err())
	}
	if preflightContext.Err() != nil {
		return 1, errors.New("Devin launch interrupted before the interactive process started")
	}
	var exitError *exec.ExitError
	if errors.As(runErr, &exitError) {
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal()), exitCodeError(128 + int(status.Signal()))
		}
		if code := exitError.ExitCode(); code >= 0 {
			return code, exitCodeError(code)
		}
	}
	return 1, fmt.Errorf("start Devin: %w", runErr)
}

// VerifyDevin performs the registered Devin checks in a protected temporary
// Session without attaching the interactive target. It is the opt-in smoke
// entrypoint: callers provide declarative data, never a Session or process.
func (e *Executor) VerifyDevin(ctx context.Context, request DevinRequest) (resultErr error) {
	if e == nil || e.sandbox == nil {
		return errors.New("contained Devin executor is unavailable")
	}
	workspaceAccess, materializer, expectedCatalog, requirements := request.resolvedInputs()
	if requirements.Recipe != authority.RecipeDevin || !requirements.Semantics.Supports(authority.RecipeDevin) {
		return errors.New("resolved authority does not select the Devin execution recipe")
	}
	request.WorkspaceAccess, request.Materializer, request.ExpectedCatalog = workspaceAccess, materializer, expectedCatalog
	if request.ResolvedPlan != nil {
		request.ExpectedInstructions = request.ResolvedPlan.DevinExpectedInstructions()
	}
	request.Executable, request.RuntimeInputs, request.ExistingHomeDirectory = requirements.Executable, requirements.RuntimeInputs, requirements.ExistingHomeDirectory
	if request.ResolvedPlan != nil {
		request.RuntimeAuthority = request.ResolvedPlan.RuntimeAuthority()
		var err error
		request.FilesystemGrants, err = request.ResolvedPlan.ResolveFilesystemGrantsForPreflight(request.WorkingDirectory, request.SessionsDirectory)
		if err == nil {
			request.ExecutableGrants, err = request.ResolvedPlan.ResolveExecutableGrants(request.WorkingDirectory, request.SessionsDirectory)
		}
		if err == nil && hasWritableFilesystemGrant(request.FilesystemGrants) {
			request.Executable, err = launch.ResolveExecutablePath(request.Executable)
		}
		if err == nil && hasWritableFilesystemGrant(request.FilesystemGrants) {
			request.FilesystemGrants, err = request.ResolvedPlan.ResolveFilesystemGrantsForExecutable(request.WorkingDirectory, request.SessionsDirectory, request.Executable)
		}
		if err != nil {
			return &launch.SandboxError{Category: launch.SandboxUnsafePath}
		}
	}
	if err := e.sandbox.Check(ctx, launch.SandboxCheck{Workspace: request.WorkingDirectory, WorkspaceAccess: request.WorkspaceAccess, SessionsDirectory: request.SessionsDirectory, Executable: request.Executable, RuntimeInputs: request.RuntimeInputs, RuntimeAuthority: request.RuntimeAuthority, FilesystemGrants: request.FilesystemGrants, ExecutableGrants: request.ExecutableGrants}); err != nil {
		return err
	}
	// Verify runs value-free target preflights, but a required selected source
	// must still be available before the verification Session is created. The
	// short-lived validation lease is never attached to a probe generation.
	environment, err := resolvePlanEnvironment(request.ResolvedPlan, e.environmentLookup)
	if err != nil {
		return err
	}
	if environment != nil {
		environment.Release()
	}
	created, err := session.CreateTracked(request.SessionsDirectory, request.WorkingDirectory, request.Materializer, "devin")
	if err != nil {
		return err
	}
	defer func() {
		if removeErr := created.Remove(); removeErr != nil {
			resultErr = cleanupPrecedence(resultErr, removeErr)
		}
	}()
	servers := []launch.MCPServerIntent{}
	environmentIntents := []launch.EnvironmentIntent{}
	if request.ResolvedPlan != nil {
		servers = request.ResolvedPlan.MCPServerIntents()
		environmentIntents = request.ResolvedPlan.EnvironmentIntents()
	}
	recipes, recipeDirectory, launcher, err := prepareMCPRecipes(created.HomeDirectory(), servers, request.ExecutableGrants, request.FilesystemGrants, environmentIntents)
	if err != nil {
		return errors.New("selected MCP bindings could not be compiled")
	}
	if launcher == "" {
		launcher, err = os.Executable()
		if err == nil {
			launcher, err = filepath.EvalSymlinks(launcher)
		}
		if err != nil {
			return errors.New("MCP target projection is unavailable")
		}
	}
	devinUserConfig, err := writeDevinUserConfig(created.HomeDirectory())
	if err != nil {
		return err
	}
	selectedMCPConfig := ""
	if len(recipes) != 0 {
		selectedMCPConfig, err = writeDevinMCPConfig(created.HomeDirectory(), launcher, recipes)
		if err != nil {
			return err
		}
	}
	request.selectedMCPConfig = selectedMCPConfig
	request.reserveMCPConfigNames = true
	request.sessionProtections = mcpSessionProtections(recipeDirectory, selectedMCPConfig)
	request.sessionProtections = append(request.sessionProtections, launch.SessionProtection{Path: devinUserConfig})
	if requirements.Semantics.CredentialProjection != "optional-allowlisted-value-omitted" {
		return errors.New("resolved authority has unsupported Devin credential projection")
	}
	if err := copyDevinCredentialIfPresent(filepath.Join(request.ExistingHomeDirectory, ".local", "share", "devin", "credentials.toml"), filepath.Join(created.HomeDirectory(), ".local", "share", "devin", "credentials.toml")); err != nil {
		return err
	}
	return e.runDevinPreflights(ctx, created, request, requirements.Semantics)
}

func (e *Executor) runDevinPreflights(ctx context.Context, created *session.Session, request DevinRequest, semantics authority.TargetSemantics) error {
	var instructionAnchor *projectedInstructionAnchor
	if len(request.ExpectedInstructions) > 0 {
		var err error
		instructionAnchor, err = openProjectedInstructionAnchor(created.HomeDirectory())
		if err != nil {
			return devinruntime.NewPreflightError(devinruntime.CapabilityInstructionRules, devinruntime.ReasonRuleMismatch)
		}
		defer instructionAnchor.Close()
	}
	for _, preflight := range semantics.Preflights {
		var err error
		if instructionAnchor != nil {
			if err := instructionAnchor.checkPathIdentity(); err != nil {
				return devinruntime.NewPreflightError(devinruntime.CapabilityInstructionRules, devinruntime.ReasonRuleMismatch)
			}
		}
		switch preflight.ID {
		case "devin.preflight.skills":
			if preflight.Mode != "contained-exact-catalog" {
				return errors.New("unsupported Devin Skill preflight")
			}
			err = e.verifyDevinSkills(ctx, created, request)
		case "devin.preflight.authentication":
			if preflight.Mode != "contained-status" {
				return errors.New("unsupported Devin authentication preflight")
			}
			err = e.verifyDevinAuthentication(ctx, created, request)
		case "devin.preflight.rules":
			if preflight.Mode != "contained-selected-rules" {
				return errors.New("unsupported Devin instruction rules preflight")
			}
			if len(request.ExpectedInstructions) == 0 {
				continue
			}
			err = e.verifyDevinRules(ctx, created, request, instructionAnchor)
		default:
			return errors.New("unsupported Devin preflight")
		}
		if err != nil {
			return err
		}
		if instructionAnchor != nil {
			if err := instructionAnchor.checkPathIdentity(); err != nil {
				return devinruntime.NewPreflightError(devinruntime.CapabilityInstructionRules, devinruntime.ReasonRuleMismatch)
			}
		}
	}
	return nil
}

func (e *Executor) verifyDevinRules(ctx context.Context, created *session.Session, request DevinRequest, anchor *projectedInstructionAnchor) error {
	if anchor == nil || anchor.checkPathIdentity() != nil {
		return devinruntime.NewPreflightError(devinruntime.CapabilityInstructionRules, devinruntime.ReasonRuleMismatch)
	}
	output, err := e.runDevinProbe(ctx, created, request, []string{"rules", "list"})
	if err != nil {
		return devinPreflightFailure(ctx, err, devinruntime.CapabilityInstructionRules, devinruntime.ReasonRuleInspectionCommandFailed)
	}
	if anchor.checkPathIdentity() != nil {
		return devinruntime.NewPreflightError(devinruntime.CapabilityInstructionRules, devinruntime.ReasonRuleMismatch)
	}
	for _, bundle := range request.ExpectedInstructions {
		name := instructions.DestinationName(bundle.Reference)
		showName := strings.TrimSuffix(name, ".md")
		if !listedRuleIsUniqueAlwaysOn(output, showName) {
			return devinruntime.NewPreflightError(devinruntime.CapabilityInstructionRules, devinruntime.ReasonRuleMismatch)
		}
		observed, probeErr := e.runDevinProbe(ctx, created, request, []string{"rules", "show", showName})
		if probeErr != nil {
			return devinPreflightFailure(ctx, probeErr, devinruntime.CapabilityInstructionRules, devinruntime.ReasonRuleInspectionCommandFailed)
		}
		if anchor.checkPathIdentity() != nil {
			return devinruntime.NewPreflightError(devinruntime.CapabilityInstructionRules, devinruntime.ReasonRuleMismatch)
		}
		path := filepath.Join(anchor.sessionHome, ".devin", "rules", name)
		materialized, readErr := readProjectedInstruction(anchor, path, len("---\ntrigger: always_on\n---\n")+len(bundle.Content))
		anchorErr := anchor.checkPathIdentity()
		expected := append([]byte("---\ntrigger: always_on\n---\n"), bundle.Content...)
		receipt, ok := parseDevinRuleReceipt(observed)
		projectedPath := filepath.Join(anchor.canonicalHome, ".devin", "rules", name)
		if readErr != nil || anchorErr != nil || !bytes.Equal(materialized, expected) || !ok || receipt.Name != showName || receipt.Provider != "Devin" || receipt.Path != projectedPath || receipt.Activation != "always-on" || !displayedInstructionMatches(receipt.Content, bundle.Content) {
			return devinruntime.NewPreflightError(devinruntime.CapabilityInstructionRules, devinruntime.ReasonRuleMismatch)
		}
	}
	return nil
}

type devinRuleReceipt struct {
	Name, Path, Provider, Activation string
	Content                          []byte
}

func listedRuleIsUniqueAlwaysOn(output []byte, wanted string) bool {
	matches := 0
	valid := false
	for _, raw := range bytes.Split(output, []byte{'\n'}) {
		line := strings.TrimSpace(strings.TrimSuffix(string(raw), "\r"))
		open := strings.LastIndex(line, " [")
		if open <= 0 {
			if strings.Contains(line, wanted) {
				return false
			}
			continue
		}
		close := strings.Index(line[open+2:], "] ")
		if close < 0 {
			if strings.Contains(line, wanted) {
				return false
			}
			continue
		}
		close += open + 2
		name, provider, activation := line[:open], line[open+2:close], strings.TrimSpace(line[close+2:])
		if name != wanted {
			if strings.Contains(name, wanted) {
				return false
			}
			continue
		}
		matches++
		valid = provider == "Devin" && activation == "always-on"
	}
	return matches == 1 && valid
}

func parseDevinRuleReceipt(output []byte) (devinRuleReceipt, bool) {
	var receipt devinRuleReceipt
	separator := []byte("\nContent:\n")
	contentAt := bytes.Index(output, separator)
	if contentAt < 0 {
		separator = []byte("\r\nContent:\r\n")
		contentAt = bytes.Index(output, separator)
	}
	if contentAt < 0 {
		return receipt, false
	}
	header := output[:contentAt]
	seen := map[string]bool{}
	for _, raw := range bytes.Split(header, []byte{'\n'}) {
		line := strings.TrimSpace(strings.TrimSuffix(string(raw), "\r"))
		recognized := false
		for _, field := range []string{"Rule", "Path", "Provider", "Activation"} {
			prefix := field + ":"
			if !strings.HasPrefix(line, prefix) {
				continue
			}
			recognized = true
			if seen[field] {
				return devinRuleReceipt{}, false
			}
			seen[field] = true
			value := strings.TrimSpace(strings.TrimPrefix(line, prefix))
			if field == "Path" {
				decoded, err := strconv.Unquote(value)
				if err != nil {
					return devinRuleReceipt{}, false
				}
				value = decoded
			}
			switch field {
			case "Rule":
				receipt.Name = value
			case "Path":
				receipt.Path = value
			case "Provider":
				receipt.Provider = value
			case "Activation":
				receipt.Activation = value
			}
		}
		if line != "" && !recognized {
			return devinRuleReceipt{}, false
		}
	}
	if len(seen) != 4 {
		return devinRuleReceipt{}, false
	}
	content := output[contentAt+len(separator):]
	framePrefix := []byte(devinRuleSeparator + "\n")
	frameSuffix := []byte("\n" + devinRuleSeparator + "\n")
	if len(content) < len(framePrefix)+len(frameSuffix) || !bytes.HasPrefix(content, framePrefix) || !bytes.HasSuffix(content, frameSuffix) {
		return devinRuleReceipt{}, false
	}
	receipt.Content = append([]byte(nil), content[len(framePrefix):len(content)-len(frameSuffix)]...)
	receipt.Content = append(receipt.Content, '\n')
	return receipt, true
}

func isRuleSeparator(line []byte) bool {
	return bytes.Equal(bytes.TrimSuffix(line, []byte("\r")), []byte(devinRuleSeparator))
}

func displayedInstructionMatches(rendered, body []byte) bool {
	// Pinned CLI corpus: rules show uses Go strings.TrimSpace(source) plus a
	// final display newline; this does not alter independently checked file bytes.
	want := []byte(strings.TrimSpace(string(body)) + "\n")
	return bytes.Equal(rendered, want)
}

type projectedInstructionAnchor struct {
	sessionHome   string
	canonicalHome string
	fd            int
}

func openProjectedInstructionAnchor(sessionHome string) (*projectedInstructionAnchor, error) {
	if !filepath.IsAbs(sessionHome) {
		return nil, errors.New("invalid projected instruction Session home")
	}
	// Session homes are ACS-owned trusted anchors. Resolve aliases such as
	// macOS /var and /tmp only at this boundary, before any Devin probe.
	canonicalHome, err := filepath.EvalSymlinks(sessionHome)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(canonicalHome, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	anchor := &projectedInstructionAnchor{sessionHome: filepath.Clean(sessionHome), canonicalHome: filepath.Clean(canonicalHome), fd: fd}
	if err := anchor.checkPathIdentity(); err != nil {
		_ = anchor.Close()
		return nil, err
	}
	return anchor, nil
}

func (anchor *projectedInstructionAnchor) checkPathIdentity() error {
	if anchor == nil || anchor.fd < 0 {
		return errors.New("closed projected instruction anchor")
	}
	var fdStat unix.Stat_t
	if err := unix.Fstat(anchor.fd, &fdStat); err != nil {
		return err
	}
	for _, path := range []string{anchor.sessionHome, anchor.canonicalHome} {
		var pathStat unix.Stat_t
		if err := unix.Stat(path, &pathStat); err != nil {
			return err
		}
		if pathStat.Dev != fdStat.Dev || pathStat.Ino != fdStat.Ino || pathStat.Mode&unix.S_IFMT != fdStat.Mode&unix.S_IFMT {
			return errors.New("Session home no longer names the anchored directory")
		}
	}
	return nil
}

func (anchor *projectedInstructionAnchor) Close() error {
	if anchor == nil || anchor.fd < 0 {
		return nil
	}
	err := unix.Close(anchor.fd)
	anchor.fd = -1
	return err
}

func readProjectedInstruction(anchor *projectedInstructionAnchor, path string, limit int) ([]byte, error) {
	if anchor == nil || anchor.fd < 0 || limit < 0 || !filepath.IsAbs(path) {
		return nil, errors.New("invalid projected instruction path")
	}
	relative, err := filepath.Rel(anchor.sessionHome, filepath.Clean(path))
	if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("projected instruction is outside its Session home")
	}
	components := strings.Split(relative, string(filepath.Separator))
	if len(components) != 3 || components[0] != ".devin" || components[1] != "rules" || components[2] == "" || components[2] == "." || components[2] == ".." {
		return nil, errors.New("invalid projected instruction location")
	}
	directoryFD, err := unix.FcntlInt(uintptr(anchor.fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(directoryFD) }()
	for _, component := range components[:2] {
		nextFD, openErr := unix.Openat(directoryFD, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		if openErr != nil {
			return nil, openErr
		}
		_ = unix.Close(directoryFD)
		directoryFD = nextFD
	}
	fd, err := unix.Openat(directoryFD, components[2], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("open projected instruction")
	}
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() > int64(limit) {
		_ = file.Close()
		return nil, errors.New("projected instruction is not a bounded regular file")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	after, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || len(data) > limit || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || before.Mode() != after.Mode() {
		return nil, errors.New("projected instruction changed during inspection")
	}
	return data, nil
}

// DevinExit is intentionally small: the adapter translates it to its stable
// public compatibility error without exposing process details.
type DevinExit interface {
	error
	ExitCode() int
}
type exitCodeError int

func (e exitCodeError) Error() string { return "Devin exited" }
func (e exitCodeError) ExitCode() int { return int(e) }

func (e *Executor) verifyDevinSkills(ctx context.Context, created *session.Session, request DevinRequest) error {
	output, err := e.runDevinProbe(ctx, created, request, []string{"skills", "list", "--json"})
	if err != nil {
		return devinPreflightFailure(ctx, err, devinruntime.CapabilitySkillIsolation, devinruntime.ReasonSkillInspectionCommandFailed)
	}
	observed, failure := devinruntime.InterpretCatalog(created.HomeDirectory(), created.WorkingDirectory(), output)
	if failure != 0 {
		return devinruntime.NewPreflightError(devinruntime.CapabilitySkillIsolation, failure)
	}
	expected := append([]skills.SkillReference(nil), request.ExpectedCatalog...)
	devinruntime.SortSkillReferences(expected)
	if observed.HasUnmanagedSource() || !devinruntime.EqualSkillReferences(expected, observed.ManagedReferences()) {
		return devinruntime.NewPreflightError(devinruntime.CapabilitySkillIsolation, devinruntime.ReasonCatalogMismatch)
	}
	return nil
}

func (e *Executor) verifyDevinAuthentication(ctx context.Context, created *session.Session, request DevinRequest) error {
	output, err := e.runDevinProbe(ctx, created, request, []string{"auth", "status"})
	if err != nil {
		return devinPreflightFailure(ctx, err, devinruntime.CapabilityAuthentication, devinruntime.ReasonAuthenticationCommandFailed)
	}
	if !devinruntime.AuthenticationLoggedIn(output) {
		return devinruntime.NewPreflightError(devinruntime.CapabilityAuthentication, devinruntime.ReasonAuthenticationUnavailable)
	}
	return nil
}

func devinPreflightFailure(ctx context.Context, err error, capability devinruntime.Capability, fallback devinruntime.PreflightFailureReason) error {
	var sandboxFailure *launch.SandboxError
	if errors.As(err, &sandboxFailure) {
		return err
	}
	if ctx.Err() != nil {
		return devinruntime.NewPreflightError(capability, devinruntime.ReasonVerificationInterrupted)
	}
	var executableError *exec.Error
	if errors.As(err, &executableError) || errors.Is(err, os.ErrNotExist) {
		return devinruntime.NewPreflightError(capability, devinruntime.ReasonExecutableUnavailable)
	}
	return devinruntime.NewPreflightError(capability, fallback)
}

func (e *Executor) runDevinProbe(ctx context.Context, created *session.Session, request DevinRequest, arguments []string) ([]byte, error) {
	output := &boundedProbeOutput{limit: maxDevinProbeOutput}
	process, err := e.prepareDevin(ctx, created, request, arguments, launch.Terminal{Output: output, ErrorOutput: io.Discard})
	if err != nil {
		return nil, err
	}
	runErr, cleanupErr := settleRetainedProcess(process, retainedProbe, nil)
	if cleanupErr != nil {
		// A probe cannot safely advance while its retained tree is uncertain;
		// cleanup proof therefore outranks every probe outcome.
		return nil, cleanupErr
	}
	if runErr != nil {
		return nil, runErr
	}
	if output.exceeded {
		return nil, errDevinProbeOutputLimit
	}
	return append([]byte(nil), output.buffer.Bytes()...), nil
}

type boundedProbeOutput struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (output *boundedProbeOutput) Write(value []byte) (int, error) {
	remaining := output.limit - output.buffer.Len()
	if remaining <= 0 {
		output.exceeded = true
		return len(value), nil
	}
	if len(value) > remaining {
		_, _ = output.buffer.Write(value[:remaining])
		output.exceeded = true
		return len(value), nil
	}
	return output.buffer.Write(value)
}

func (e *Executor) prepareDevin(ctx context.Context, created *session.Session, request DevinRequest, arguments []string, terminal launch.Terminal, selected ...*environmentresource.Lease) (launch.Process, error) {
	var environment *environmentresource.Lease
	if len(selected) != 0 {
		environment = selected[0]
	}
	return e.prepareRetainedProcess(ctx, created, launch.ProcessRequest{Workspace: created.WorkingDirectory(), WorkspaceAccess: request.WorkspaceAccess, SessionsDirectory: created.SessionsDirectory(), SessionDirectory: created.RootDirectory(), SessionHome: created.HomeDirectory(), TemporaryDirectory: created.TemporaryDirectory(), Executable: request.Executable, RuntimeInputs: request.RuntimeInputs, Arguments: arguments, Terminal: terminal, RuntimeAuthority: request.RuntimeAuthority, FilesystemGrants: request.FilesystemGrants, ExecutableGrants: request.ExecutableGrants, SessionProtections: request.sessionProtections, SelectedMCPConfig: request.selectedMCPConfig, ReserveMCPConfigNames: request.reserveMCPConfigNames, Environment: environment})
}

// prepareDevinInteractive commits the handoff before a process reference can
// retain its Session. Signals after that commitment are queued for replay once
// the prepared target has started; a failed preparation ends the commitment
// without starting a target.
func (e *Executor) prepareDevinInteractive(ctx context.Context, created *session.Session, request DevinRequest, supervisor *devinSignalSupervisor, selected ...*environmentresource.Lease) (launch.Process, error) {
	if err := supervisor.reserveInteractive(); err != nil {
		return nil, err
	}
	process, err := e.prepareDevin(ctx, created, request, []string{"--respect-workspace-trust", "false"}, request.Terminal, selected...)
	if err != nil {
		supervisor.cancelInteractiveReservation()
		return nil, err
	}
	return process, nil
}

func copyDevinCredentialIfPresent(source, destination string) error {
	info, err := os.Stat(source)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return errors.New("allowlisted credentials could not be inspected safely")
	}
	if !info.Mode().IsRegular() {
		return errors.New("allowlisted credentials path is not a regular file")
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return errors.New("allowlisted credentials could not be copied safely")
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("allowlisted credentials could not be copied safely")
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(destination)
		return errors.New("allowlisted credentials could not be copied safely")
	}
	return os.Chmod(destination, 0o600)
}

func cleanupPrecedence(outcome, cleanup error) error {
	if outcome == nil {
		return cleanup
	}
	var targetExit *exec.ExitError
	var exitCoder interface{ ExitCode() int }
	if errors.As(outcome, &targetExit) || errors.As(outcome, &exitCoder) {
		return cleanup
	}
	return errors.Join(outcome, cleanup)
}

type devinSignalSupervisor struct {
	forwarded       chan os.Signal
	done            chan struct{}
	cancelPreflight context.CancelFunc
	mutex           sync.Mutex
	child           launch.Process
	pending         os.Signal
	starting        bool
}

func newDevinSignalSupervisor(cancel context.CancelFunc) *devinSignalSupervisor {
	s := &devinSignalSupervisor{forwarded: make(chan os.Signal, 1), done: make(chan struct{}), cancelPreflight: cancel}
	signal.Notify(s.forwarded, os.Interrupt, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGWINCH)
	go s.run()
	return s
}
func (s *devinSignalSupervisor) run() {
	for {
		select {
		case received := <-s.forwarded:
			s.handleSignal(received)
		case <-s.done:
			return
		}
	}
}

func (s *devinSignalSupervisor) handleSignal(received os.Signal) {
	s.mutex.Lock()
	child := s.child
	if child == nil {
		if s.starting {
			// Resize notifications may coalesce, but must never erase a
			// termination already accepted during interactive preparation.
			if s.pending == nil || received != syscall.SIGWINCH {
				s.pending = received
			}
			s.mutex.Unlock()
			return
		}
		if received != syscall.SIGWINCH {
			s.pending = received
			s.cancelPreflight()
		}
		s.mutex.Unlock()
		return
	}
	s.mutex.Unlock()
	_ = child.Signal(received)
}
func (s *devinSignalSupervisor) start(child launch.Process) (bool, error) {
	if err := s.reserveInteractive(); err != nil {
		return false, err
	}
	return s.startReserved(child)
}

// reserveInteractive makes a completed preflight's interactive start
// inevitable if preparation succeeds. It is deliberately private: only the
// executor may make this lifecycle commitment.
func (s *devinSignalSupervisor) reserveInteractive() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if s.pending != nil {
		return errors.New("Devin launch interrupted before the interactive process started")
	}
	s.starting = true
	return nil
}

func (s *devinSignalSupervisor) cancelInteractiveReservation() {
	s.mutex.Lock()
	s.starting = false
	s.mutex.Unlock()
}

func (s *devinSignalSupervisor) startReserved(child launch.Process) (bool, error) {
	err := child.Start()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.starting = false
	if err != nil {
		return false, err
	}
	s.child = child
	pending := s.pending
	s.pending = nil
	if pending == nil {
		return true, nil
	}
	s.mutex.Unlock()
	err = child.Signal(pending)
	s.mutex.Lock()
	if err != nil {
		return true, &launch.SandboxError{Category: launch.SandboxProcessStartFailed}
	}
	return true, nil
}
func (s *devinSignalSupervisor) detach() { s.mutex.Lock(); defer s.mutex.Unlock(); s.child = nil }
func (s *devinSignalSupervisor) stop()   { signal.Stop(s.forwarded); close(s.done) }
func runDevinAttached(process launch.Process, supervisor *devinSignalSupervisor) error {
	started, startErr := supervisor.start(process)
	return runDevinStarted(process, supervisor, started, startErr)
}
func runDevinAttachedReserved(process launch.Process, supervisor *devinSignalSupervisor) error {
	started, startErr := supervisor.startReserved(process)
	return runDevinStarted(process, supervisor, started, startErr)
}
func runDevinStarted(process launch.Process, supervisor *devinSignalSupervisor, started bool, startErr error) error {
	if !started {
		return startErr
	}
	defer supervisor.detach()
	waitErr := process.Wait()
	if startErr == nil {
		return waitErr
	}
	if waitErr == nil {
		return startErr
	}
	return errors.Join(startErr, &launch.SandboxError{Category: launch.SandboxProcessWaitFailed})
}
