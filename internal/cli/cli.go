// Package cli implements the public ACS command-line interface.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/codexauth"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
	"github.com/charmbracelet/x/term"
)

type ProfileDraftEditor interface {
	EditProfileDraft(context.Context, category.Draft, io.Reader, io.Writer) (category.Draft, error)
}

// ProfileBuilder owns the terminal UI and returns its post-terminal outcome.
type ProfileBuilder interface {
	BuildProfile(context.Context, string, category.Draft, builder.SaveFunc, io.Reader, io.Writer) (builder.Outcome, error)
}

type ProfileStore interface {
	Create(profile.Profile) (string, error)
	CreateContext(context.Context, profile.Profile) (string, error)
	Load(string) (profile.Profile, error)
}

type LaunchPlanner interface {
	PlanLaunch(context.Context, string, category.ResolvedProfile) (launch.Plan, error)
}

type ProfileLauncher interface {
	Launch(context.Context, string, string, category.ResolvedProfile, launch.Terminal) (int, error)
}

type CodexAuthRegistry interface {
	Login(context.Context, codexauth.LoginRequest) (codexauth.IdentityMetadata, error)
	List(context.Context) ([]codexauth.IdentityMetadata, error)
	Logout(context.Context, string) error
	Status(context.Context, string) (codexauth.IdentityStatus, error)
	Recover(context.Context, string) (codexauth.BindingDisposition, error)
}

type exitCodeError interface {
	error
	ExitCode() int
}

type ProfileInspector interface {
	List() profileinspect.Result
	Show(string) profileinspect.Result
}

type App struct {
	Inspector         ProfileInspector
	Version           string
	Categories        *category.Registry
	Builder           ProfileBuilder
	DraftEditor       ProfileDraftEditor
	Planner           LaunchPlanner
	Launcher          ProfileLauncher
	SandboxPlanner    LaunchPlanner
	SandboxLauncher   ProfileLauncher
	CodexAuth         CodexAuthRegistry
	Profiles          ProfileStore
	SessionsDirectory string
	WorkingDirectory  string
	Input             io.Reader
	Output            io.Writer
	ErrorOutput       io.Writer
	Interactive       func(io.Reader, io.Writer) bool
}

// StandardStreamsInteractive reports whether both endpoints are actual
// terminals. Callers can inject a narrower capability check in tests.
func StandardStreamsInteractive(input io.Reader, output io.Writer) bool {
	inputFile, inputIsFile := input.(*os.File)
	outputFile, outputIsFile := output.(*os.File)
	if !inputIsFile || !outputIsFile {
		return false
	}
	return term.IsTerminal(inputFile.Fd()) && term.IsTerminal(outputFile.Fd())
}

func (app App) Run(ctx context.Context, args []string) int {
	if handled, code := app.RunInformational(args); handled {
		return code
	}
	if handled, code := app.RunDiagnostics(args, os.UserHomeDir); handled {
		return code
	}
	inv, _ := parseCommand(args)
	switch inv.command.path {
	case "profile list", "profile show":
		return app.inspectProfiles(inv)
	case "devin create-profile":
		return app.createProfile(ctx, inv.value)
	case "devin":
		if inv.enabled {
			return app.dryRun(ctx, inv.value, app.Planner, "No Session was created and Devin was not started.")
		}
		return app.launchProfile(ctx, inv.value, app.Launcher, "launch")
	case "sandbox":
		if inv.enabled {
			return app.dryRun(ctx, inv.value, app.SandboxPlanner, "No Session was created and no sandbox shell was started.")
		}
		return app.launchProfile(ctx, inv.value, app.SandboxLauncher, "launch sandbox")
	case "codex auth login":
		return app.loginCodexAuth(ctx, inv.value, inv.enabled)
	case "codex auth list":
		return app.listCodexAuth(ctx)
	case "codex auth logout":
		return app.logoutCodexAuth(ctx, inv.value)
	case "codex auth status":
		return app.statusCodexAuth(ctx, inv.value)
	case "codex auth recover":
		return app.recoverCodexAuth(ctx, inv.value)
	}
	return app.fail("unavailable command; try acs help")
}

func (app App) loginCodexAuth(ctx context.Context, name string, deviceAuth bool) int {
	if app.CodexAuth == nil {
		return app.fail("Codex authentication is unavailable")
	}
	if app.Interactive == nil || !app.Interactive(app.Input, app.Output) {
		return app.fail("Codex authentication login requires interactive stdin and stdout")
	}
	metadata, err := app.CodexAuth.Login(ctx, codexauth.LoginRequest{
		Name: name, DeviceAuth: deviceAuth,
		Terminal: launch.Terminal{Input: app.Input, Output: app.Output, ErrorOutput: app.ErrorOutput},
	})
	if err != nil {
		return app.fail("login Codex authentication identity %q: %v", name, err)
	}
	fmt.Fprintf(app.Output, "\nStored Codex authentication identity %q.\n", safeTerminalText(string(metadata.Name)))
	return 0
}

func (app App) listCodexAuth(ctx context.Context) int {
	if app.CodexAuth == nil {
		return app.fail("Codex authentication is unavailable")
	}
	identities, err := app.CodexAuth.List(ctx)
	if err != nil {
		return app.fail("%v", err)
	}
	fmt.Fprintln(app.Output, "Codex authentication identities:")
	if len(identities) == 0 {
		fmt.Fprintln(app.Output, "  (none)")
		return 0
	}
	for _, identity := range identities {
		fmt.Fprintf(app.Output, "  %s\n", safeTerminalText(string(identity.Name)))
		fmt.Fprintf(app.Output, "    method: %s\n", safeTerminalText(string(identity.Method)))
		workspace := identity.Workspace
		if workspace == "" {
			workspace = "(none)"
		}
		fmt.Fprintf(app.Output, "    workspace: %s\n", safeTerminalText(workspace))
	}
	return 0
}

func (app App) logoutCodexAuth(ctx context.Context, name string) int {
	if app.CodexAuth == nil {
		return app.fail("Codex authentication is unavailable")
	}
	if err := app.CodexAuth.Logout(ctx, name); err != nil {
		return app.fail("logout Codex authentication identity %q: %v", name, err)
	}
	fmt.Fprintf(app.Output, "Removed Codex authentication identity %q if it existed.\n", safeTerminalText(name))
	return 0
}

func (app App) statusCodexAuth(ctx context.Context, name string) int {
	if app.CodexAuth == nil {
		return app.fail("Codex authentication is unavailable")
	}
	status, err := app.CodexAuth.Status(ctx, name)
	if err != nil {
		return app.fail("check Codex authentication identity %q: %v", name, err)
	}
	fmt.Fprintf(app.Output, "Codex authentication identity %q is authenticated.\n", safeTerminalText(string(status.Metadata.Name)))
	fmt.Fprintf(app.Output, "  method: %s\n", safeTerminalText(string(status.Metadata.Method)))
	workspace := status.Metadata.Workspace
	if workspace == "" {
		workspace = "(none)"
	}
	fmt.Fprintf(app.Output, "  workspace: %s\n", safeTerminalText(workspace))
	fmt.Fprintf(app.Output, "  disposition: %s\n", safeTerminalText(string(status.Disposition)))
	return 0
}

func (app App) recoverCodexAuth(ctx context.Context, name string) int {
	if app.CodexAuth == nil {
		return app.fail("Codex authentication is unavailable")
	}
	disposition, err := app.CodexAuth.Recover(ctx, name)
	if err != nil {
		return app.fail("recover Codex authentication identity %q: %v", name, err)
	}
	fmt.Fprintf(app.Output, "Recovered Codex authentication identity %q.\n", safeTerminalText(name))
	fmt.Fprintf(app.Output, "  disposition: %s\n", safeTerminalText(string(disposition)))
	return 0
}

func (app App) createProfile(ctx context.Context, name string) int {
	if err := profile.ValidateName(name); err != nil {
		return app.fail("%v", err)
	}
	if _, err := app.Profiles.Load(name); err == nil {
		return app.fail("create Profile %q: %v: %q", name, profile.ErrProfileExists, name)
	} else if !errors.Is(err, os.ErrNotExist) {
		return app.fail("check Profile %q: %v", name, err)
	}

	draft := app.Categories.NewDraft()
	if app.Builder != nil {
		if app.Interactive == nil || !app.Interactive(app.Input, app.Output) {
			return app.fail("create Profile requires interactive stdin and stdout")
		}
		save := func(saveContext context.Context, snapshot category.Draft) (string, error) {
			created, err := app.Categories.NewProfile(name, snapshot)
			if err != nil {
				return "", fmt.Errorf("build Profile %q: %w", name, err)
			}
			path, err := app.Profiles.CreateContext(saveContext, created)
			if err != nil {
				return "", fmt.Errorf("create Profile %q: %w", created.Name, err)
			}
			return path, nil
		}
		outcome, err := app.Builder.BuildProfile(ctx, name, draft, save, app.Input, app.Output)
		if err != nil {
			return app.fail("edit Profile %q: %v", name, err)
		}
		if outcome.Cancelled {
			fmt.Fprintln(app.Output, "Profile creation cancelled.")
			return 130
		}
		if !outcome.Create {
			return app.fail("edit Profile %q: Profile Builder ended without an outcome", name)
		}
		draft = outcome.Draft
		fmt.Fprintf(app.Output, "\nCreated Profile %q at %s\n", name, safeTerminalText(outcome.Path))
		for _, summary := range draft.Summaries() {
			fmt.Fprintf(app.Output, "  %s: %d selected\n", safeTerminalText(summary.ID), summary.Count)
		}
		return 0
	} else {
		fmt.Fprintf(app.Output, "Create Profile %q\n\n", name)
		edited, err := app.DraftEditor.EditProfileDraft(ctx, draft, app.Input, app.Output)
		if err != nil {
			return app.fail("edit Profile %q: %v", name, err)
		}
		draft = edited
	}
	created, err := app.Categories.NewProfile(name, draft)
	if err != nil {
		return app.fail("build Profile %q: %v", name, err)
	}
	path, err := app.Profiles.Create(created)
	if err != nil {
		return app.fail("create Profile %q: %v", created.Name, err)
	}
	fmt.Fprintf(app.Output, "\nCreated Profile %q at %s\n", created.Name, safeTerminalText(path))
	for _, summary := range draft.Summaries() {
		fmt.Fprintf(app.Output, "  %s: %d selected\n", safeTerminalText(summary.ID), summary.Count)
	}
	return 0
}

func (app App) dryRun(ctx context.Context, name string, planner LaunchPlanner, closingMessage string) int {
	resolved, err := app.resolveProfile(ctx, name)
	if err != nil {
		return app.fail("%v", err)
	}
	plan, err := planner.PlanLaunch(ctx, app.WorkingDirectory, resolved)
	if err != nil {
		return app.fail("plan Profile %q launch: %v", name, err)
	}

	fmt.Fprintf(app.Output, "Dry run for Profile %q\n", name)
	for _, section := range plan.Sections {
		fmt.Fprintln(app.Output, "\n"+safeTerminalText(section.Title))
		if len(section.Items) == 0 {
			fmt.Fprintln(app.Output, "  (none)")
		}
		for _, item := range section.Items {
			fmt.Fprintf(app.Output, "  %s\n", safeTerminalText(item.Label))
			for _, detail := range item.Details {
				fmt.Fprintf(app.Output, "    %s: %s\n", safeTerminalText(detail.Label), safeTerminalText(detail.Value))
			}
		}
	}
	fmt.Fprintln(app.Output, "\n"+closingMessage)
	return 0
}

func (app App) launchProfile(ctx context.Context, name string, launcher ProfileLauncher, action string) int {
	resolved, err := app.resolveProfile(ctx, name)
	if err != nil {
		return app.fail("%v", err)
	}
	exitCode, err := launcher.Launch(
		ctx,
		app.SessionsDirectory,
		app.WorkingDirectory,
		resolved,
		launch.Terminal{Input: app.Input, Output: app.Output, ErrorOutput: app.ErrorOutput},
	)
	if err != nil {
		var targetExit exitCodeError
		if errors.As(err, &targetExit) {
			return targetExit.ExitCode()
		}
		return app.fail("%s Profile %q: %v", action, name, err)
	}
	return exitCode
}

func (app App) resolveProfile(ctx context.Context, name string) (category.ResolvedProfile, error) {
	if err := profile.ValidateName(name); err != nil {
		return category.ResolvedProfile{}, err
	}
	loaded, err := app.Profiles.Load(name)
	if err != nil {
		return category.ResolvedProfile{}, fmt.Errorf("load Profile %q: %w", name, err)
	}
	resolved, err := app.Categories.Resolve(ctx, loaded)
	if err != nil {
		return category.ResolvedProfile{}, fmt.Errorf("resolve Profile %q: %w", name, err)
	}
	return resolved, nil
}

func (app App) fail(format string, arguments ...any) int {
	fmt.Fprintf(app.ErrorOutput, "acs: "+format+"\n", arguments...)
	return 1
}

func safeTerminalText(value string) string {
	quoted := strconv.QuoteToASCII(value)
	return quoted[1 : len(quoted)-1]
}
