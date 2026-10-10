package launch

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/codexcompat"
	"github.com/alcimerio/ai-config-selector/internal/environmentresource"
	"github.com/alcimerio/ai-config-selector/internal/linuxprobe"
)

type linuxRecipeKind uint8

const (
	linuxShellRecipe linuxRecipeKind = iota + 1
	linuxCommandRecipe
	linuxDevinRecipe
	linuxCodexRecipe
)

// The zero value refuses admission. Only tests opt in: no registered backend,
// environment variable, command-line flag, or production re-exec entry exists.
type linuxRecipeAdmission struct{ experimental bool }

type linuxRecipe struct {
	plan        linuxFilesystemPlan
	wire        linuxLaunchWire
	interactive bool
	session     string
	codex       bool
}

// The caller supplies the compiler's complete captured Profile/Session tree.
// Runtime files are discovered separately and matched to pinned mount sources.
// This is not production snapshot capture or general-purpose Linux admission.
func linuxCompileRecipe(admission linuxRecipeAdmission, kind linuxRecipeKind, request validatedProcessRequest,
	tree linuxFilesystemSnapshot, interactive bool) (linuxRecipe, error) {
	if !admission.experimental {
		return linuxRecipe{}, unsupportedPlatformError("linux")
	}
	if len(request.runtimeInputs) != 0 || len(request.runtimeProbePaths) != 0 {
		return linuxRecipe{}, errLinuxRecipe
	}
	if request.workspaceAccess == WorkspaceAccessLegacy {
		request.workspaceAccess = WorkspaceAccessReadOnly
	}
	switch kind {
	case linuxShellRecipe:
		if request.executable != "" || len(request.arguments) != 0 {
			return linuxRecipe{}, errLinuxRecipe
		}
		request.executable, request.arguments = ShellRecipe("linux")
	case linuxCommandRecipe:
		request.arguments = append([]string(nil), request.arguments...)
	case linuxDevinRecipe:
		if interactive || !filepath.IsAbs(request.executable) || !linuxDevinArguments(request.arguments) {
			return linuxRecipe{}, errLinuxRecipe
		}
		request.arguments = append([]string(nil), request.arguments...)
	case linuxCodexRecipe:
		if !filepath.IsAbs(request.executable) || !codexcompat.ValidLinuxArguments(request.arguments, request.workspace, interactive) {
			return linuxRecipe{}, errLinuxRecipe
		}
		request.arguments = append([]string(nil), request.arguments...)
	default:
		return linuxRecipe{}, errLinuxRecipe
	}
	executable, err := filepath.EvalSymlinks(request.executable)
	if err != nil || !linuxCanonicalPlanPath(executable) {
		return linuxRecipe{}, errLinuxRecipe
	}
	request.executable = executable
	var files []linuxRuntimeFile
	if kind == linuxDevinRecipe {
		files, err = linuxDevinRuntime(executable)
	} else if kind == linuxCodexRecipe {
		files, err = linuxCodexRuntime(executable)
	} else {
		files, err = linuxDiscoverRuntime(executable, interactive)
	}
	if err != nil {
		return linuxRecipe{}, err
	}
	var denied []string
	for _, exclusion := range request.filesystemExclusions {
		denied = append(denied, exclusion.path, exclusion.logicalPath)
	}
	for _, protection := range request.sessionProtections {
		denied = append(denied, protection.path)
	}
	denied = append(denied, request.sessionsDirectory, SessionOperationsDirectory(request.sessionsDirectory))
	snapshot := make(linuxFilesystemSnapshot, len(tree)+len(files))
	for path, node := range tree {
		snapshot[path] = node
	}
	for _, file := range files {
		if old, exists := snapshot[file.path]; exists && old.identity != file.node.identity {
			return linuxRecipe{}, errLinuxRecipe
		}
		snapshot[file.path] = file.node
		request.runtimeInputs = append(request.runtimeInputs, file.path)
	}
	plan, err := compileLinuxFilesystemPlan(request, snapshot, linuxFilesystemFeatures{6, linuxUnixSocketsDenyCreation}, nil)
	if err != nil {
		return linuxRecipe{}, errors.Join(errLinuxRecipe, err)
	}
	if linuxAddRuntimeAliases(&plan, files, denied) != nil {
		return linuxRecipe{}, errLinuxRecipe
	}
	wire := linuxLaunchWire{Version: 1, Executable: executable,
		Argv: append([]string{executable}, request.arguments...), Home: request.sessionHome,
		Temporary: request.temporaryDirectory, Directory: request.workspace}
	for _, rule := range plan.rules {
		wire.Rules = append(wire.Rules, linuxWireRule{rule.path, rule.access})
	}
	if wire.validate() != nil {
		return linuxRecipe{}, errLinuxRecipe
	}
	return linuxRecipe{plan: plan, wire: wire, interactive: interactive, session: request.sessionDirectory, codex: kind == linuxCodexRecipe}, nil
}

// Run only in the dedicated test supervisor. All recipes, including redirected
// commands, use the sealed launcher and atomic per-Session cgroup placement.
// Even an experimental opt-in cannot bypass the real host prerequisite probe.
func linuxRunRecipe(ctx context.Context, admission linuxRecipeAdmission, recipe linuxRecipe,
	owner, helper *os.File, helperArgs []string, stdio [3]*os.File, env *environmentresource.Lease,
	cleanup *linuxSessionCleanup) (result linuxSessionResult, resultErr error) {
	if !admission.experimental {
		return result, unsupportedPlatformError("linux")
	}
	if cleanup == nil || cleanup.lease == nil || cleanup.lease.RootDir != recipe.session {
		return result, errLinuxSettlement
	}
	supervised := false
	defer func() {
		if !supervised {
			// No child has been started. Restoration/persistence can still fail.
			cleanupErr := cleanup.finish(true)
			result.Settled = cleanupErr == nil
			resultErr = errors.Join(resultErr, cleanupErr)
		}
	}()
	if owner == nil || helper == nil || recipe.wire.validate() != nil {
		return result, errLinuxRecipe
	}
	// Auth must come exclusively from the selected file projection. The initial
	// Codex recipe admits no environment overrides (including API tokens,
	// CODEX_HOME, proxy endpoints, or a desktop bus).
	if recipe.codex && (env == nil || !env.Empty()) {
		return result, errLinuxRecipe
	}
	interactive, err := linuxRecipeStdioMode(stdio)
	if err != nil || interactive != recipe.interactive {
		return result, errLinuxRecipe
	}
	if !linuxprobe.Probe(ctx).PrerequisitesPassed() {
		return result, errLinuxRecipe
	}
	if recipe.interactive {
		terminal, err := linuxRecipeTerminal(stdio, cleanup.terminal)
		if err != nil {
			return result, err
		}
		recipe.wire.Terminal = terminal
	}
	status, report, err := os.Pipe()
	if err != nil {
		return result, errLinuxRecipe
	}
	defer status.Close()
	defer report.Close()
	control, gate, err := os.Pipe()
	if err != nil {
		return result, errLinuxRecipe
	}
	defer control.Close()
	defer gate.Close()
	prepared, err := linuxPrepareBwrap(ctx, recipe.plan, recipe.wire, env, helper, report, control, stdio, helperArgs)
	if err != nil {
		return result, err
	}
	defer prepared.close()
	supervised = true
	return linuxSuperviseSession(ctx, owner, linuxSupervisedCommand{
		command: prepared.command, status: status, control: gate,
		childEnds: []*os.File{report, control}, cleanup: cleanup,
	})
}
