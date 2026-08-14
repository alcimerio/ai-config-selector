package launch

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

const safeProcessPath = "/usr/local/bin:/usr/bin:/bin"

// SandboxErrorCategory is a stable, non-sensitive class of sandbox failure.
type SandboxErrorCategory string

const (
	SandboxUnsupportedPlatform SandboxErrorCategory = "unsupported_platform"
	SandboxBackendUnavailable  SandboxErrorCategory = "backend_unavailable"
	SandboxUnsafePath          SandboxErrorCategory = "unsafe_path"
	SandboxInvalidEnvironment  SandboxErrorCategory = "invalid_environment"
	SandboxInvalidDescriptor   SandboxErrorCategory = "invalid_descriptor"
	SandboxSetupFailed         SandboxErrorCategory = "setup_failed"
	SandboxProcessStartFailed  SandboxErrorCategory = "process_start_failed"
	SandboxProcessWaitFailed   SandboxErrorCategory = "process_wait_failed"
)

// SandboxError deliberately reports only a stable category. Backend output,
// generated policy, host paths, and environment values stay private.
type SandboxError struct {
	Category    SandboxErrorCategory
	remediation string
}

func (e *SandboxError) Error() string {
	var message string
	switch e.Category {
	case SandboxUnsupportedPlatform:
		message = "process sandbox unavailable: unsupported platform"
	case SandboxBackendUnavailable:
		message = "process sandbox unavailable: required system backend is unavailable"
	case SandboxUnsafePath:
		message = "process sandbox preparation failed: unsafe runtime path"
	case SandboxInvalidEnvironment:
		message = "process sandbox preparation failed: invalid environment"
	case SandboxInvalidDescriptor:
		message = "process sandbox preparation failed: invalid file descriptor"
	case SandboxSetupFailed:
		message = "process sandbox preparation failed"
	case SandboxProcessStartFailed:
		message = "sandboxed process failed to start"
	case SandboxProcessWaitFailed:
		message = "sandboxed process failed while waiting"
	default:
		return string(SandboxSetupFailed) + ": process sandbox preparation failed"
	}
	if e.remediation != "" {
		message += "; " + e.remediation
	}
	return string(e.Category) + ": " + message
}

func sandboxError(category SandboxErrorCategory, _ error) error {
	return &SandboxError{Category: category}
}

func bubblewrapUnavailable() error {
	return &SandboxError{
		Category:    SandboxBackendUnavailable,
		remediation: "install or repair the signed Ubuntu package with 'sudo apt-get install --reinstall bubblewrap'",
	}
}

func bubblewrapCapabilityUnavailable() error {
	return &SandboxError{
		Category:    SandboxBackendUnavailable,
		remediation: "review and enable the targeted AppArmor bwrap user-namespace profile for /usr/bin/bwrap",
	}
}

// Platform identifies the host properties relevant to the supported sandbox
// contract. Distribution is required only for Linux.
type Platform struct {
	OS           string
	Architecture string
	Distribution string
	Release      string
}

// ValidatePlatform accepts only the release and architecture combinations
// certified by ACS.
func ValidatePlatform(platform Platform) error {
	architectureSupported := platform.Architecture == "amd64" || platform.Architecture == "arm64"
	supported := false
	switch platform.OS {
	case "darwin":
		supported = architectureSupported && releaseLine(platform.Release, "26")
	case "linux":
		supported = architectureSupported && strings.EqualFold(platform.Distribution, "ubuntu") && releaseLine(platform.Release, "24.04")
	}
	if !supported {
		return sandboxError(SandboxUnsupportedPlatform, nil)
	}
	return nil
}

func releaseLine(release, line string) bool {
	if release == line {
		return true
	}
	if !strings.HasPrefix(release, line+".") {
		return false
	}
	for _, component := range strings.Split(strings.TrimPrefix(release, line+"."), ".") {
		if component == "" {
			return false
		}
		if _, err := strconv.ParseUint(component, 10, 32); err != nil {
			return false
		}
	}
	return true
}

// CurrentPlatform identifies the running host without exposing probe output in
// returned diagnostics.
func CurrentPlatform() (Platform, error) {
	platform := Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH}
	switch runtime.GOOS {
	case "darwin":
		output, err := exec.Command("/usr/bin/sw_vers", "-productVersion").Output()
		if err != nil {
			return Platform{}, sandboxError(SandboxUnsupportedPlatform, err)
		}
		platform.Release = strings.TrimSpace(string(output))
	case "linux":
		file, err := os.Open("/etc/os-release")
		if err != nil {
			return Platform{}, sandboxError(SandboxUnsupportedPlatform, err)
		}
		defer file.Close()
		values := make(map[string]string)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			key, value, found := strings.Cut(scanner.Text(), "=")
			if found {
				values[key] = strings.Trim(strings.TrimSpace(value), `"`)
			}
		}
		if err := scanner.Err(); err != nil {
			return Platform{}, sandboxError(SandboxUnsupportedPlatform, err)
		}
		platform.Distribution = values["ID"]
		platform.Release = values["VERSION_ID"]
	default:
		return Platform{}, sandboxError(SandboxUnsupportedPlatform, nil)
	}
	return platform, nil
}

// SandboxCheck contains every runtime input ACS can validate before leasing a
// Session.
type SandboxCheck struct {
	Workspace         string
	SessionsDirectory string
	Executable        string
	RuntimeInputs     []string
}

// ProcessRequest describes one command that must run through the selected
// native sandbox. Callers supply intent, not backend policy or mount details.
type ProcessRequest struct {
	Workspace          string
	SessionsDirectory  string
	SessionDirectory   string
	SessionHome        string
	TemporaryDirectory string
	Executable         string
	RuntimeInputs      []string
	Arguments          []string
	Terminal           Terminal
}

// Process is a prepared sandboxed process tree.
type Process interface {
	Start() error
	Wait() error
	Signal(os.Signal) error
}

// ProcessSandbox is the shared launch boundary used by probes and interactive
// targets alike.
type ProcessSandbox interface {
	Check(context.Context, SandboxCheck) error
	Prepare(context.Context, ProcessRequest) (Process, error)
}

type platformProbe func() (Platform, error)

type sandboxBackend interface {
	check(context.Context) error
	prepare(context.Context, validatedProcessRequest) (Process, error)
}

type nativeProcessSandbox struct {
	platform platformProbe
	backends map[string]sandboxBackend
	environ  func() []string
}

// NewProcessSandbox returns the fail-closed native sandbox selector. Native
// backends register inside this package; callers cannot select or bypass them.
func NewProcessSandbox() ProcessSandbox {
	return newNativeProcessSandbox(CurrentPlatform, nativeSandboxBackends())
}

func newNativeProcessSandbox(platform platformProbe, backends map[string]sandboxBackend) *nativeProcessSandbox {
	return &nativeProcessSandbox{platform: platform, backends: backends, environ: os.Environ}
}

func (sandbox *nativeProcessSandbox) selectedBackend(ctx context.Context) (sandboxBackend, error) {
	platform, err := sandbox.platform()
	if err != nil {
		return nil, sandboxError(SandboxUnsupportedPlatform, err)
	}
	if err := ValidatePlatform(platform); err != nil {
		return nil, err
	}
	backend := sandbox.backends[platform.OS]
	if backend == nil {
		return nil, sandboxError(SandboxBackendUnavailable, nil)
	}
	if err := backend.check(ctx); err != nil {
		var classified *SandboxError
		if errors.As(err, &classified) {
			return nil, &SandboxError{Category: classified.Category, remediation: classified.remediation}
		}
		return nil, sandboxError(SandboxBackendUnavailable, err)
	}
	return backend, nil
}

func (sandbox *nativeProcessSandbox) Check(ctx context.Context, request SandboxCheck) error {
	if _, err := sandbox.selectedBackend(ctx); err != nil {
		return err
	}
	_, err := validateSandboxCheck(request)
	return err
}

func (sandbox *nativeProcessSandbox) Prepare(ctx context.Context, request ProcessRequest) (Process, error) {
	backend, err := sandbox.selectedBackend(ctx)
	if err != nil {
		return nil, err
	}
	validated, err := validateProcessRequest(request)
	if err != nil {
		return nil, err
	}
	if err := validateTerminal(request.Terminal); err != nil {
		return nil, err
	}
	validated.environment, err = buildProcessEnvironment(validated.sessionHome, validated.temporaryDirectory, sandbox.environ())
	if err != nil {
		return nil, err
	}
	process, err := backend.prepare(ctx, validated)
	if err != nil {
		var classified *SandboxError
		if errors.As(err, &classified) {
			return nil, sandboxError(classified.Category, nil)
		}
		return nil, sandboxError(SandboxSetupFailed, err)
	}
	if process == nil {
		return nil, sandboxError(SandboxSetupFailed, nil)
	}
	return sanitizedProcess{process: process}, nil
}

type sanitizedProcess struct {
	process Process
}

func (process sanitizedProcess) Start() error {
	if err := process.process.Start(); err != nil {
		return sandboxError(SandboxProcessStartFailed, err)
	}
	return nil
}

func (process sanitizedProcess) Wait() error {
	err := process.process.Wait()
	if err == nil {
		return nil
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return err
	}
	return sandboxError(SandboxProcessWaitFailed, err)
}

func (process sanitizedProcess) Signal(signal os.Signal) error {
	return process.process.Signal(signal)
}

type validatedSandboxCheck struct {
	workspace         string
	sessionsDirectory string
	executable        string
	runtimeInputs     []string
}

func validateSandboxCheck(request SandboxCheck) (validatedSandboxCheck, error) {
	workspace, err := resolveExistingPath(request.Workspace, true, false)
	if err != nil {
		return validatedSandboxCheck{}, sandboxError(SandboxUnsafePath, err)
	}
	sessionsDirectory, err := resolveFuturePath(request.SessionsDirectory)
	if err != nil {
		return validatedSandboxCheck{}, sandboxError(SandboxUnsafePath, err)
	}
	if workspace == string(filepath.Separator) || workspace == sessionsDirectory || pathWithin(workspace, sessionsDirectory) {
		return validatedSandboxCheck{}, sandboxError(SandboxUnsafePath, nil)
	}
	executable, err := resolveExecutable(request.Executable)
	if err != nil {
		return validatedSandboxCheck{}, sandboxError(SandboxUnsafePath, err)
	}
	runtimeInputs, err := resolveRuntimeInputs(request.RuntimeInputs)
	if err != nil {
		return validatedSandboxCheck{}, sandboxError(SandboxUnsafePath, err)
	}
	for _, input := range runtimeInputs {
		if broadRuntimeInput(input, workspace, sessionsDirectory) {
			return validatedSandboxCheck{}, sandboxError(SandboxUnsafePath, nil)
		}
	}
	return validatedSandboxCheck{workspace: workspace, sessionsDirectory: sessionsDirectory, executable: executable, runtimeInputs: runtimeInputs}, nil
}

func broadRuntimeInput(input, workspace, sessionsDirectory string) bool {
	if input == string(filepath.Separator) || input == workspace || input == sessionsDirectory {
		return true
	}
	return pathWithin(input, workspace) || pathWithin(input, sessionsDirectory)
}

type validatedProcessRequest struct {
	workspace          string
	sessionsDirectory  string
	sessionDirectory   string
	sessionHome        string
	temporaryDirectory string
	executable         string
	runtimeInputs      []string
	arguments          []string
	environment        []string
	terminal           Terminal
}

func validateProcessRequest(request ProcessRequest) (validatedProcessRequest, error) {
	checked, err := validateSandboxCheck(SandboxCheck{
		Workspace: request.Workspace, SessionsDirectory: request.SessionsDirectory,
		Executable: request.Executable, RuntimeInputs: request.RuntimeInputs,
	})
	if err != nil {
		return validatedProcessRequest{}, err
	}
	sessionDirectory, err := resolveExistingPath(request.SessionDirectory, true, false)
	if err != nil || !pathWithin(checked.sessionsDirectory, sessionDirectory) {
		return validatedProcessRequest{}, sandboxError(SandboxUnsafePath, err)
	}
	sessionHome, err := resolveExistingPath(request.SessionHome, true, false)
	if err != nil || !pathWithin(sessionDirectory, sessionHome) {
		return validatedProcessRequest{}, sandboxError(SandboxUnsafePath, err)
	}
	temporaryDirectory, err := resolveExistingPath(request.TemporaryDirectory, true, false)
	if err != nil || !pathWithin(sessionDirectory, temporaryDirectory) {
		return validatedProcessRequest{}, sandboxError(SandboxUnsafePath, err)
	}
	return validatedProcessRequest{
		workspace: checked.workspace, sessionsDirectory: checked.sessionsDirectory,
		sessionDirectory: sessionDirectory, sessionHome: sessionHome,
		temporaryDirectory: temporaryDirectory, executable: checked.executable,
		runtimeInputs: checked.runtimeInputs, arguments: append([]string(nil), request.Arguments...),
		terminal: request.Terminal,
	}, nil
}

func resolveExecutable(path string) (string, error) {
	if path == "" {
		return "", errors.New("executable is required")
	}
	if !strings.ContainsRune(path, filepath.Separator) {
		resolved, err := exec.LookPath(path)
		if err != nil {
			return "", err
		}
		path = resolved
	}
	return resolveExistingPath(path, false, true)
}

func resolveRuntimeInputs(inputs []string) ([]string, error) {
	resolved := make([]string, 0, len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for _, input := range inputs {
		path, err := resolveExistingPath(input, false, false)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[path]; exists {
			continue
		}
		seen[path] = struct{}{}
		resolved = append(resolved, path)
	}
	sort.Strings(resolved)
	return resolved, nil
}

func resolveExistingPath(path string, requireDirectory, requireExecutable bool) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("path must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", err
	}
	if requireDirectory && !info.IsDir() {
		return "", errors.New("path is not a directory")
	}
	if !requireDirectory && !info.Mode().IsRegular() && !info.IsDir() {
		return "", errors.New("path is not a regular file or directory")
	}
	if requireExecutable && (!info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0) {
		return "", errors.New("path is not an executable file")
	}
	return resolved, nil
}

func resolveFuturePath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("path must be absolute")
	}
	cleaned := filepath.Clean(path)
	current := cleaned
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			info, statErr := os.Stat(resolved)
			if statErr != nil || !info.IsDir() {
				return "", errors.New("path parent is not a directory")
			}
			for index := len(suffix) - 1; index >= 0; index-- {
				resolved = filepath.Join(resolved, suffix[index])
			}
			return resolved, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", err
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
}

func pathWithin(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func validateTerminal(terminal Terminal) error {
	for _, endpoint := range []struct {
		value    any
		expected uintptr
	}{
		{value: terminal.Input, expected: uintptr(os.Stdin.Fd())},
		{value: terminal.Output, expected: uintptr(os.Stdout.Fd())},
		{value: terminal.ErrorOutput, expected: uintptr(os.Stderr.Fd())},
	} {
		file, isFile := endpoint.value.(*os.File)
		if isFile && file.Fd() != endpoint.expected {
			return sandboxError(SandboxInvalidDescriptor, nil)
		}
	}
	return nil
}

func buildProcessEnvironment(sessionHome, temporaryDirectory string, host []string) ([]string, error) {
	values := map[string]string{}
	for _, entry := range host {
		key, value, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		switch key {
		case "TERM", "COLORTERM", "LANG", "LC_ALL", "LC_CTYPE":
			if !safeEnvironmentValue(value) {
				return nil, sandboxError(SandboxInvalidEnvironment, nil)
			}
			values[key] = value
		}
	}
	environment := []string{
		"HOME=" + sessionHome,
		"XDG_CONFIG_HOME=" + filepath.Join(sessionHome, ".config"),
		"XDG_DATA_HOME=" + filepath.Join(sessionHome, ".local", "share"),
		"XDG_CACHE_HOME=" + filepath.Join(sessionHome, ".cache"),
		"XDG_STATE_HOME=" + filepath.Join(sessionHome, ".local", "state"),
		"TMPDIR=" + temporaryDirectory,
		"PATH=" + safeProcessPath,
	}
	for _, key := range []string{"TERM", "COLORTERM", "LANG", "LC_ALL", "LC_CTYPE"} {
		if value, exists := values[key]; exists {
			environment = append(environment, key+"="+value)
		}
	}
	return environment, nil
}

func safeEnvironmentValue(value string) bool {
	if value == "" || len(value) > 256 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._@+:/-", character) {
			continue
		}
		return false
	}
	return true
}
