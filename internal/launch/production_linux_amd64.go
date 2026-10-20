//go:build linux && amd64

package launch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/codexcompat"
	"github.com/alcimerio/ai-config-selector/internal/environmentresource"
	"github.com/alcimerio/ai-config-selector/internal/linuxprobe"
	"golang.org/x/sys/unix"
)

const (
	linuxSupervisorArgument = "--acs-internal-linux-supervisor"
	linuxInitArgument       = "--acs-internal-linux-init"
)

func init() {
	if len(os.Args) != 2 {
		return
	}
	switch os.Args[1] {
	case linuxSupervisorArgument:
		code, err := linuxProductionSupervisor()
		if err != nil || code < 0 || code > 255 {
			os.Exit(125)
		}
		os.Exit(code)
	case linuxInitArgument:
		if linuxProductionInit() != nil {
			os.Exit(125)
		}
		os.Exit(0)
	}
}

type linuxProductionBackend struct{}

func (linuxProductionBackend) check(ctx context.Context) error {
	report := linuxprobe.Probe(ctx)
	if report.PrerequisitesPassed() {
		return nil
	}
	notes := make([]string, 0, len(report.Checks))
	for _, check := range report.Checks {
		if check.Status == "fail" && check.NextStep != "" {
			notes = append(notes, check.NextStep)
		}
	}
	if len(notes) == 0 {
		notes = append(notes, "Linux host prerequisites did not pass.")
	}
	return newSandboxError(SandboxVerificationFailed, joinNotes(notes))
}

func joinNotes(notes []string) string {
	text := ""
	for _, note := range notes {
		if text != "" {
			text += " "
		}
		if len(text)+len(note) > 1200 {
			break
		}
		text += note
	}
	return text
}

func (linuxProductionBackend) prepare(ctx context.Context, request validatedProcessRequest) (Process, error) {
	return linuxProductionPrepare(ctx, request)
}

func linuxProductionKind(request validatedProcessRequest) (linuxRecipeKind, error) {
	shell, shellArgs := ShellRecipe("linux")
	if request.executable == shell && len(request.arguments) == len(shellArgs) {
		match := true
		for i := range shellArgs {
			if request.arguments[i] != shellArgs[i] {
				match = false
				break
			}
		}
		if match {
			return linuxShellRecipe, nil
		}
	}
	if linuxDevinArguments(request.arguments) {
		return linuxDevinRecipe, nil
	}
	if codexcompat.ValidLinuxArguments(request.arguments, request.workspace, false) ||
		codexcompat.ValidLinuxArguments(request.arguments, request.workspace, true) {
		return linuxCodexRecipe, nil
	}
	if filepath.Base(request.executable) == "grok" {
		if linuxGrokArguments(request.arguments, false) || linuxGrokArguments(request.arguments, true) {
			return linuxGrokRecipe, nil
		}
		return 0, errLinuxRecipe
	}
	if request.executable == "" {
		return 0, errLinuxRecipe
	}
	return linuxCommandRecipe, nil
}

func linuxAdmitAuthority(request validatedProcessRequest) validatedProcessRequest {
	ports := append([]int(nil), request.runtimeAuthority.LoopbackPorts...)
	callback := request.runtimeAuthority.CodexLoginCallback
	request.runtimeAuthority = linuxFilesystemRuntimeAuthority()
	request.runtimeAuthority.LoopbackPorts = ports
	request.runtimeAuthority.CodexLoginCallback = callback
	return request
}

type linuxLaunchSpec struct {
	Version                                                              int
	Kind                                                                 linuxRecipeKind
	Interactive                                                          bool
	Workspace                                                            string
	WorkspaceAccess                                                      WorkspaceAccess
	SessionsDirectory, SessionDirectory, SessionHome, TemporaryDirectory string
	Executable                                                           string
	Arguments                                                            []string
	LoopbackPorts                                                        []int
	Callback                                                             bool
	Challenge                                                            []byte
	Grants                                                               []linuxSpecGrant
	Exclusions                                                           []linuxSpecExclusion
	Executables                                                          []string
	Protections                                                          []linuxSpecProtection
	Environment                                                          []byte
}

type linuxSpecGrant struct {
	Path      string
	Access    PathAccess
	Type      PathType
	Effective bool
}

type linuxSpecExclusion struct {
	Path, LogicalPath, FirstMissing, WitnessPath string
	Exists                                       bool
}

type linuxSpecProtection struct {
	Path      string
	Recursive bool
}

func linuxSpecFrom(kind linuxRecipeKind, interactive bool, request validatedProcessRequest) linuxLaunchSpec {
	spec := linuxLaunchSpec{
		Version: 1, Kind: kind, Interactive: interactive,
		Workspace: request.workspace, WorkspaceAccess: request.workspaceAccess,
		SessionsDirectory: request.sessionsDirectory, SessionDirectory: request.sessionDirectory,
		SessionHome: request.sessionHome, TemporaryDirectory: request.temporaryDirectory,
		Executable: request.executable, Arguments: append([]string(nil), request.arguments...),
		LoopbackPorts: append([]int(nil), request.runtimeAuthority.LoopbackPorts...),
		Callback:      request.runtimeAuthority.CodexLoginCallback,
		Challenge:     append([]byte(nil), request.recoveryProofChallenge...),
	}
	for _, grant := range request.filesystemGrants {
		spec.Grants = append(spec.Grants, linuxSpecGrant{Path: grant.path, Access: grant.Access, Type: grant.Type, Effective: grant.effective})
	}
	for _, exclusion := range request.filesystemExclusions {
		spec.Exclusions = append(spec.Exclusions, linuxSpecExclusion{
			Path: exclusion.path, LogicalPath: exclusion.logicalPath, FirstMissing: exclusion.firstMissing,
			WitnessPath: exclusion.witness.path, Exists: exclusion.exists,
		})
	}
	for _, grant := range request.executableGrants {
		spec.Executables = append(spec.Executables, grant.path)
	}
	for _, protection := range request.sessionProtections {
		spec.Protections = append(spec.Protections, linuxSpecProtection{Path: protection.path, Recursive: protection.recursive})
	}
	return spec
}

func linuxProductionPrepare(ctx context.Context, request validatedProcessRequest) (Process, error) {
	kind, err := linuxProductionKind(request)
	if err != nil {
		var classified *SandboxError
		if errors.As(err, &classified) {
			return nil, classified
		}
		return nil, sandboxError(SandboxSetupFailed, err)
	}
	stdio, interactive, err := linuxProductionStdio(request.terminal)
	if err != nil {
		return nil, sandboxError(SandboxInvalidDescriptor, err)
	}
	if len(request.recoveryProofChallenge) != RecoveryProofChallengeSize {
		return nil, sandboxError(SandboxSetupFailed, errLinuxSettlement)
	}
	admitted := linuxAdmitAuthority(request)
	spec := linuxSpecFrom(kind, interactive, admitted)
	if request.environmentProjection != nil {
		var frame bytes.Buffer
		if err := request.environmentProjection.WriteFrame(&frame); err != nil {
			return nil, sandboxError(SandboxInvalidEnvironment, err)
		}
		spec.Environment = frame.Bytes()
	}
	compiled := admitted
	if kind == linuxShellRecipe {
		compiled.executable = ""
		compiled.arguments = nil
	}
	tree, err := linuxCaptureSnapshot(linuxSnapshotRoots(compiled, spec))
	if err != nil {
		clear(spec.Environment)
		return nil, sandboxError(SandboxUnsafePath, err)
	}
	if _, err := linuxCompileRecipe(linuxRecipeAdmission{experimental: true}, kind, compiled, tree, interactive); err != nil {
		clear(spec.Environment)
		return nil, sandboxError(SandboxSetupFailed, err)
	}
	payload, err := json.Marshal(spec)
	clear(spec.Environment)
	if err != nil {
		return nil, sandboxError(SandboxSetupFailed, err)
	}
	specFile, err := linuxSealedMemfd(payload)
	clear(payload)
	if err != nil {
		return nil, sandboxError(SandboxSetupFailed, err)
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		_ = specFile.Close()
		return nil, sandboxError(SandboxSetupFailed, err)
	}
	owner := os.NewFile(uintptr(pair[0]), "linux-owner")
	child := os.NewFile(uintptr(pair[1]), "linux-owner-child")
	command := exec.CommandContext(ctx, "/proc/self/exe", linuxSupervisorArgument)
	command.Dir = "/"
	command.Env = []string{"LANG=C", "LC_ALL=C"}
	command.Stdin, command.Stdout, command.Stderr = stdio[0], stdio[1], stdio[2]
	command.ExtraFiles = []*os.File{specFile, child}
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	command.WaitDelay = linuxContainmentTimeout
	return &linuxProductionProcess{
		command: command, owner: owner, spec: specFile, child: child,
		done: make(chan struct{}), unproven: make(chan struct{}),
	}, nil
}

func linuxProductionStdio(terminal Terminal) ([3]*os.File, bool, error) {
	values := []any{terminal.Input, terminal.Output, terminal.ErrorOutput}
	var stdio [3]*os.File
	for i, value := range values {
		file, ok := value.(*os.File)
		if !ok || file == nil {
			return stdio, false, errLinuxRecipe
		}
		stdio[i] = file
	}
	interactive, err := linuxRecipeStdioMode(stdio)
	return stdio, interactive, err
}

func linuxSnapshotRoots(request validatedProcessRequest, spec linuxLaunchSpec) []string {
	roots := []string{request.workspace, request.sessionDirectory}
	if request.executable != "" {
		roots = append(roots, request.executable)
	}
	for _, grant := range spec.Grants {
		roots = append(roots, grant.Path)
	}
	for _, exclusion := range spec.Exclusions {
		roots = append(roots, exclusion.WitnessPath)
		if exclusion.Exists {
			roots = append(roots, exclusion.Path)
		}
	}
	return append(roots, spec.Executables...)
}

func linuxCaptureSnapshot(roots []string) (linuxFilesystemSnapshot, error) {
	tree := linuxFilesystemSnapshot{}
	seen := map[string]bool{}
	filesystemByMount := map[uint64]int64{}
	for _, root := range roots {
		if root == "" || seen[root] {
			continue
		}
		if _, err := os.Lstat(root); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		if err := linuxSnapshotWalk(tree, root, filesystemByMount); err != nil {
			return nil, err
		}
		seen[root] = true
	}
	return tree, nil
}

// linuxSnapshotWalk records one non-following identity per path. Child names
// come from the directory listing that discovers them. Filesystem type is
// constant for a mount, so it is read once per mount id.
func linuxSnapshotWalk(tree linuxFilesystemSnapshot, path string, filesystemByMount map[uint64]int64) error {
	node, err := linuxSnapshotNode(path, filesystemByMount)
	if err != nil {
		return err
	}
	if old, exists := tree[path]; exists && old.identity != node.identity {
		return errLinuxRecipe
	}
	tree[path] = node
	if !node.identity.mode.IsDir() {
		return nil
	}
	for _, name := range node.children {
		if err := linuxSnapshotWalk(tree, filepath.Join(path, name), filesystemByMount); err != nil {
			return err
		}
	}
	return nil
}

func linuxSnapshotNode(path string, filesystemByMount map[uint64]int64) (linuxFilesystemNode, error) {
	extended, mode, err := linuxSnapshotStat(path)
	if err != nil {
		return linuxFilesystemNode{}, err
	}
	filesystem, err := linuxSnapshotFilesystem(path, extended, mode, filesystemByMount)
	if err != nil {
		return linuxFilesystemNode{}, err
	}
	node := linuxFilesystemNode{
		identity:       linuxIdentityFromStatx(extended, mode),
		mountID:        extended.Mnt_id,
		filesystemType: filesystem,
	}
	if !mode.IsDir() {
		return node, nil
	}
	children, err := os.ReadDir(path)
	if err != nil {
		return linuxFilesystemNode{}, err
	}
	node.children = make([]string, len(children))
	for index, child := range children {
		node.children[index] = child.Name()
	}
	return node, nil
}

const linuxSnapshotStatMask = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_NLINK | unix.STATX_INO | unix.STATX_SIZE | unix.STATX_MTIME | unix.STATX_MNT_ID

func linuxSnapshotStat(path string) (unix.Statx_t, os.FileMode, error) {
	var extended unix.Statx_t
	if unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, linuxSnapshotStatMask, &extended) != nil ||
		extended.Mask&linuxSnapshotStatMask != linuxSnapshotStatMask || extended.Mnt_id == 0 {
		return unix.Statx_t{}, 0, errLinuxRecipe
	}
	return extended, linuxModeFromStatx(extended.Mode), nil
}

func linuxSnapshotFilesystem(path string, extended unix.Statx_t, mode os.FileMode, cache map[uint64]int64) (int64, error) {
	var filesystem unix.Statfs_t
	if mode&os.ModeSymlink != 0 {
		// Statfs follows, matching the previous capture. The result describes
		// the target and must not be stored under the link's mount id.
		if unix.Statfs(path, &filesystem) != nil {
			return 0, errLinuxRecipe
		}
		return filesystem.Type, nil
	}
	if kind, ok := cache[extended.Mnt_id]; ok {
		return kind, nil
	}
	// Learn the type from the same descriptor that confirms this mount id.
	// A replacement between the path stat and this open fails closed instead
	// of publishing another filesystem's type for the mount.
	fd, err := unix.Open(path, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, errLinuxRecipe
	}
	confirmed, confirmedMode, statErr := linuxSnapshotStatFd(fd)
	fsErr := unix.Fstatfs(fd, &filesystem)
	unix.Close(fd)
	if statErr != nil || fsErr != nil || confirmed.Mnt_id != extended.Mnt_id || confirmedMode&os.ModeSymlink != 0 ||
		linuxIdentityFromStatx(confirmed, confirmedMode) != linuxIdentityFromStatx(extended, mode) {
		return 0, errLinuxRecipe
	}
	cache[extended.Mnt_id] = filesystem.Type
	return filesystem.Type, nil
}

func linuxSnapshotStatFd(fd int) (unix.Statx_t, os.FileMode, error) {
	var extended unix.Statx_t
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW, linuxSnapshotStatMask, &extended) != nil ||
		extended.Mask&linuxSnapshotStatMask != linuxSnapshotStatMask || extended.Mnt_id == 0 {
		return unix.Statx_t{}, 0, errLinuxRecipe
	}
	return extended, linuxModeFromStatx(extended.Mode), nil
}

func linuxIdentityFromStatx(extended unix.Statx_t, mode os.FileMode) pathIdentity {
	identity := pathIdentity{
		device: unix.Mkdev(extended.Dev_major, extended.Dev_minor),
		inode:  extended.Ino,
		mode:   mode,
	}
	if mode.IsRegular() {
		identity.links = uint64(extended.Nlink)
		identity.size = int64(extended.Size)
		identity.modifiedNanos = time.Unix(extended.Mtime.Sec, int64(extended.Mtime.Nsec)).UnixNano()
	}
	return identity
}

// linuxModeFromStatx matches os.FileInfo.Mode for a non-following stat so
// snapshot identities stay comparable with path grants.
func linuxModeFromStatx(raw uint16) os.FileMode {
	mode := os.FileMode(raw & 0777)
	switch raw & unix.S_IFMT {
	case unix.S_IFBLK:
		mode |= os.ModeDevice
	case unix.S_IFCHR:
		mode |= os.ModeDevice | os.ModeCharDevice
	case unix.S_IFDIR:
		mode |= os.ModeDir
	case unix.S_IFIFO:
		mode |= os.ModeNamedPipe
	case unix.S_IFLNK:
		mode |= os.ModeSymlink
	case unix.S_IFSOCK:
		mode |= os.ModeSocket
	}
	if raw&unix.S_ISUID != 0 {
		mode |= os.ModeSetuid
	}
	if raw&unix.S_ISGID != 0 {
		mode |= os.ModeSetgid
	}
	if raw&unix.S_ISVTX != 0 {
		mode |= os.ModeSticky
	}
	return mode
}

type linuxProductionProcess struct {
	command                *exec.Cmd
	owner, spec, child     *os.File
	started, execSeen      bool
	done, unproven         chan struct{}
	doneOnce, unprovenOnce sync.Once
}

func (process *linuxProductionProcess) Start() error {
	if process.started {
		return sandboxError(SandboxProcessStartFailed, nil)
	}
	if err := process.command.Start(); err != nil {
		process.AbortPrepared()
		return sandboxError(SandboxProcessStartFailed, err)
	}
	process.started = true
	_ = process.spec.Close()
	_ = process.child.Close()
	if err := process.readOwner('R', 30*time.Second); err != nil || process.writeOwner('S') != nil || process.readOwner('E', 30*time.Second) != nil {
		_ = process.command.Process.Kill()
		_ = process.command.Wait()
		process.markUnproven()
		return sandboxError(SandboxProcessStartFailed, errLinuxContainment)
	}
	process.execSeen = true
	return nil
}

func (process *linuxProductionProcess) Wait() error {
	if !process.execSeen {
		return sandboxError(SandboxProcessWaitFailed, nil)
	}
	err := process.readOwner('X', 0)
	waitErr := process.command.Wait()
	if err != nil {
		process.markUnproven()
		return sandboxError(SandboxProcessWaitFailed, err)
	}
	process.markDone()
	return waitErr
}

func (process *linuxProductionProcess) Signal(signal os.Signal) error {
	if !process.execSeen {
		return sandboxError(SandboxProcessStartFailed, nil)
	}
	sys, ok := signal.(syscall.Signal)
	if !ok {
		return sandboxError(SandboxProcessStartFailed, nil)
	}
	if _, ok := linuxForwardedSignal(byte(sys)); !ok {
		return sandboxError(SandboxProcessStartFailed, nil)
	}
	return process.writeOwner(byte(sys))
}

func (process *linuxProductionProcess) CleanupDone() <-chan struct{}     { return process.done }
func (process *linuxProductionProcess) CleanupUnproven() <-chan struct{} { return process.unproven }

func (process *linuxProductionProcess) AbortPrepared() error {
	if process.started {
		return nil
	}
	if process.spec != nil {
		_ = process.spec.Close()
	}
	if process.child != nil {
		_ = process.child.Close()
	}
	if process.owner != nil {
		_ = process.owner.Close()
	}
	process.markUnproven()
	return nil
}

func (process *linuxProductionProcess) readOwner(expect byte, limit time.Duration) error {
	if limit > 0 {
		_ = process.owner.SetReadDeadline(time.Now().Add(limit))
		defer process.owner.SetReadDeadline(time.Time{})
	}
	var received [1]byte
	if _, err := io.ReadFull(process.owner, received[:]); err != nil || received[0] != expect {
		return errLinuxContainment
	}
	return nil
}

func (process *linuxProductionProcess) writeOwner(code byte) error {
	_, err := process.owner.Write([]byte{code})
	if err != nil {
		return sandboxError(SandboxProcessStartFailed, err)
	}
	return nil
}

func (process *linuxProductionProcess) markDone() {
	process.doneOnce.Do(func() { close(process.done) })
}

func (process *linuxProductionProcess) markUnproven() {
	process.unprovenOnce.Do(func() { close(process.unproven) })
}

func linuxProductionInit() error {
	transport := os.NewFile(3, "transport")
	report := os.NewFile(4, "report")
	control := os.NewFile(5, "control")
	wire, env, err := linuxReadTransport(transport)
	_ = transport.Close()
	if err != nil {
		return err
	}
	return linuxRunContainedInit(wire, env, report, control)
}

func linuxProductionSupervisor() (int, error) {
	specFile := os.NewFile(3, "linux-launch-spec")
	owner := os.NewFile(4, "linux-owner")
	payload, err := io.ReadAll(io.LimitReader(specFile, linuxTransportLimit+1))
	_ = specFile.Close()
	if err != nil || len(payload) == 0 || len(payload) > linuxTransportLimit {
		return 125, errLinuxRecipe
	}
	var spec linuxLaunchSpec
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&spec) != nil || spec.Version != 1 || decoder.Decode(new(any)) != io.EOF {
		clear(payload)
		return 125, errLinuxRecipe
	}
	clear(payload)
	request := validatedProcessRequest{
		workspace: spec.Workspace, workspaceAccess: spec.WorkspaceAccess,
		sessionsDirectory: spec.SessionsDirectory, sessionDirectory: spec.SessionDirectory,
		sessionHome: spec.SessionHome, temporaryDirectory: spec.TemporaryDirectory,
		executable: spec.Executable, arguments: append([]string(nil), spec.Arguments...),
		recoveryProofChallenge: append([]byte(nil), spec.Challenge...),
	}
	request.runtimeAuthority.LoopbackPorts = append([]int(nil), spec.LoopbackPorts...)
	request.runtimeAuthority.CodexLoginCallback = spec.Callback
	request = linuxAdmitAuthority(request)
	for _, grant := range spec.Grants {
		request.filesystemGrants = append(request.filesystemGrants, FilesystemGrant{
			Access: grant.Access, Type: grant.Type, logicalPath: grant.Path, path: grant.Path, effective: grant.Effective,
		})
	}
	for _, exclusion := range spec.Exclusions {
		request.filesystemExclusions = append(request.filesystemExclusions, FilesystemExclusion{
			path: exclusion.Path, logicalPath: exclusion.LogicalPath, firstMissing: exclusion.FirstMissing,
			exists: exclusion.Exists, witness: FilesystemGrant{path: exclusion.WitnessPath},
		})
	}
	for _, path := range spec.Executables {
		request.executableGrants = append(request.executableGrants, ExecutableGrant{logicalPath: path, path: path})
	}
	for _, protection := range spec.Protections {
		request.sessionProtections = append(request.sessionProtections, validatedSessionProtection{path: protection.Path, recursive: protection.Recursive})
	}
	compiled := request
	if spec.Kind == linuxShellRecipe {
		compiled.executable = ""
		compiled.arguments = nil
	}
	tree, err := linuxCaptureSnapshot(linuxSnapshotRoots(compiled, spec))
	if err != nil {
		return 125, err
	}
	for i, grant := range request.filesystemGrants {
		node, ok := tree[grant.path]
		if !ok {
			return 125, errLinuxRecipe
		}
		request.filesystemGrants[i].identity = node.identity
		compiled.filesystemGrants[i].identity = node.identity
	}
	for i, exclusion := range request.filesystemExclusions {
		node, ok := tree[exclusion.witness.path]
		if !ok {
			return 125, errLinuxRecipe
		}
		request.filesystemExclusions[i].witness.identity = node.identity
		compiled.filesystemExclusions[i].witness.identity = node.identity
	}
	for i, grant := range request.executableGrants {
		node, ok := tree[grant.path]
		if !ok {
			return 125, errLinuxRecipe
		}
		request.executableGrants[i].identity = node.identity
		compiled.executableGrants[i].identity = node.identity
	}
	for i, protection := range request.sessionProtections {
		node, ok := tree[protection.path]
		if !ok {
			return 125, errLinuxRecipe
		}
		request.sessionProtections[i].identity = node.identity
		compiled.sessionProtections[i].identity = node.identity
	}
	stdio := [3]*os.File{os.Stdin, os.Stdout, os.Stderr}
	interactive, err := linuxRecipeStdioMode(stdio)
	if err != nil || interactive != spec.Interactive {
		return 125, errLinuxRecipe
	}
	recipe, err := linuxCompileRecipe(linuxRecipeAdmission{experimental: true}, spec.Kind, compiled, tree, interactive)
	if err != nil {
		return 125, err
	}
	var assignments []string
	if len(spec.Environment) != 0 {
		assignments, err = environmentresource.ReadFrame(bytes.NewReader(spec.Environment), nil)
		clear(spec.Environment)
		if err != nil {
			return 125, err
		}
	}
	selected, err := environmentresource.Restore(assignments)
	if err != nil {
		return 125, err
	}
	defer selected.Release()
	session, err := linuxAdoptPreparedSession(spec.SessionsDirectory, spec.SessionDirectory)
	if err != nil {
		return 125, err
	}
	cleanup, err := linuxPrepareCleanup(session, spec.Challenge, os.Stdin)
	clear(spec.Challenge)
	if err != nil {
		return 125, err
	}
	helper, err := os.Open("/proc/self/exe")
	if err != nil {
		return 125, err
	}
	defer helper.Close()
	result, err := linuxRunRecipe(context.Background(), linuxRecipeAdmission{experimental: true}, recipe, owner, helper,
		[]string{linuxInitArgument}, stdio, selected, cleanup)
	if err != nil || !result.Settled || !result.Exited {
		return 125, err
	}
	switch {
	case result.Status.Exited():
		return result.Status.ExitStatus(), nil
	case result.Status.Signaled():
		return 128 + int(result.Status.Signal()), nil
	default:
		return 125, errLinuxContainment
	}
}

func linuxAdoptPreparedSession(sessionsDirectory, root string) (*SessionLease, error) {
	guardPath := sessionLeasePath(sessionsDirectory, root)
	fd, err := unix.Open(guardPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errLinuxSettlement
	}
	guard := os.NewFile(uintptr(fd), "linux-session-guard")
	recovery := sessionRecoveryPath(sessionsDirectory, root)
	_, statErr := os.Lstat(recovery)
	if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		_ = guard.Close()
		return nil, errLinuxSettlement
	}
	return &SessionLease{
		RootDir: root, guard: guard, guardPath: guardPath, recoveryPath: recovery,
		recoveryProtected: statErr == nil, references: 1,
	}, nil
}
