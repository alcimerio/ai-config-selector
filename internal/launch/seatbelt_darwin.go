//go:build darwin

package launch

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	seatbeltExecutable           = "/usr/bin/sandbox-exec"
	seatbeltCancellationTimeout  = 2 * time.Second
	seatbeltSettlementAttempts   = 100
	seatbeltSettlementRetryDelay = 10 * time.Millisecond
	seatbeltQuarantineRetryDelay = 100 * time.Millisecond
)

type seatbeltPolicyBuilder func(validatedProcessRequest) (string, []string, error)
type seatbeltVerifier func(context.Context, string) error

type seatbeltBackend struct {
	executable string
	policy     seatbeltPolicyBuilder
	verify     seatbeltVerifier
}

func newSeatbeltBackend(executable string) *seatbeltBackend {
	return &seatbeltBackend{executable: executable, policy: buildSeatbeltPolicy, verify: verifySeatbeltBackend}
}

func (backend *seatbeltBackend) check(ctx context.Context) error {
	if backend.executable != seatbeltExecutable {
		return sandboxError(SandboxBackendUnavailable, nil)
	}
	info, err := os.Lstat(backend.executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o111 == 0 || info.Mode().Perm()&0o022 != 0 {
		return sandboxError(SandboxBackendUnavailable, err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return sandboxError(SandboxBackendUnavailable, nil)
	}
	if err := backend.verify(ctx, backend.executable); err != nil {
		return sandboxError(SandboxVerificationFailed, err)
	}
	return nil
}

func verifySeatbeltBackend(ctx context.Context, executable string) error {
	policy := `(version 1)
(deny default)
(allow process-exec)
(allow file-read* (literal "/") (literal "/usr") (literal "/usr/bin/true"))`
	command := exec.CommandContext(ctx, executable, "-p", policy, "--", "/usr/bin/true")
	command.Env = []string{"PATH=" + safeProcessPath}
	command.Stdin = nil
	command.Stdout = nil
	command.Stderr = nil
	command.ExtraFiles = nil
	return command.Run()
}

func (backend *seatbeltBackend) prepare(ctx context.Context, request validatedProcessRequest) (Process, error) {
	policy, definitions, err := backend.policy(request)
	if err != nil {
		return nil, sandboxError(SandboxSetupFailed, err)
	}
	supervisor, err := os.Executable()
	if err != nil {
		return nil, sandboxError(SandboxSetupFailed, err)
	}
	supervisor, err = filepath.EvalSymlinks(supervisor)
	if err != nil {
		return nil, sandboxError(SandboxSetupFailed, err)
	}
	definitions = append(definitions, "-DSUPERVISOR="+supervisor)
	if err := backend.validateGeneratedPolicy(ctx, request, policy, definitions); err != nil {
		return nil, sandboxError(SandboxPolicyRejected, err)
	}
	arguments := make([]string, 0, 7+len(definitions)+len(request.arguments))
	arguments = append(arguments, "-p", policy)
	arguments = append(arguments, definitions...)
	arguments = append(arguments, "--", supervisor, seatbeltHelperArgument, "--", request.executable)
	arguments = append(arguments, request.arguments...)
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, sandboxError(SandboxSetupFailed, err)
	}
	unix.CloseOnExec(sockets[0])
	unix.CloseOnExec(sockets[1])
	control := os.NewFile(uintptr(sockets[0]), "acs-seatbelt-control")
	helperControl := os.NewFile(uintptr(sockets[1]), "acs-seatbelt-helper-control")
	if control == nil || helperControl == nil {
		if control != nil {
			_ = control.Close()
		}
		if helperControl != nil {
			_ = helperControl.Close()
		}
		return nil, sandboxError(SandboxSetupFailed, nil)
	}
	statusSockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		_ = control.Close()
		_ = helperControl.Close()
		return nil, sandboxError(SandboxSetupFailed, err)
	}
	unix.CloseOnExec(statusSockets[0])
	unix.CloseOnExec(statusSockets[1])
	statusControl := os.NewFile(uintptr(statusSockets[0]), "acs-seatbelt-status-control")
	proxyStatus := os.NewFile(uintptr(statusSockets[1]), "acs-seatbelt-proxy-status")
	if statusControl == nil || proxyStatus == nil {
		if statusControl != nil {
			_ = statusControl.Close()
		}
		if proxyStatus != nil {
			_ = proxyStatus.Close()
		}
		_ = control.Close()
		_ = helperControl.Close()
		return nil, sandboxError(SandboxSetupFailed, nil)
	}
	challenge := make([]byte, seatbeltChallengeSize)
	if _, err := rand.Read(challenge); err != nil {
		_ = control.Close()
		_ = helperControl.Close()
		_ = statusControl.Close()
		_ = proxyStatus.Close()
		return nil, sandboxError(SandboxSetupFailed, err)
	}
	proxyArguments := append([]string{seatbeltStatusProxyArgument, "--", backend.executable}, arguments...)
	command := exec.CommandContext(ctx, supervisor, proxyArguments...)
	command.Dir = request.workspace
	command.Env = seatbeltStatusProxyEnvironment(request.environment)
	command.Stdin = request.terminal.Input
	command.Stdout = request.terminal.Output
	command.Stderr = request.terminal.ErrorOutput
	command.ExtraFiles = []*os.File{proxyStatus, helperControl}
	terminal, foregroundGroup := seatbeltForegroundTerminal(request.terminal)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if terminal != nil {
		command.SysProcAttr.Foreground = true
		command.SysProcAttr.Ctty = int(terminal.Fd())
	}
	process := &seatbeltProcess{
		ctx: ctx, command: command, terminal: terminal, foregroundGroup: foregroundGroup,
		cleanupDone: make(chan struct{}), supervised: true, control: control,
		helperControl: helperControl, statusControl: statusControl, proxyStatus: proxyStatus,
		challenge: challenge,
	}
	command.Cancel = process.cancel
	command.WaitDelay = time.Second
	return process, nil
}

func (backend *seatbeltBackend) validateGeneratedPolicy(
	ctx context.Context,
	request validatedProcessRequest,
	policy string,
	definitions []string,
) error {
	arguments := make([]string, 0, 4+len(definitions))
	arguments = append(arguments, "-p", policy)
	arguments = append(arguments, definitions...)
	arguments = append(arguments, "--", "/usr/bin/true")
	command := exec.CommandContext(ctx, backend.executable, arguments...)
	command.Dir = request.workspace
	command.Env = append([]string(nil), request.environment...)
	command.Stdin = nil
	var diagnostics bytes.Buffer
	command.Stdout = &diagnostics
	command.Stderr = &diagnostics
	command.ExtraFiles = nil
	return command.Run()
}

type seatbeltProcess struct {
	ctx                       context.Context
	command                   *exec.Cmd
	terminal                  *os.File
	foregroundGroup           int
	startupIdentityMutex      sync.Mutex
	identityMutex             sync.Mutex
	processGroup              int
	waitCommand               func() error
	cancellationTimeout       func() <-chan time.Time
	killProcessGroup          func(int, syscall.Signal) error
	settlementAttempts        int
	cleanupRetry              func()
	quarantineRetry           func()
	cleanupQuarantine         func(*seatbeltProcess)
	setForegroundProcessGroup func(*os.File, int) error
	cleanupDone               chan struct{}
	cleanupDoneOnce           sync.Once
	leaderWaitMutex           sync.Mutex
	leaderWaitDone            <-chan error
	supervised                bool
	control                   *os.File
	helperControl             *os.File
	statusControl             *os.File
	proxyStatus               *os.File
	challenge                 []byte
	controlMutex              sync.Mutex
	statusControlMutex        sync.Mutex
	proofTimeout              func() <-chan time.Time
}

func (process *seatbeltProcess) Start() error {
	process.startupIdentityMutex.Lock()
	defer process.startupIdentityMutex.Unlock()
	err := process.command.Start()
	if err == nil {
		// Darwin does not expose pidfds. Retain the process-group identifier
		// captured while the leader is our live child; the kernel preserves the
		// group identity while any member remains, which is the strongest stable
		// tree identity available on this platform.
		process.identityMutex.Lock()
		process.processGroup = process.command.Process.Pid
		process.identityMutex.Unlock()
	}
	if process.helperControl != nil {
		_ = process.helperControl.Close()
		process.helperControl = nil
	}
	if process.proxyStatus != nil {
		_ = process.proxyStatus.Close()
		process.proxyStatus = nil
	}
	if err == nil && process.supervised {
		if writeErr := process.writeControl(process.challenge); writeErr != nil {
			process.closeControl()
			process.closeStatusControl()
			process.quarantineUnprovenCleanup()
			process.reapStartedSupervisor()
			return errors.Join(sandboxError(SandboxProcessStartFailed, writeErr), process.restoreForegroundTerminal())
		}
	}
	if err == nil {
		return nil
	}
	process.closeControl()
	process.closeStatusControl()
	process.markCleanupDone()
	return errors.Join(err, process.restoreForegroundTerminal())
}

func (process *seatbeltProcess) Wait() error {
	if process.supervised {
		return process.waitForSupervisorProof()
	}
	waitDone := make(chan error, 1)
	waitCommand := process.waitCommand
	if waitCommand == nil {
		waitCommand = process.command.Wait
	}
	go func() { waitDone <- waitCommand() }()
	waitErr, leaderDone := process.waitForLeader(waitDone)
	terminalErr := process.restoreForegroundTerminal()
	if !leaderDone {
		process.retainLeaderWait(waitDone)
		process.quarantineCleanup()
		return errors.Join(waitErr, terminalErr)
	}
	cleanupErr := process.settleProcessGroup()
	if cleanupErr != nil {
		process.quarantineCleanup()
		return errors.Join(waitErr, cleanupErr, terminalErr)
	}
	process.markCleanupDone()
	return errors.Join(waitErr, terminalErr)
}

func (process *seatbeltProcess) waitForSupervisorProof() error {
	waitDone := make(chan error, 1)
	go func() { waitDone <- process.command.Wait() }()
	proof, proofErr := process.readCleanupProof()
	if proofErr == nil {
		proofErr = validateSeatbeltCleanupProof(proof, process.challenge)
	}
	if proofErr == nil {
		proofErr = process.writeTargetStatus(proof)
	}
	process.closeStatusControl()
	waitErr := <-waitDone
	terminalErr := process.restoreForegroundTerminal()
	if proofErr == nil {
		proofErr = matchSeatbeltProofStatus(proof, waitErr)
	}
	if proofErr != nil {
		process.quarantineUnprovenCleanup()
		return errors.Join(waitErr, sandboxError(SandboxProcessWaitFailed, proofErr), terminalErr)
	}
	process.markCleanupDone()
	return errors.Join(waitErr, terminalErr)
}

func (process *seatbeltProcess) readCleanupProof() ([]byte, error) {
	if process.control == nil {
		return nil, errors.New("Seatbelt cleanup proof channel is unavailable")
	}
	done := make(chan struct{})
	var data []byte
	var readErr error
	go func() {
		data, readErr = io.ReadAll(io.LimitReader(process.control, 4097))
		close(done)
	}()
	finish := func() ([]byte, error) {
		_ = process.control.Close()
		if len(data) > 4096 {
			return nil, errors.New("Seatbelt cleanup proof exceeds its limit")
		}
		return data, readErr
	}
	var canceled <-chan struct{}
	if process.ctx != nil {
		canceled = process.ctx.Done()
	}
	if canceled == nil {
		<-done
		return finish()
	}
	select {
	case <-done:
		return finish()
	case <-canceled:
	}
	timeout := process.proofTimeout
	if timeout == nil {
		timeout = func() <-chan time.Time { return time.After(seatbeltCancellationTimeout) }
	}
	select {
	case <-done:
		return finish()
	case <-timeout():
		_ = process.control.Close()
		return nil, context.DeadlineExceeded
	}
}

func matchSeatbeltProofStatus(data []byte, waitErr error) error {
	var proof seatbeltCleanupProof
	if err := json.Unmarshal(data, &proof); err != nil {
		return errors.New("decode Seatbelt target status proof")
	}
	if proof.NoTargetStarted {
		exitError, ok := waitErr.(*exec.ExitError)
		if !ok {
			return errors.New("Seatbelt no-target proof requires a supervisor exit status")
		}
		status, ok := exitError.Sys().(syscall.WaitStatus)
		if !ok || !status.Exited() || status.ExitStatus() != 125 {
			return errors.New("Seatbelt no-target proof does not match supervisor status")
		}
		return nil
	}
	if waitErr == nil {
		if proof.TargetExited && proof.TargetExitCode == 0 {
			return nil
		}
		return errors.New("Seatbelt target status does not match supervisor status")
	}
	exitError, ok := waitErr.(*exec.ExitError)
	if !ok {
		return errors.New("Seatbelt supervisor wait failed without an exit status")
	}
	status, ok := exitError.Sys().(syscall.WaitStatus)
	if !ok {
		return errors.New("Seatbelt supervisor returned an unknown exit status")
	}
	if status.Exited() && proof.TargetExited && status.ExitStatus() == proof.TargetExitCode {
		return nil
	}
	if status.Signaled() && proof.TargetSignal == int(status.Signal()) {
		return nil
	}
	return errors.New("Seatbelt target status does not match supervisor status")
}

func (process *seatbeltProcess) waitForLeader(waitDone <-chan error) (error, bool) {
	var canceled <-chan struct{}
	if process.ctx != nil {
		canceled = process.ctx.Done()
	}
	select {
	case err := <-waitDone:
		return err, true
	case <-canceled:
	}
	timeout := process.cancellationTimeout
	if timeout == nil {
		timeout = func() <-chan time.Time { return time.After(seatbeltCancellationTimeout) }
	}
	select {
	case err := <-waitDone:
		return err, true
	case <-timeout():
		return errors.Join(process.ctx.Err(), fmt.Errorf("wait for Seatbelt process cancellation: %w", context.DeadlineExceeded)), false
	}
}

func (process *seatbeltProcess) Signal(signal os.Signal) error {
	if process.supervised {
		unixSignal, ok := signal.(syscall.Signal)
		if !ok || unixSignal <= 0 || unixSignal > 255 {
			return errors.New("unsupported Seatbelt target signal")
		}
		if err := process.writeControl([]byte{'S', byte(unixSignal)}); err != nil {
			return os.ErrProcessDone
		}
		return nil
	}
	processGroup := process.stableProcessGroup()
	if processGroup <= 0 {
		return os.ErrProcessDone
	}
	unixSignal, ok := signal.(syscall.Signal)
	if !ok {
		return process.command.Process.Signal(signal)
	}
	err := process.signalProcessGroup(processGroup, unixSignal)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

func (process *seatbeltProcess) CleanupDone() <-chan struct{} {
	return process.cleanupDone
}

func (process *seatbeltProcess) cancel() error {
	if process.supervised {
		process.startupIdentityMutex.Lock()
		process.startupIdentityMutex.Unlock()
		return process.Signal(syscall.SIGKILL)
	}
	// exec.Cmd can call Cancel before Start returns to our caller. Wait until
	// the process-group identity has either been recorded or definitively
	// failed, then address only that group.
	process.startupIdentityMutex.Lock()
	process.startupIdentityMutex.Unlock()
	processGroup := process.stableProcessGroup()
	if processGroup <= 0 {
		return os.ErrProcessDone
	}
	if err := process.signalProcessGroup(processGroup, syscall.SIGKILL); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return fmt.Errorf("stop Seatbelt process group: %w", err)
	}
	return nil
}

func (process *seatbeltProcess) writeControl(data []byte) error {
	process.controlMutex.Lock()
	defer process.controlMutex.Unlock()
	if process.control == nil {
		return os.ErrProcessDone
	}
	for len(data) > 0 {
		written, err := process.control.Write(data)
		if err != nil {
			return err
		}
		data = data[written:]
	}
	return nil
}

func (process *seatbeltProcess) closeControl() {
	process.controlMutex.Lock()
	defer process.controlMutex.Unlock()
	if process.control != nil {
		_ = process.control.Close()
	}
}

func (process *seatbeltProcess) writeTargetStatus(data []byte) error {
	status, err := seatbeltTargetStatus(data)
	if err != nil {
		return err
	}
	process.statusControlMutex.Lock()
	defer process.statusControlMutex.Unlock()
	if process.statusControl == nil {
		return os.ErrProcessDone
	}
	for len(status) > 0 {
		written, err := process.statusControl.Write(status)
		if err != nil {
			return err
		}
		status = status[written:]
	}
	return nil
}

func (process *seatbeltProcess) closeStatusControl() {
	process.statusControlMutex.Lock()
	defer process.statusControlMutex.Unlock()
	if process.statusControl != nil {
		_ = process.statusControl.Close()
	}
}

func (process *seatbeltProcess) reapStartedSupervisor() {
	waitDone := make(chan error, 1)
	process.retainLeaderWait(waitDone)
	go func() {
		waitDone <- process.command.Wait()
	}()
}

func (process *seatbeltProcess) stableProcessGroup() int {
	process.identityMutex.Lock()
	defer process.identityMutex.Unlock()
	return process.processGroup
}

func (process *seatbeltProcess) signalProcessGroup(processGroup int, signal syscall.Signal) error {
	kill := process.killProcessGroup
	if kill == nil {
		kill = func(group int, signal syscall.Signal) error {
			return syscall.Kill(-group, signal)
		}
	}
	return kill(processGroup, signal)
}

func (process *seatbeltProcess) settleProcessGroup() error {
	attempts := process.settlementAttempts
	if attempts <= 0 {
		attempts = seatbeltSettlementAttempts
	}
	retry := process.cleanupRetry
	if retry == nil {
		retry = func() { time.Sleep(seatbeltSettlementRetryDelay) }
	}
	processGroup := process.stableProcessGroup()
	if processGroup <= 0 {
		return errors.New("settle Seatbelt process group: stable identity is unavailable")
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		err := process.signalProcessGroup(processGroup, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		if err != nil {
			lastErr = err
		}
		if attempt+1 < attempts {
			retry()
		}
	}
	return fmt.Errorf("settle Seatbelt process group: %w", errors.Join(lastErr, context.DeadlineExceeded))
}

func (process *seatbeltProcess) restoreForegroundTerminal() error {
	if process.terminal == nil {
		return nil
	}
	setForeground := process.setForegroundProcessGroup
	if setForeground == nil {
		setForeground = setSeatbeltForegroundProcessGroup
	}
	return setForeground(process.terminal, process.foregroundGroup)
}

func (process *seatbeltProcess) markCleanupDone() {
	if process.cleanupDone == nil {
		return
	}
	process.cleanupDoneOnce.Do(func() { close(process.cleanupDone) })
}

func (process *seatbeltProcess) quarantineCleanup() {
	quarantine := process.cleanupQuarantine
	if quarantine == nil {
		quarantine = quarantineSeatbeltCleanup
	}
	quarantine(process)
}

func (process *seatbeltProcess) quarantineUnprovenCleanup() {
	seatbeltCleanupQuarantine.Lock()
	seatbeltCleanupQuarantine.processes[process] = struct{}{}
	seatbeltCleanupQuarantine.Unlock()
}

func (process *seatbeltProcess) retainLeaderWait(waitDone <-chan error) {
	process.leaderWaitMutex.Lock()
	process.leaderWaitDone = waitDone
	process.leaderWaitMutex.Unlock()
}

func (process *seatbeltProcess) awaitRetainedLeader() {
	process.leaderWaitMutex.Lock()
	waitDone := process.leaderWaitDone
	process.leaderWaitMutex.Unlock()
	if waitDone != nil {
		<-waitDone
	}
}

func seatbeltForegroundTerminal(terminal Terminal) (*os.File, int) {
	input, ok := terminal.Input.(*os.File)
	if !ok {
		return nil, 0
	}
	foregroundGroup, err := unix.IoctlGetInt(int(input.Fd()), unix.TIOCGPGRP)
	if err != nil || foregroundGroup != syscall.Getpgrp() {
		return nil, 0
	}
	return input, foregroundGroup
}

var seatbeltTerminalProcessGroupMutex sync.Mutex

func setSeatbeltForegroundProcessGroup(terminal *os.File, processGroup int) error {
	seatbeltTerminalProcessGroupMutex.Lock()
	defer seatbeltTerminalProcessGroupMutex.Unlock()
	alreadyIgnored := signal.Ignored(syscall.SIGTTOU)
	if !alreadyIgnored {
		signal.Ignore(syscall.SIGTTOU)
		defer signal.Reset(syscall.SIGTTOU)
	}
	return unix.IoctlSetPointerInt(int(terminal.Fd()), unix.TIOCSPGRP, processGroup)
}

var seatbeltCleanupQuarantine = struct {
	sync.Mutex
	processes map[*seatbeltProcess]struct{}
}{processes: make(map[*seatbeltProcess]struct{})}

func quarantineSeatbeltCleanup(process *seatbeltProcess) {
	seatbeltCleanupQuarantine.Lock()
	if _, exists := seatbeltCleanupQuarantine.processes[process]; exists {
		seatbeltCleanupQuarantine.Unlock()
		return
	}
	seatbeltCleanupQuarantine.processes[process] = struct{}{}
	seatbeltCleanupQuarantine.Unlock()
	go func() {
		for {
			if process.settleProcessGroup() == nil {
				process.awaitRetainedLeader()
				process.markCleanupDone()
				seatbeltCleanupQuarantine.Lock()
				delete(seatbeltCleanupQuarantine.processes, process)
				seatbeltCleanupQuarantine.Unlock()
				return
			}
			retry := process.quarantineRetry
			if retry == nil {
				retry = func() { time.Sleep(seatbeltQuarantineRetryDelay) }
			}
			retry()
		}
	}()
}

func buildSeatbeltPolicy(request validatedProcessRequest) (string, []string, error) {
	definitions := []string{
		"-DWORKSPACE=" + request.workspace,
		"-DSESSION=" + request.sessionDirectory,
		"-DEXECUTABLE=" + request.executable,
	}
	var executableAncestorRules strings.Builder
	for index, ancestor := range seatbeltExecutableAncestors(request.executable) {
		name := "EXECUTABLE_ANCESTOR_" + strconv.Itoa(index)
		definitions = append(definitions, "-D"+name+"="+ancestor)
		fmt.Fprintf(&executableAncestorRules, "\n  (literal (param %q))", name)
	}
	var runtimeRules strings.Builder
	for index, input := range request.runtimeInputs {
		name := "RUNTIME_" + strconv.Itoa(index)
		definitions = append(definitions, "-D"+name+"="+input)
		fmt.Fprintf(&runtimeRules, "\n  (literal (param %q))\n  (subpath (param %q))", name, name)
	}
	policy := `(version 1)
(deny default)

; A sandboxed target may create descendants and communicate with processes in
; the same sandbox. Seatbelt applies the profile to every descendant.
(allow process-exec)
(allow process-fork)
(allow process-info* (target same-sandbox))
(allow signal (target same-sandbox))

; Go runtime startup reads the host page size before initializing its heap and
; reads the CPU count while starting its scheduler.
(allow sysctl-read
  (sysctl-name "hw.pagesize")
  (sysctl-name "hw.pagesize_compat")
  (sysctl-name "hw.ncpu"))

; The root literal permits pathname traversal without granting descendants.
; The tested system roots below provide the dynamic runtime and fixed-PATH
; commands used by the credential-free compatibility harness.
(allow file-read*
  (literal "/")
  (literal "/System") (subpath "/System/Library")
  (literal "/usr") (subpath "/usr/bin") (subpath "/usr/lib")
  (literal "/bin") (subpath "/bin")
  (literal "/private") (literal "/private/var")
  (literal "/var")
  (literal "/private/var/select") (literal "/private/var/select/sh")
  (literal (param "SUPERVISOR"))
  (literal (param "EXECUTABLE"))
  (literal (param "WORKSPACE")) (subpath (param "WORKSPACE"))
  (literal (param "SESSION")) (subpath (param "SESSION"))` + runtimeRules.String() + `)

; Security.framework creates TLS policies by inspecting the running executable.
; Metadata access is restricted to the already validated executable's ancestors;
; it does not permit reading any directory's contents.
(allow file-read-metadata` + executableAncestorRules.String() + `)

; Writes are limited to the selected workspace and leased Session.
(allow file-write*
  (literal (param "WORKSPACE")) (subpath (param "WORKSPACE"))
  (literal (param "SESSION")) (subpath (param "SESSION")))

; Normal outbound IP traffic and the macOS DNS resolver are available. Other
; Unix sockets remain denied by default.
(allow network-bind (local ip))
(allow network-outbound
  (remote ip)
  (literal "/private/var/run/mDNSResponder"))

; Security.framework reads system trust settings and evaluates platform TLS
; through these exact Mach services. All other Mach services remain denied.
(allow mach-lookup
  (global-name "com.apple.SecurityServer"))
(allow mach-lookup
  (global-name "com.apple.trustd.agent"))

; Preserve the invoking terminal, raw mode, and resize operations.
(allow pseudo-tty)
(allow file-ioctl file-read-data file-write-data
  (literal "/dev/null")
  (literal "/dev/zero")
  (literal "/dev/random")
  (literal "/dev/urandom")
  (literal "/dev/ptmx")
  (literal "/dev/tty")
  (regex #"^/dev/ttys[0-9]+"))
(allow file-read-data file-write-data
  (literal "/dev/ptmx")
  (literal "/dev/tty")
  (regex #"^/dev/ttys[0-9]+")
  (literal "/dev/fd")
  (subpath "/dev/fd"))`
	return policy, definitions, nil
}

func seatbeltExecutableAncestors(executable string) []string {
	ancestors := make([]string, 0, 8)
	for ancestor := filepath.Dir(executable); ; ancestor = filepath.Dir(ancestor) {
		ancestors = append(ancestors, ancestor)
		if ancestor == string(filepath.Separator) {
			return ancestors
		}
	}
}
