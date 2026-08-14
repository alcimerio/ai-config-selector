//go:build linux

package launch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const bubblewrapExecutable = "/usr/bin/bwrap"
const dpkgExecutable = "/usr/bin/dpkg"
const dpkgQueryExecutable = "/usr/bin/dpkg-query"

const (
	bubblewrapInfoDescriptor    = 3
	bubblewrapReleaseDescriptor = 4
	bubblewrapStartupTimeout    = 10 * time.Second
	bubblewrapTeardownTimeout   = 5 * time.Second
)

func nativeSandboxBackends() map[string]sandboxBackend {
	return map[string]sandboxBackend{"linux": bubblewrapBackend{}}
}

type bubblewrapBackend struct{}

func (bubblewrapBackend) check(ctx context.Context) error {
	checker := bubblewrapTrustChecker{
		architecture:    runtime.GOARCH,
		validExecutable: validRootOwnedSystemExecutable,
		run:             runBubblewrapTrustCommand,
	}
	return checker.check(ctx)
}

type bubblewrapCommandResult struct {
	output []byte
	stderr []byte
	err    error
}

type bubblewrapTrustChecker struct {
	architecture    string
	validExecutable func(string) bool
	run             func(context.Context, string, ...string) bubblewrapCommandResult
}

func (checker bubblewrapTrustChecker) check(ctx context.Context) error {
	for _, executable := range []string{bubblewrapExecutable, dpkgQueryExecutable, dpkgExecutable} {
		if !checker.validExecutable(executable) {
			return bubblewrapUnavailable()
		}
	}
	owner := checker.run(ctx, dpkgQueryExecutable, "--search", bubblewrapExecutable)
	if !trustedCommandSucceeded(owner) {
		return bubblewrapUnavailable()
	}
	show := checker.run(ctx, dpkgQueryExecutable, "--show", "--showformat=${db:Status-Abbrev}\n${binary:Package}\n${source:Package}\n${Architecture}\n", "bubblewrap")
	if !trustedCommandSucceeded(show) || !validBubblewrapPackageRecord(string(owner.output), string(show.output), checker.architecture) {
		return bubblewrapUnavailable()
	}
	integrity := checker.run(ctx, dpkgExecutable, "--verify", "--verify-format=rpm", "bubblewrap")
	if !trustedCommandSucceeded(integrity) || len(integrity.output) != 0 {
		return bubblewrapUnavailable()
	}
	probe := checker.run(ctx, bubblewrapExecutable, bubblewrapCapabilityProbeArguments()...)
	if !trustedCommandSucceeded(probe) {
		return bubblewrapCapabilityUnavailable()
	}
	return nil
}

func bubblewrapCapabilityProbeArguments() []string {
	return []string{
		"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup",
		"--die-with-parent", "--clearenv", "--proc", "/proc", "--dev", "/dev",
		"--dir", "/tmp",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/sbin", "/sbin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--ro-bind", "/usr", "/usr", "--remount-ro", "/",
		"--setenv", "PATH", safeProcessPath, "--chdir", "/tmp", "--", "/usr/bin/true",
	}
}

func trustedCommandSucceeded(result bubblewrapCommandResult) bool {
	return result.err == nil && len(result.stderr) == 0
}

func runBubblewrapTrustCommand(ctx context.Context, path string, arguments ...string) bubblewrapCommandResult {
	command := exec.CommandContext(ctx, path, arguments...)
	if path == bubblewrapExecutable {
		var err error
		command, err = newBubblewrapCommand(ctx, arguments)
		if err != nil {
			return bubblewrapCommandResult{err: err}
		}
	}
	command.Env = []string{"LC_ALL=C", "PATH=" + safeProcessPath}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	return bubblewrapCommandResult{output: stdout.Bytes(), stderr: stderr.Bytes(), err: err}
}

func validRootOwnedSystemExecutable(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && validBubblewrapExecutableMetadata(info.Mode(), stat.Uid)
}

func (bubblewrapBackend) prepare(ctx context.Context, request validatedProcessRequest) (Process, error) {
	informationReader, informationWriter, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	releaseReader, releaseWriter, err := os.Pipe()
	if err != nil {
		_ = informationReader.Close()
		_ = informationWriter.Close()
		return nil, err
	}
	arguments := append([]string{
		"--as-pid-1",
		"--info-fd", strconv.Itoa(bubblewrapInfoDescriptor),
		"--userns-block-fd", strconv.Itoa(bubblewrapReleaseDescriptor),
		// Bubblewrap 0.9 leaves the userns-block descriptor open in the
		// sandbox child. Consume that duplicate during setup, then cover the
		// temporary file with the empty /run mount before the target execs.
		"--dir", "/run",
		"--file", strconv.Itoa(bubblewrapReleaseDescriptor), "/run/.acs-userns-handshake",
		"--tmpfs", "/run",
		"--remount-ro", "/run",
	}, bubblewrapArguments(request)...)
	command, err := newBubblewrapCommand(ctx, arguments, informationWriter, releaseReader)
	if err != nil {
		_ = informationReader.Close()
		_ = informationWriter.Close()
		_ = releaseReader.Close()
		_ = releaseWriter.Close()
		return nil, err
	}
	command.Env = []string{}
	command.Stdin = request.terminal.Input
	command.Stdout = request.terminal.Output
	command.Stderr = request.terminal.ErrorOutput
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	process := &bubblewrapProcess{
		ctx:               ctx,
		command:           command,
		information:       informationReader,
		release:           releaseWriter,
		childDescriptors:  []*os.File{informationWriter, releaseReader},
		monitorDescriptor: -1,
		targetDescriptor:  -1,
		cleanupDone:       make(chan struct{}),
	}
	command.Cancel = process.cancel
	return process, nil
}

type bubblewrapProcess struct {
	ctx                     context.Context
	command                 *exec.Cmd
	information             *os.File
	release                 *os.File
	childDescriptors        []*os.File
	monitorDescriptor       int
	targetDescriptor        int
	targetPID               int
	handshakeTimeout        time.Duration
	monitorPidfdOpen        func(int, int) (int, error)
	monitorPidfdSignal      func(int, unix.Signal) error
	monitorPidfdClose       func(int) error
	monitorPidfdStopped     func(int) error
	monitorPidfdWait        func(int) error
	monitorWaitid           func(int, int, *unix.Siginfo, int, *unix.Rusage) error
	monitorChildren         func(int) ([]int, error)
	monitorWait             func() error
	monitorKill             func() error
	pidfdOpen               func(int, int) (int, error)
	pidfdAlive              func(int) error
	pidfdSignal             func(int, unix.Signal) error
	pidfdClose              func(int) error
	pidfdWait               func(int) error
	pidfdPoll               func([]unix.PollFd, int) (int, error)
	teardownTimeout         time.Duration
	cleanupRetry            func()
	cleanupQuarantine       func(*bubblewrapProcess)
	configureUserNS         func(int) error
	releaseReady            func(int, int) error
	targetReady             func(int, int) (bool, error)
	signalCaught            func(int, syscall.Signal) (bool, error)
	afterFunc               func(context.Context, func()) func() bool
	startupIdentityMutex    sync.Mutex
	cleanupMutex            sync.Mutex
	cleanupDone             chan struct{}
	cleanupDoneOnce         sync.Once
	preIdentityChildrenDead bool
	preIdentityCleanupDone  bool
	mutex                   sync.Mutex
}

type bubblewrapInformation struct {
	ChildPID int `json:"child-pid"`
}

func (process *bubblewrapProcess) Start() error {
	process.startupIdentityMutex.Lock()
	if err := process.command.Start(); err != nil {
		process.startupIdentityMutex.Unlock()
		process.closeStartupDescriptors()
		process.markCleanupDone()
		return err
	}
	for _, descriptor := range process.childDescriptors {
		_ = descriptor.Close()
	}
	process.childDescriptors = nil
	openMonitor := process.monitorPidfdOpen
	if openMonitor == nil {
		openMonitor = unix.PidfdOpen
	}
	monitorDescriptor, err := openMonitor(process.command.Process.Pid, 0)
	if err != nil {
		process.startupIdentityMutex.Unlock()
		return process.abortStart(fmt.Errorf("open Bubblewrap monitor identity: %w", err))
	}
	process.mutex.Lock()
	process.monitorDescriptor = monitorDescriptor
	process.mutex.Unlock()
	process.startupIdentityMutex.Unlock()

	timeout := process.handshakeTimeout
	if timeout <= 0 {
		timeout = bubblewrapStartupTimeout
	}
	handshakeContext, cancel := context.WithTimeout(process.ctx, timeout)
	informationFile := process.information
	afterFunc := process.afterFunc
	if afterFunc == nil {
		afterFunc = context.AfterFunc
	}
	stopClose := afterFunc(handshakeContext, func() { _ = informationFile.Close() })
	var information bubblewrapInformation
	err = json.NewDecoder(informationFile).Decode(&information)
	contextErr := handshakeContext.Err()
	stopClose()
	cancel()
	_ = informationFile.Close()
	process.information = nil
	if contextErr != nil {
		return process.abortStart(fmt.Errorf("Bubblewrap startup handshake: %w", contextErr))
	}
	if err != nil {
		return process.abortStart(fmt.Errorf("Bubblewrap startup handshake: %w", err))
	}
	if information.ChildPID <= 0 {
		return process.abortStart(errors.New("Bubblewrap startup handshake returned an invalid child process"))
	}

	open := process.pidfdOpen
	if open == nil {
		open = unix.PidfdOpen
	}
	descriptor, err := open(information.ChildPID, 0)
	if err != nil {
		return process.abortStart(fmt.Errorf("open Bubblewrap target identity: %w", err))
	}
	process.mutex.Lock()
	process.targetDescriptor = descriptor
	process.targetPID = information.ChildPID
	process.mutex.Unlock()
	if err := process.stableTargetAlive(); err != nil {
		return process.abortStart(fmt.Errorf("verify Bubblewrap target identity: %w", err))
	}
	configureUserNS := process.configureUserNS
	if configureUserNS == nil {
		configureUserNS = configureBubblewrapUserNamespace
	}
	if err := configureUserNS(information.ChildPID); err != nil {
		return process.abortStart(fmt.Errorf("configure Bubblewrap user namespace: %w", err))
	}
	if err := process.ctx.Err(); err != nil {
		return process.abortStart(fmt.Errorf("configure Bubblewrap user namespace: %w", err))
	}
	if err := process.stableTargetAlive(); err != nil {
		return process.abortStart(fmt.Errorf("reverify Bubblewrap target identity: %w", err))
	}
	releaseReady := process.releaseReady
	if releaseReady == nil {
		releaseReady = bubblewrapTargetBlocked
	}
	if err := releaseReady(process.targetPID, process.targetDescriptor); err != nil {
		return process.abortStart(fmt.Errorf("verify Bubblewrap target readiness: %w", err))
	}
	if err := process.ctx.Err(); err != nil {
		return process.abortStart(fmt.Errorf("release Bubblewrap target: %w", err))
	}

	if _, err := process.release.Write([]byte{1}); err != nil {
		return process.abortStart(fmt.Errorf("release Bubblewrap target: %w", err))
	}
	_ = process.release.Close()
	process.release = nil
	if err := process.waitForTarget(timeout); err != nil {
		return process.abortStart(err)
	}
	return nil
}

func bubblewrapTargetBlocked(pid, descriptor int) error {
	runsBubblewrap, err := stableBubblewrapTarget(pid, descriptor)
	if err != nil {
		return err
	}
	if !runsBubblewrap {
		return errors.New("Bubblewrap target left the release barrier")
	}
	return nil
}

func (process *bubblewrapProcess) stableTargetAlive() error {
	alive := process.pidfdAlive
	if alive == nil {
		alive = func(descriptor int) error {
			return unix.PidfdSendSignal(descriptor, 0, nil, 0)
		}
	}
	return alive(process.targetDescriptor)
}

func configureBubblewrapUserNamespace(pid int) error {
	proc := filepath.Join("/proc", strconv.Itoa(pid))
	if err := os.WriteFile(filepath.Join(proc, "setgroups"), []byte("deny\n"), 0); err != nil {
		return err
	}
	uid := strconv.Itoa(os.Getuid())
	if err := os.WriteFile(filepath.Join(proc, "uid_map"), []byte(uid+" "+uid+" 1\n"), 0); err != nil {
		return err
	}
	gid := strconv.Itoa(os.Getgid())
	if err := os.WriteFile(filepath.Join(proc, "gid_map"), []byte(gid+" "+gid+" 1\n"), 0); err != nil {
		return err
	}
	return nil
}

func (process *bubblewrapProcess) Wait() error {
	waitErr := process.command.Wait()
	process.mutex.Lock()
	targetDescriptor := process.targetDescriptor
	monitorDescriptor := process.monitorDescriptor
	process.mutex.Unlock()
	var targetErr, monitorErr error
	if targetDescriptor >= 0 {
		// The target is PID 1 in the private PID namespace. Linux tears down
		// every remaining namespace process before this stable pidfd reports
		// exit, so this is also a direct kernel proof of whole-tree death.
		targetErr = process.waitStableTargetExit(targetDescriptor)
	}
	if monitorDescriptor >= 0 {
		monitorErr = process.waitStableMonitorExit(monitorDescriptor)
	}
	if cleanupErr := errors.Join(targetErr, monitorErr); cleanupErr != nil {
		process.quarantineCleanup()
		return errors.Join(waitErr, cleanupErr)
	}
	process.closeIdentityDescriptors()
	process.markCleanupDone()
	return waitErr
}

func (process *bubblewrapProcess) CleanupDone() <-chan struct{} {
	return process.cleanupDone
}

func (process *bubblewrapProcess) markCleanupDone() {
	if process.cleanupDone == nil {
		return
	}
	process.cleanupDoneOnce.Do(func() { close(process.cleanupDone) })
}

func (process *bubblewrapProcess) Signal(signal os.Signal) error {
	process.mutex.Lock()
	defer process.mutex.Unlock()
	descriptor := process.targetDescriptor
	if descriptor < 0 {
		return errors.New("process has not started")
	}
	systemSignal, ok := signal.(syscall.Signal)
	if !ok {
		return fmt.Errorf("unsupported Linux process signal %T", signal)
	}
	caught := process.signalCaught
	if caught == nil {
		caught = linuxProcessCatchesSignal
	}
	if handlesSignal, err := caught(process.targetPID, systemSignal); err == nil && handlesSignal {
		return process.signalStableTarget(descriptor, unix.Signal(systemSignal))
	}
	if !linuxSignalTerminatesProcess(systemSignal) {
		return process.signalStableTarget(descriptor, unix.Signal(systemSignal))
	}
	// A PID namespace's PID 1 ignores unhandled terminating signals. Stop it
	// before signaling the monitor so it cannot win the exit-status race, then
	// kill the stable target explicitly: AppArmor exec transitions can make
	// Bubblewrap's inherited parent-death signal insufficient for teardown.
	if err := process.signalStableTarget(descriptor, unix.SIGSTOP); err != nil {
		return err
	}
	monitorErr := process.signalStableMonitor(process.monitorDescriptor, unix.Signal(systemSignal))
	var monitorWaitErr error
	if monitorErr == nil {
		monitorWaitErr = process.waitStableMonitorExit(process.monitorDescriptor)
	}
	targetErr := process.signalStableTarget(descriptor, unix.SIGKILL)
	if targetErr != nil && !errors.Is(targetErr, unix.ESRCH) {
		targetErr = fmt.Errorf("stop Bubblewrap target after monitor exit: %w", targetErr)
	} else {
		targetErr = nil
	}
	return errors.Join(monitorErr, monitorWaitErr, targetErr)
}

func linuxSignalTerminatesProcess(signal syscall.Signal) bool {
	switch signal {
	case syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGILL,
		syscall.SIGABRT, syscall.SIGBUS, syscall.SIGFPE, syscall.SIGKILL,
		syscall.SIGUSR1, syscall.SIGSEGV, syscall.SIGUSR2, syscall.SIGPIPE,
		syscall.SIGALRM, syscall.SIGTERM, syscall.SIGSTKFLT, syscall.SIGXCPU,
		syscall.SIGXFSZ, syscall.SIGVTALRM, syscall.SIGPROF, syscall.SIGIO,
		syscall.SIGPWR, syscall.SIGSYS, syscall.SIGTRAP:
		return true
	default:
		return false
	}
}

func (process *bubblewrapProcess) signalStableTarget(descriptor int, signal unix.Signal) error {
	signalTarget := process.pidfdSignal
	if signalTarget == nil {
		signalTarget = func(descriptor int, signal unix.Signal) error {
			return unix.PidfdSendSignal(descriptor, signal, nil, 0)
		}
	}
	return signalTarget(descriptor, signal)
}

func (process *bubblewrapProcess) signalStableMonitor(descriptor int, signal unix.Signal) error {
	signalMonitor := process.monitorPidfdSignal
	if signalMonitor == nil {
		signalMonitor = func(descriptor int, signal unix.Signal) error {
			return unix.PidfdSendSignal(descriptor, signal, nil, 0)
		}
	}
	return signalMonitor(descriptor, signal)
}

func (process *bubblewrapProcess) waitStableTargetExit(descriptor int) error {
	wait := process.pidfdWait
	if wait != nil {
		return wait(descriptor)
	}
	return process.pollStableExit(descriptor)
}

func (process *bubblewrapProcess) waitStableMonitorExit(descriptor int) error {
	wait := process.monitorPidfdWait
	if wait != nil {
		return wait(descriptor)
	}
	return process.pollStableExit(descriptor)
}

func (process *bubblewrapProcess) pollStableExit(descriptor int) error {
	timeout := process.teardownTimeout
	if timeout <= 0 {
		timeout = bubblewrapTeardownTimeout
	}
	deadline := time.Now().Add(timeout)
	pollDescriptor := process.pidfdPoll
	if pollDescriptor == nil {
		pollDescriptor = unix.Poll
	}
	poll := []unix.PollFd{{Fd: int32(descriptor), Events: unix.POLLIN}}
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return fmt.Errorf("pidfd exit proof: %w", context.DeadlineExceeded)
		}
		pollMilliseconds := int((remaining + time.Millisecond - 1) / time.Millisecond)
		ready, err := pollDescriptor(poll, pollMilliseconds)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if ready == 1 && poll[0].Revents&unix.POLLIN != 0 {
			return nil
		}
		if ready == 0 {
			continue
		}
		return fmt.Errorf("pidfd wait returned revents %#x", poll[0].Revents)
	}
}

func (process *bubblewrapProcess) stableExitReady(descriptor int) (bool, error) {
	pollDescriptor := process.pidfdPoll
	if pollDescriptor == nil {
		pollDescriptor = unix.Poll
	}
	poll := []unix.PollFd{{Fd: int32(descriptor), Events: unix.POLLIN}}
	ready, err := pollDescriptor(poll, 0)
	if err != nil {
		return false, err
	}
	return ready == 1 && poll[0].Revents&unix.POLLIN != 0, nil
}

func (process *bubblewrapProcess) waitStableStop(descriptor int) error {
	waitStopped := process.monitorWaitid
	if waitStopped == nil {
		waitStopped = unix.Waitid
	}
	timeout := process.teardownTimeout
	if timeout <= 0 {
		timeout = bubblewrapTeardownTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		var information unix.Siginfo
		err := waitStopped(unix.P_PIDFD, descriptor, &information, unix.WSTOPPED|unix.WNOWAIT|unix.WNOHANG, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if information.Signo != 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("pidfd stop proof: %w", context.DeadlineExceeded)
		}
		time.Sleep(time.Millisecond)
	}
}

func linuxProcessCatchesSignal(pid int, signal syscall.Signal) (bool, error) {
	contents, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return false, err
	}
	for _, line := range bytes.Split(contents, []byte{'\n'}) {
		value, found := bytes.CutPrefix(line, []byte("SigCgt:"))
		if !found {
			continue
		}
		mask, err := strconv.ParseUint(string(bytes.TrimSpace(value)), 16, 64)
		if err != nil {
			return false, fmt.Errorf("parse Linux caught-signal mask: %w", err)
		}
		if signal <= 0 || signal > 64 {
			return false, nil
		}
		return mask&(uint64(1)<<uint(signal-1)) != 0, nil
	}
	return false, errors.New("Linux process status lacks caught-signal mask")
}

func (process *bubblewrapProcess) waitForTarget(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(process.ctx, timeout)
	defer cancel()
	ready := process.targetReady
	if ready == nil {
		ready = bubblewrapTargetReady
	}
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("Bubblewrap target readiness: %w", err)
		}
		isReady, err := ready(process.targetPID, process.targetDescriptor)
		if err == nil && isReady {
			if err := ctx.Err(); err != nil {
				return fmt.Errorf("Bubblewrap target readiness: %w", err)
			}
			return nil
		}
		if errors.Is(err, unix.ESRCH) {
			// The stable pidfd proves the reported process exited; Wait retains
			// Bubblewrap's normal setup or target exit status.
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("Bubblewrap target readiness: %w", ctx.Err())
		case <-time.After(time.Millisecond):
		}
	}
}

func bubblewrapTargetReady(pid, descriptor int) (bool, error) {
	runsBubblewrap, err := stableBubblewrapTarget(pid, descriptor)
	if err != nil {
		return false, err
	}
	return !runsBubblewrap, nil
}

func stableBubblewrapTarget(pid, descriptor int) (bool, error) {
	if err := unix.PidfdSendSignal(descriptor, 0, nil, 0); err != nil {
		return false, err
	}
	target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe"))
	if err != nil {
		return false, err
	}
	bubblewrap, err := filepath.EvalSymlinks(bubblewrapExecutable)
	if err != nil {
		return false, err
	}
	if err := unix.PidfdSendSignal(descriptor, 0, nil, 0); err != nil {
		return false, err
	}
	return target == bubblewrap, nil
}

func (process *bubblewrapProcess) abortStart(startErr error) error {
	// Bubblewrap 0.9 treats EOF on --userns-block-fd as permission to
	// continue. Keep the release writer open until a stable identity has
	// been stopped, otherwise cleanup itself can launch the requested target.
	process.mutex.Lock()
	targetDescriptor := process.targetDescriptor
	targetKnown := targetDescriptor >= 0
	process.mutex.Unlock()
	targetStopped, _ := process.stopStableTarget()
	if targetStopped {
		if targetErr := process.waitStableTargetExit(targetDescriptor); targetErr != nil {
			process.quarantineCleanup()
			return errors.Join(startErr, targetErr)
		}
		process.closeStartupDescriptors()
		if monitorErr := process.stopStableMonitorAndWait(); monitorErr != nil {
			process.quarantineCleanup()
			return errors.Join(startErr, monitorErr)
		}
		process.reapStableMonitor()
	} else if targetKnown {
		// If signaling an identified, still-blocked target fails, keep the gate
		// closed until the monitor is dead so its installed parent-death signal
		// remains the fail-closed fallback.
		if monitorErr := process.stopStableMonitorAndWait(); monitorErr != nil {
			process.quarantineCleanup()
			return errors.Join(startErr, monitorErr)
		}
		process.reapStableMonitor()
		if targetErr := process.waitStableTargetExit(targetDescriptor); targetErr != nil {
			process.quarantineCleanup()
			return errors.Join(startErr, targetErr)
		}
		process.closeStartupDescriptors()
	} else {
		// Before info-fd yields the target identity, freeze the stable monitor.
		// That makes its child list immutable and keeps exited children from PID
		// reuse while stable pidfds are opened. Kill and prove every child dead
		// before killing the monitor or releasing the startup gate: Bubblewrap
		// 0.9 can clone its namespace child before installing --die-with-parent.
		if cleanupErr := process.stopStableMonitorTree(); cleanupErr != nil {
			// Keep the release gate and stable monitor identity open when the
			// frozen-tree invariant itself cannot be established. Closing either
			// could release an unproven namespace child.
			process.quarantineCleanup()
			return errors.Join(startErr, cleanupErr)
		}
		process.reapStableMonitor()
		process.closeStartupDescriptors()
	}
	process.closeIdentityDescriptors()
	process.markCleanupDone()
	return startErr
}

func (process *bubblewrapProcess) quarantineCleanup() {
	quarantine := process.cleanupQuarantine
	if quarantine == nil {
		quarantine = quarantineBubblewrapCleanup
	}
	quarantine(process)
}

func (process *bubblewrapProcess) cancel() error {
	// exec.Cmd may invoke Cancel as soon as Start returns internally. Wait
	// until Start's attempt to install the stable monitor identity concludes
	// before choosing the teardown path.
	process.startupIdentityMutex.Lock()
	process.startupIdentityMutex.Unlock()
	process.mutex.Lock()
	targetKnown := process.targetDescriptor >= 0
	process.mutex.Unlock()
	if !targetKnown {
		return process.stopStableMonitorTree()
	}
	_, targetErr := process.stopStableTarget()
	monitorErr := process.stopStableMonitor()
	return errors.Join(targetErr, monitorErr)
}

func (process *bubblewrapProcess) stopStableTarget() (bool, error) {
	process.mutex.Lock()
	descriptor := process.targetDescriptor
	process.mutex.Unlock()
	if descriptor < 0 {
		return false, nil
	}
	err := process.signalStableTarget(descriptor, unix.SIGKILL)
	if err == nil || errors.Is(err, unix.ESRCH) {
		return true, nil
	}
	return false, fmt.Errorf("stop Bubblewrap target: %w", err)
}

func (process *bubblewrapProcess) stopStableMonitor() error {
	process.mutex.Lock()
	descriptor := process.monitorDescriptor
	process.mutex.Unlock()
	var signalErr error
	if descriptor >= 0 {
		signalErr = process.signalStableMonitor(descriptor, unix.SIGKILL)
		if signalErr == nil {
			return nil
		}
		if errors.Is(signalErr, unix.ESRCH) {
			return os.ErrProcessDone
		}
	}
	if process.command.Process != nil {
		killMonitor := process.monitorKill
		if killMonitor == nil {
			killMonitor = process.command.Process.Kill
		}
		if err := killMonitor(); err == nil {
			return nil
		} else if errors.Is(err, os.ErrProcessDone) {
			return os.ErrProcessDone
		} else {
			return errors.Join(signalErr, fmt.Errorf("stop Bubblewrap monitor: %w", err))
		}
	}
	return signalErr
}

func (process *bubblewrapProcess) stopStableMonitorAndWait() error {
	if err := process.stopStableMonitor(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	process.mutex.Lock()
	descriptor := process.monitorDescriptor
	process.mutex.Unlock()
	if descriptor < 0 {
		return errors.New("Bubblewrap monitor identity is unavailable")
	}
	wait := process.monitorPidfdWait
	if wait != nil {
		return wait(descriptor)
	}
	return process.waitStableMonitorExit(descriptor)
}

func (process *bubblewrapProcess) stopStableMonitorTree() error {
	process.cleanupMutex.Lock()
	defer process.cleanupMutex.Unlock()
	if process.preIdentityCleanupDone {
		return nil
	}
	if process.preIdentityChildrenDead {
		monitorErr := process.stopStableMonitorAndWait()
		if monitorErr == nil {
			process.preIdentityCleanupDone = true
			return nil
		}
		return monitorErr
	}
	process.mutex.Lock()
	descriptor := process.monitorDescriptor
	monitorPID := 0
	if process.command.Process != nil {
		monitorPID = process.command.Process.Pid
	}
	process.mutex.Unlock()
	if monitorPID <= 0 {
		return errors.New("Bubblewrap monitor identity is unavailable")
	}
	if descriptor < 0 {
		openMonitor := process.monitorPidfdOpen
		if openMonitor == nil {
			openMonitor = unix.PidfdOpen
		}
		openedDescriptor, err := openMonitor(monitorPID, 0)
		if err != nil {
			return fmt.Errorf("recover Bubblewrap monitor identity: %w", err)
		}
		process.mutex.Lock()
		if process.monitorDescriptor < 0 {
			process.monitorDescriptor = openedDescriptor
			descriptor = openedDescriptor
		} else {
			descriptor = process.monitorDescriptor
			closeDescriptor := process.monitorPidfdClose
			if closeDescriptor == nil {
				closeDescriptor = unix.Close
			}
			_ = closeDescriptor(openedDescriptor)
		}
		process.mutex.Unlock()
	}
	if err := process.signalStableMonitor(descriptor, unix.SIGSTOP); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return fmt.Errorf("freeze Bubblewrap monitor: %w", err)
	}
	waitStopped := process.monitorPidfdStopped
	if waitStopped == nil {
		waitStopped = process.waitStableStop
	}
	if err := waitStopped(descriptor); err != nil {
		if exited, pollErr := process.stableExitReady(descriptor); exited && pollErr == nil {
			return os.ErrProcessDone
		}
		return fmt.Errorf("prove Bubblewrap monitor stopped: %w", err)
	}
	children := process.monitorChildren
	if children == nil {
		children = bubblewrapMonitorChildren
	}
	open := process.pidfdOpen
	if open == nil {
		open = unix.PidfdOpen
	}
	closeDescriptor := process.pidfdClose
	if closeDescriptor == nil {
		closeDescriptor = unix.Close
	}
	retry := process.cleanupRetry
	if retry == nil {
		retry = func() { time.Sleep(time.Millisecond) }
	}
	cleanupTimeout := process.teardownTimeout
	if cleanupTimeout <= 0 {
		cleanupTimeout = bubblewrapTeardownTimeout
	}
	deadline := time.Now().Add(cleanupTimeout)
	var lastErr error
	for {
		childPIDs, err := children(monitorPID)
		childDescriptors := make([]int, 0, len(childPIDs))
		if err == nil {
			for _, childPID := range childPIDs {
				childDescriptor, openErr := open(childPID, 0)
				if openErr != nil {
					err = fmt.Errorf("open frozen Bubblewrap child identity: %w", openErr)
					break
				}
				childDescriptors = append(childDescriptors, childDescriptor)
			}
		}
		if err == nil {
			for _, childDescriptor := range childDescriptors {
				if signalErr := process.signalStableTarget(childDescriptor, unix.SIGKILL); signalErr != nil && !errors.Is(signalErr, unix.ESRCH) {
					err = fmt.Errorf("stop frozen Bubblewrap child: %w", signalErr)
					break
				}
			}
		}
		if err == nil {
			for _, childDescriptor := range childDescriptors {
				if waitErr := process.waitStableTargetExit(childDescriptor); waitErr != nil {
					err = fmt.Errorf("prove frozen Bubblewrap child exited: %w", waitErr)
					break
				}
			}
		}
		for _, childDescriptor := range childDescriptors {
			_ = closeDescriptor(childDescriptor)
		}
		if err == nil {
			break
		}
		lastErr = err
		if time.Now().After(deadline) {
			return errors.Join(lastErr, fmt.Errorf("clean frozen Bubblewrap children: %w", context.DeadlineExceeded))
		}
		retry()
	}
	process.preIdentityChildrenDead = true
	monitorErr := process.stopStableMonitorAndWait()
	if monitorErr == nil {
		process.preIdentityCleanupDone = true
		return nil
	}
	return monitorErr
}

var bubblewrapCleanupQuarantine = struct {
	sync.Mutex
	processes map[*bubblewrapProcess]struct{}
}{processes: make(map[*bubblewrapProcess]struct{})}

func quarantineBubblewrapCleanup(process *bubblewrapProcess) {
	bubblewrapCleanupQuarantine.Lock()
	if _, exists := bubblewrapCleanupQuarantine.processes[process]; exists {
		bubblewrapCleanupQuarantine.Unlock()
		return
	}
	bubblewrapCleanupQuarantine.processes[process] = struct{}{}
	bubblewrapCleanupQuarantine.Unlock()
	go func() {
		for {
			process.mutex.Lock()
			targetDescriptor := process.targetDescriptor
			targetKnown := targetDescriptor >= 0
			process.mutex.Unlock()
			var cleanupErr error
			if targetKnown {
				_, _ = process.stopStableTarget()
				cleanupErr = process.stopStableMonitorAndWait()
				if cleanupErr == nil {
					process.reapStableMonitor()
					cleanupErr = process.waitStableTargetExit(targetDescriptor)
				}
			} else {
				cleanupErr = process.stopStableMonitorTree()
				if cleanupErr == nil {
					process.reapStableMonitor()
				}
			}
			if cleanupErr != nil {
				time.Sleep(100 * time.Millisecond)
				continue
			}
			process.closeStartupDescriptors()
			process.closeIdentityDescriptors()
			process.markCleanupDone()
			bubblewrapCleanupQuarantine.Lock()
			delete(bubblewrapCleanupQuarantine.processes, process)
			bubblewrapCleanupQuarantine.Unlock()
			return
		}
	}()
}

func bubblewrapMonitorChildren(pid int) ([]int, error) {
	tasks, err := os.ReadDir(filepath.Join("/proc", strconv.Itoa(pid), "task"))
	if err != nil {
		return nil, err
	}
	seen := make(map[int]struct{})
	var children []int
	for _, task := range tasks {
		contents, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "task", task.Name(), "children"))
		if err != nil {
			return nil, err
		}
		for _, field := range bytes.Fields(contents) {
			childPID, err := strconv.Atoi(string(field))
			if err != nil || childPID <= 0 {
				return nil, fmt.Errorf("invalid Bubblewrap child PID %q", field)
			}
			if _, exists := seen[childPID]; exists {
				continue
			}
			seen[childPID] = struct{}{}
			children = append(children, childPID)
		}
	}
	return children, nil
}

func (process *bubblewrapProcess) reapStableMonitor() {
	wait := process.monitorWait
	if wait != nil {
		_ = wait()
		return
	}
	if process.command.Process != nil {
		_ = process.command.Wait()
	}
}

func (process *bubblewrapProcess) closeStartupDescriptors() {
	if process.information != nil {
		_ = process.information.Close()
		process.information = nil
	}
	if process.release != nil {
		_ = process.release.Close()
		process.release = nil
	}
	for _, descriptor := range process.childDescriptors {
		_ = descriptor.Close()
	}
	process.childDescriptors = nil
}

func (process *bubblewrapProcess) closeIdentityDescriptors() {
	process.mutex.Lock()
	defer process.mutex.Unlock()
	if process.targetDescriptor >= 0 {
		closeDescriptor := process.pidfdClose
		if closeDescriptor == nil {
			closeDescriptor = unix.Close
		}
		_ = closeDescriptor(process.targetDescriptor)
		process.targetDescriptor = -1
	}
	if process.monitorDescriptor >= 0 {
		closeDescriptor := process.monitorPidfdClose
		if closeDescriptor == nil {
			closeDescriptor = unix.Close
		}
		_ = closeDescriptor(process.monitorDescriptor)
		process.monitorDescriptor = -1
	}
}
