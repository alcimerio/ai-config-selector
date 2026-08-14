//go:build darwin

package launch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const seatbeltExecutable = "/usr/bin/sandbox-exec"

type seatbeltPolicyBuilder func(validatedProcessRequest) (string, []string, error)

type seatbeltBackend struct {
	executable string
	policy     seatbeltPolicyBuilder
}

func newSeatbeltBackend(executable string) *seatbeltBackend {
	return &seatbeltBackend{executable: executable, policy: buildSeatbeltPolicy}
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
	policy := `(version 1)
(deny default)
(allow process-exec)
(allow file-read* (literal "/") (literal "/usr") (literal "/usr/bin/true"))`
	command := exec.CommandContext(ctx, backend.executable, "-p", policy, "--", "/usr/bin/true")
	command.Env = []string{"PATH=" + safeProcessPath}
	command.Stdin = nil
	command.Stdout = nil
	command.Stderr = nil
	command.ExtraFiles = nil
	if err := command.Run(); err != nil {
		return sandboxError(SandboxBackendUnavailable, err)
	}
	return nil
}

func (backend *seatbeltBackend) prepare(ctx context.Context, request validatedProcessRequest) (Process, error) {
	policy, definitions, err := backend.policy(request)
	if err != nil {
		return nil, sandboxError(SandboxSetupFailed, err)
	}
	if err := backend.validateGeneratedPolicy(ctx, request, policy, definitions); err != nil {
		return nil, sandboxError(SandboxSetupFailed, err)
	}
	arguments := make([]string, 0, 4+len(definitions)+len(request.arguments))
	arguments = append(arguments, "-p", policy)
	arguments = append(arguments, definitions...)
	arguments = append(arguments, "--", request.executable)
	arguments = append(arguments, request.arguments...)
	command := exec.CommandContext(ctx, backend.executable, arguments...)
	command.Dir = request.workspace
	command.Env = append([]string(nil), request.environment...)
	command.Stdin = request.terminal.Input
	command.Stdout = request.terminal.Output
	command.Stderr = request.terminal.ErrorOutput
	command.ExtraFiles = nil
	terminal, foregroundGroup := seatbeltForegroundTerminal(request.terminal)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if terminal != nil {
		command.SysProcAttr.Foreground = true
		command.SysProcAttr.Ctty = int(terminal.Fd())
	}
	command.Cancel = func() error {
		if command.Process == nil {
			return os.ErrProcessDone
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = time.Second
	return &seatbeltProcess{command: command, terminal: terminal, foregroundGroup: foregroundGroup}, nil
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
	command         *exec.Cmd
	terminal        *os.File
	foregroundGroup int
}

func (process *seatbeltProcess) Start() error { return process.command.Start() }

func (process *seatbeltProcess) Wait() error {
	waitErr := process.command.Wait()
	pid := process.command.Process.Pid
	settleSeatbeltProcessGroup(pid)
	if process.terminal != nil {
		if err := setSeatbeltForegroundProcessGroup(process.terminal, process.foregroundGroup); err != nil {
			return errors.Join(waitErr, err)
		}
	}
	return waitErr
}

func (process *seatbeltProcess) Signal(signal os.Signal) error {
	if process.command.Process == nil {
		return os.ErrProcessDone
	}
	unixSignal, ok := signal.(syscall.Signal)
	if !ok {
		return process.command.Process.Signal(signal)
	}
	err := syscall.Kill(-process.command.Process.Pid, unixSignal)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
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

func settleSeatbeltProcessGroup(processGroup int) {
	for {
		err := syscall.Kill(-processGroup, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func buildSeatbeltPolicy(request validatedProcessRequest) (string, []string, error) {
	definitions := []string{
		"-DWORKSPACE=" + request.workspace,
		"-DSESSION=" + request.sessionDirectory,
		"-DEXECUTABLE=" + request.executable,
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
  (literal "/private/var/select") (literal "/private/var/select/sh")
  (literal (param "EXECUTABLE"))
  (literal (param "WORKSPACE")) (subpath (param "WORKSPACE"))
  (literal (param "SESSION")) (subpath (param "SESSION"))` + runtimeRules.String() + `)

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
