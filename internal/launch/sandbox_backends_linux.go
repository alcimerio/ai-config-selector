//go:build linux

package launch

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

const bubblewrapExecutable = "/usr/bin/bwrap"
const dpkgExecutable = "/usr/bin/dpkg"
const dpkgQueryExecutable = "/usr/bin/dpkg-query"

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
	command, err := newBubblewrapCommand(ctx, bubblewrapArguments(request))
	if err != nil {
		return nil, err
	}
	command.Env = []string{}
	command.Stdin = request.terminal.Input
	command.Stdout = request.terminal.Output
	command.Stderr = request.terminal.ErrorOutput
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return &bubblewrapProcess{command: command}, nil
}

type bubblewrapProcess struct {
	command *exec.Cmd
}

func (process *bubblewrapProcess) Start() error { return process.command.Start() }
func (process *bubblewrapProcess) Wait() error  { return process.command.Wait() }
func (process *bubblewrapProcess) Signal(signal os.Signal) error {
	if process.command.Process == nil {
		return errors.New("process has not started")
	}
	return process.command.Process.Signal(signal)
}
