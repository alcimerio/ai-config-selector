//go:build linux

package launch

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"syscall"
)

const bubblewrapExecutable = "/usr/bin/bwrap"
const dpkgQueryExecutable = "/usr/bin/dpkg-query"

func nativeSandboxBackends() map[string]sandboxBackend {
	return map[string]sandboxBackend{"linux": bubblewrapBackend{}}
}

type bubblewrapBackend struct{}

func (bubblewrapBackend) check(ctx context.Context) error {
	if !validRootOwnedSystemExecutable(bubblewrapExecutable) || !validRootOwnedSystemExecutable(dpkgQueryExecutable) {
		return bubblewrapUnavailable()
	}
	owner := exec.CommandContext(ctx, dpkgQueryExecutable, "--search", bubblewrapExecutable)
	owner.Env = []string{}
	output, err := owner.Output()
	if err != nil {
		return bubblewrapUnavailable()
	}
	ownerOutput := string(output)
	status := exec.CommandContext(ctx, dpkgQueryExecutable, "--show", "--showformat=${db:Status-Abbrev}", "bubblewrap")
	status.Env = []string{}
	output, err = status.Output()
	if err != nil || !validBubblewrapPackageRecord(ownerOutput, string(output)) {
		return bubblewrapUnavailable()
	}
	probe := exec.CommandContext(ctx, bubblewrapExecutable,
		"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup",
		"--die-with-parent", "--clearenv", "--proc", "/proc", "--dev", "/dev",
		"--dir", "/tmp", "--ro-bind", "/usr", "/usr", "--remount-ro", "/",
		"--setenv", "PATH", safeProcessPath, "--chdir", "/tmp", "--", "/usr/bin/true",
	)
	probe.Env = []string{}
	if err := probe.Run(); err != nil {
		return bubblewrapUnavailable()
	}
	return nil
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
	command := exec.CommandContext(ctx, bubblewrapExecutable, bubblewrapArguments(request)...)
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
