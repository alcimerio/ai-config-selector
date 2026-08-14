// Package launchtest provides test-only Process Sandbox implementations.
package launchtest

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

// DirectSandbox runs fixture commands directly. Production assembly never
// imports this package.
type DirectSandbox struct{}

func (DirectSandbox) Check(_ context.Context, request launch.SandboxCheck) error {
	if request.Workspace == "" || request.Executable == "" || request.SessionsDirectory == "" {
		return &launch.SandboxError{Category: launch.SandboxUnsafePath}
	}
	return nil
}

func (DirectSandbox) Prepare(ctx context.Context, request launch.ProcessRequest) (launch.Process, error) {
	command := exec.CommandContext(ctx, request.Executable, request.Arguments...)
	command.Dir = request.Workspace
	command.Env = directEnvironment(request.SessionHome, request.TemporaryDirectory)
	command.Stdin = request.Terminal.Input
	command.Stdout = request.Terminal.Output
	command.Stderr = request.Terminal.ErrorOutput
	command.ExtraFiles = nil
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
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
	return &directProcess{command: command}, nil
}

func directEnvironment(home, temporaryDirectory string) []string {
	overrides := map[string]string{
		"HOME": home, "TMPDIR": temporaryDirectory,
		"XDG_CONFIG_HOME": filepath.Join(home, ".config"),
		"XDG_DATA_HOME":   filepath.Join(home, ".local", "share"),
		"XDG_CACHE_HOME":  filepath.Join(home, ".cache"),
		"XDG_STATE_HOME":  filepath.Join(home, ".local", "state"),
	}
	environment := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, found := strings.Cut(entry, "=")
		if _, overridden := overrides[key]; found && overridden {
			continue
		}
		environment = append(environment, entry)
	}
	for key, value := range overrides {
		environment = append(environment, key+"="+value)
	}
	return environment
}

type directProcess struct {
	command *exec.Cmd
}

func (process *directProcess) Start() error { return process.command.Start() }
func (process *directProcess) Wait() error  { return process.command.Wait() }
func (process *directProcess) Signal(signal os.Signal) error {
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
