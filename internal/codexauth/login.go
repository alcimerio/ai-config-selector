package codexauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

type codexLoginConfig struct {
	BinaryPath        string
	SupportedVersion  string
	RuntimeInputs     []string
	RuntimeProbePaths []string
	SessionsDirectory string
	WorkingDirectory  string
}

type codexLoginRunner struct {
	config  codexLoginConfig
	sandbox launch.ProcessSandbox
}

const maximumVersionOutputSize = 256
const codexSystemRequirementsPath = "/etc/codex/requirements.toml"

type boundedBuffer struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (buffer *boundedBuffer) Write(contents []byte) (int, error) {
	written := len(contents)
	remaining := buffer.limit - buffer.Len()
	if remaining <= 0 {
		buffer.overflow = buffer.overflow || written > 0
		return written, nil
	}
	if len(contents) > remaining {
		contents = contents[:remaining]
		buffer.overflow = true
	}
	_, _ = buffer.Buffer.Write(contents)
	return written, nil
}

func newCodexLoginRunner(config codexLoginConfig, sandbox launch.ProcessSandbox) *codexLoginRunner {
	config.RuntimeInputs = append([]string(nil), config.RuntimeInputs...)
	config.RuntimeProbePaths = codexRuntimeProbePaths(config.RuntimeProbePaths)
	return &codexLoginRunner{config: config, sandbox: sandbox}
}

func codexRuntimeProbePaths(additional []string) []string {
	paths := append([]string(nil), additional...)
	return append(paths, codexSystemRequirementsPath)
}

func (runner *codexLoginRunner) Login(
	ctx context.Context,
	deviceAuth bool,
	terminal launch.Terminal,
) (auth []byte, resultErr error) {
	if runner == nil || runner.sandbox == nil {
		return nil, ErrLoginFailed
	}
	if err := runner.sandbox.Check(ctx, launch.SandboxCheck{
		Workspace: runner.config.WorkingDirectory, SessionsDirectory: runner.config.SessionsDirectory,
		Executable: runner.config.BinaryPath, RuntimeInputs: runner.config.RuntimeInputs,
		RuntimeProbePaths: runner.config.RuntimeProbePaths,
	}); err != nil {
		return nil, err
	}

	created, err := session.Create(runner.config.SessionsDirectory, runner.config.WorkingDirectory, nil)
	if err != nil {
		return nil, ErrLoginFailed
	}
	defer func() {
		if err := created.Remove(); err != nil {
			clearBytes(auth)
			auth = nil
			resultErr = ErrLoginCleanupUncertain
		}
	}()

	codexHome := filepath.Join(created.HomeDirectory(), ".codex")
	if err := os.MkdirAll(codexHome, 0o700); err != nil {
		return nil, ErrLoginFailed
	}
	if err := os.Chmod(codexHome, 0o700); err != nil {
		return nil, ErrLoginFailed
	}
	configuration := []byte("cli_auth_credentials_store = \"file\"\nforced_login_method = \"chatgpt\"\n")
	if err := os.WriteFile(filepath.Join(codexHome, "config.toml"), configuration, 0o600); err != nil {
		return nil, ErrLoginFailed
	}

	versionOutput := boundedBuffer{limit: maximumVersionOutputSize}
	if err := runner.run(ctx, created, []string{"--version"}, launch.Terminal{
		Output: &versionOutput, ErrorOutput: io.Discard,
	}); err != nil {
		return nil, err
	}
	if versionOutput.overflow || strings.TrimSpace(versionOutput.String()) != "codex-cli "+runner.config.SupportedVersion {
		return nil, ErrUnsupportedVersion
	}

	arguments := []string{"login"}
	if deviceAuth {
		arguments = append(arguments, "--device-auth")
	}
	if err := runner.run(ctx, created, arguments, terminal); err != nil {
		return nil, err
	}

	auth, err = readPrivateAuthFile(filepath.Join(codexHome, "auth.json"))
	if err != nil {
		return nil, ErrUnsupportedAuth
	}
	return auth, nil
}

func readPrivateAuthFile(path string) ([]byte, error) {
	contents, err := readPrivateRegularFile(path, maximumAuthJSONSize)
	if err != nil {
		return nil, ErrUnsupportedAuth
	}
	return contents, nil
}

func readPrivateRegularFile(path string, maximumSize int64) ([]byte, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return nil, errors.New("open private file")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maximumSize {
		return nil, errors.New("invalid private file")
	}
	if native, ok := info.Sys().(*syscall.Stat_t); !ok || native.Uid != uint32(os.Geteuid()) || native.Nlink != 1 {
		return nil, errors.New("invalid private file")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumSize+1))
	if err != nil || len(contents) == 0 || int64(len(contents)) > maximumSize {
		clearBytes(contents)
		return nil, errors.New("invalid private file")
	}
	return contents, nil
}

func (runner *codexLoginRunner) run(
	ctx context.Context,
	created *session.Session,
	arguments []string,
	terminal launch.Terminal,
) error {
	process, err := runner.sandbox.Prepare(ctx, launch.ProcessRequest{
		Workspace: created.WorkingDirectory(), SessionsDirectory: created.SessionsDirectory(),
		SessionDirectory: created.RootDirectory(), SessionHome: created.HomeDirectory(),
		TemporaryDirectory: created.TemporaryDirectory(), Executable: runner.config.BinaryPath,
		RuntimeInputs: runner.config.RuntimeInputs, RuntimeProbePaths: runner.config.RuntimeProbePaths,
		Arguments: arguments, Terminal: terminal,
	})
	if err != nil {
		return err
	}
	process, err = created.RetainUntilProcessDone(process)
	if err != nil {
		return ErrLoginCleanupUncertain
	}
	runErr := launch.RunAttached(process)
	cleanupErr := launch.AwaitRetainedSessionCleanup(process)
	if cleanupErr != nil {
		return ErrLoginCleanupUncertain
	}
	if runErr != nil {
		var sandboxFailure *launch.SandboxError
		if errors.As(runErr, &sandboxFailure) {
			return sandboxFailure
		}
		return ErrLoginFailed
	}
	return nil
}
