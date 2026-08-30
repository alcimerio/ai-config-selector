package codexauth

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
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
	config     codexLoginConfig
	executable *pinnedExecutable
	sandbox    launch.ProcessSandbox
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
	return &codexLoginRunner{
		config: config, executable: newPinnedExecutable(config.BinaryPath), sandbox: sandbox,
	}
}

func codexRuntimeProbePaths(additional []string) []string {
	paths := append([]string(nil), additional...)
	return append(paths, codexSystemRequirementsPath)
}

func codexAuthRuntimeArguments(workspace string, arguments ...string) []string {
	overrides := []string{
		"-c", `cli_auth_credentials_store="file"`,
		"-c", `forced_login_method="chatgpt"`,
	}
	if workspace != "" {
		overrides = append(overrides, "-c", `forced_chatgpt_workspace_id=`+strconv.Quote(workspace))
	}
	return append(overrides, arguments...)
}

func (runner *codexLoginRunner) Check(ctx context.Context) error {
	if runner == nil || runner.sandbox == nil {
		return ErrLoginFailed
	}
	executable, err := runner.executable.Resolve()
	if err != nil {
		return ErrUnsupportedVersion
	}
	return runner.sandbox.Check(ctx, launch.SandboxCheck{
		Workspace: runner.config.WorkingDirectory, SessionsDirectory: runner.config.SessionsDirectory,
		Executable: executable, RuntimeInputs: runner.config.RuntimeInputs,
		RuntimeProbePaths: runner.config.RuntimeProbePaths,
	})
}

func (runner *codexLoginRunner) Run(
	ctx context.Context,
	created *session.Session,
	proofChallenge string,
	deviceAuth bool,
	terminal launch.Terminal,
) loginRunResult {
	if runner == nil || runner.sandbox == nil || created == nil {
		return loginRunResult{containedRunResult: containedRunResult{err: ErrLoginFailed, cleanupProven: true}}
	}

	codexHome := filepath.Join(created.HomeDirectory(), ".codex")
	if err := os.MkdirAll(codexHome, 0o700); err != nil {
		return loginRunResult{containedRunResult: containedRunResult{err: ErrLoginFailed, cleanupProven: true}}
	}
	if err := os.Chmod(codexHome, 0o700); err != nil {
		return loginRunResult{containedRunResult: containedRunResult{err: ErrLoginFailed, cleanupProven: true}}
	}
	configuration := []byte("cli_auth_credentials_store = \"file\"\nforced_login_method = \"chatgpt\"\n")
	if err := os.WriteFile(filepath.Join(codexHome, "config.toml"), configuration, 0o600); err != nil {
		return loginRunResult{containedRunResult: containedRunResult{err: ErrLoginFailed, cleanupProven: true}}
	}
	config, cleanup, err := runner.snapshotConfig()
	if err != nil {
		return loginRunResult{containedRunResult: containedRunResult{err: ErrUnsupportedVersion, cleanupProven: true}}
	}
	defer cleanup()

	versionOutput := boundedBuffer{limit: maximumVersionOutputSize}
	versionRun := runner.run(ctx, config, created, proofChallenge, []string{"--version"}, launch.Terminal{
		Output: &versionOutput, ErrorOutput: io.Discard,
	})
	if versionRun.err != nil || !versionRun.cleanupProven {
		return loginRunResult{
			containedRunResult: versionRun,
		}
	}
	if versionOutput.overflow || strings.TrimSpace(versionOutput.String()) != "codex-cli "+runner.config.SupportedVersion {
		return loginRunResult{containedRunResult: containedRunResult{err: ErrUnsupportedVersion, cleanupProven: true}}
	}

	arguments := []string{"login"}
	if deviceAuth {
		arguments = append(arguments, "--device-auth")
	}
	loginRun := runner.run(ctx, config, created, proofChallenge, arguments, terminal)
	if loginRun.err != nil || !loginRun.cleanupProven {
		return loginRunResult{
			containedRunResult: loginRun,
		}
	}

	auth, err := readPrivateAuthFile(filepath.Join(codexHome, "auth.json"))
	if err != nil {
		return loginRunResult{containedRunResult: containedRunResult{err: ErrUnsupportedAuth, cleanupProven: true}}
	}
	return loginRunResult{auth: auth, containedRunResult: containedRunResult{cleanupProven: true}}
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
	config codexLoginConfig,
	created *session.Session,
	proofChallenge string,
	arguments []string,
	terminal launch.Terminal,
) statusRunResult {
	return runContainedCodex(
		ctx, config, runner.sandbox, created, "", proofChallenge, arguments, terminal,
		ErrLoginFailed, ErrLoginCleanupUncertain,
	)
}

func (runner *codexLoginRunner) snapshotConfig() (codexLoginConfig, func(), error) {
	root, err := executableSnapshotRoot(runner.config)
	if err != nil {
		return codexLoginConfig{}, nil, err
	}
	executable, cleanup, err := runner.executable.Snapshot(root)
	if err != nil {
		return codexLoginConfig{}, nil, err
	}
	config := runner.config
	config.BinaryPath = executable
	return config, cleanup, nil
}
