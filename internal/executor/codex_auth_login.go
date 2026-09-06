package executor

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

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
	PrivateRoot       string
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
	return &codexLoginRunner{
		config: config, sandbox: sandbox,
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

func (runner *codexLoginRunner) Prepare(ctx context.Context) (loginPreparation, error) {
	if runner == nil {
		return loginPreparation{}, ErrLoginFailed
	}
	operation, err := prepareContainedOperation(ctx, runner.config, runner.sandbox, ErrLoginFailed)
	if err != nil {
		return loginPreparation{}, err
	}
	return loginPreparation{
		run: func(
			ctx context.Context,
			created *session.Session,
			proofChallenge string,
			binding loginResourceBinding,
			deviceAuth bool,
			terminal launch.Terminal,
		) loginRunResult {
			return runner.runOperation(ctx, operation.config, created, proofChallenge, binding, deviceAuth, terminal)
		},
		operation: operation,
	}, nil
}

func validateContainedAuthWorkspace(config codexLoginConfig) error {
	if config.PrivateRoot == "" {
		return nil
	}
	workspace, err := filepath.EvalSymlinks(config.WorkingDirectory)
	if err != nil {
		return err
	}
	privateRoot, err := filepath.EvalSymlinks(config.PrivateRoot)
	if err != nil {
		return err
	}
	if pathsOverlap(workspace, privateRoot) {
		return errors.New("contained authentication workspace overlaps private state")
	}
	return nil
}

func (runner *codexLoginRunner) runOperation(
	ctx context.Context,
	config codexLoginConfig,
	created *session.Session,
	proofChallenge string,
	binding loginResourceBinding,
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
	versionOutput := boundedBuffer{limit: maximumVersionOutputSize}
	versionRun := runner.run(ctx, config, created, proofChallenge, binding, []string{"--version"}, launch.Terminal{
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
	loginRun := runner.run(ctx, config, created, proofChallenge, binding, arguments, terminal)
	if loginRun.err != nil || !loginRun.cleanupProven {
		return loginRunResult{
			containedRunResult: loginRun,
		}
	}

	// The resource binding reads auth.json from the protected Session root only
	// after process cleanup has settled.  Do not carry credential bytes through
	// the executable orchestration result.
	return loginRunResult{containedRunResult: containedRunResult{cleanupProven: true}}
}

func (runner *codexLoginRunner) run(
	ctx context.Context,
	config codexLoginConfig,
	created *session.Session,
	proofChallenge string,
	binding loginResourceBinding,
	arguments []string,
	terminal launch.Terminal,
) statusRunResult {
	return runContainedCodex(
		ctx, config, runner.sandbox, created, "", proofChallenge, binding, arguments, terminal,
		ErrLoginFailed, ErrLoginCleanupUncertain,
	)
}
