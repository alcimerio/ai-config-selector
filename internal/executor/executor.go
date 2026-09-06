// Package executor owns the contained-process lifecycle shared by targets.
package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

// Recipe is validated target intent. It deliberately contains no backend,
// process handle, or lifecycle callback.
type Recipe struct {
	Executable    string
	RuntimeInputs []string
	Arguments     []string
	Probes        [][]string
	Projection    *Projection
}

// Projection describes the one allowlisted file copied into a Session.
type Projection struct{ Source, RelativeDestination string }

// Request binds a recipe to one materialized Session and interactive terminal.
type Request struct {
	SessionsDirectory, WorkingDirectory string
	Materializer                        session.Materializer
	Recipe                              Recipe
	Terminal                            launch.Terminal
}

// Result contains captured probe stdout and the raw contained target result.
// Callers translate only their target-specific output and ordinary exit errors.
type Result struct {
	ProbeOutput [][]byte
	RunErr      error
}

type Executor struct{ sandbox launch.ProcessSandbox }

func New(sandbox launch.ProcessSandbox) *Executor { return &Executor{sandbox: sandbox} }

func (e *Executor) Run(ctx context.Context, request Request) (result Result, resultErr error) {
	if e == nil || e.sandbox == nil || request.Recipe.Executable == "" {
		return result, errors.New("contained execution recipe is invalid")
	}
	if err := e.sandbox.Check(ctx, launch.SandboxCheck{Workspace: request.WorkingDirectory, SessionsDirectory: request.SessionsDirectory, Executable: request.Recipe.Executable, RuntimeInputs: request.Recipe.RuntimeInputs}); err != nil {
		return result, err
	}
	created, err := session.Create(request.SessionsDirectory, request.WorkingDirectory, request.Materializer)
	if err != nil {
		return result, err
	}
	defer func() {
		if err := created.Remove(); err != nil {
			var exit *exec.ExitError
			if errors.As(resultErr, &exit) {
				resultErr = err
			} else if resultErr != nil {
				resultErr = errors.Join(resultErr, err)
			} else {
				resultErr = err
			}
		}
	}()
	if projection := request.Recipe.Projection; projection != nil {
		if filepath.IsAbs(projection.RelativeDestination) || projection.RelativeDestination == "" {
			return result, errors.New("contained execution projection is invalid")
		}
		if err := copyFileIfPresent(projection.Source, filepath.Join(created.HomeDirectory(), projection.RelativeDestination)); err != nil {
			return result, err
		}
	}
	for _, arguments := range request.Recipe.Probes {
		output, err := e.run(ctx, created, request.Recipe, arguments, launch.Terminal{})
		result.ProbeOutput = append(result.ProbeOutput, output)
		if err != nil {
			return result, err
		}
	}
	_, result.RunErr = e.run(ctx, created, request.Recipe, request.Recipe.Arguments, request.Terminal)
	return result, result.RunErr
}

func (e *Executor) run(ctx context.Context, created *session.Session, recipe Recipe, arguments []string, terminal launch.Terminal) ([]byte, error) {
	var output bytes.Buffer
	if terminal.Output == nil {
		terminal.Output = &output
	}
	if terminal.ErrorOutput == nil {
		terminal.ErrorOutput = io.Discard
	}
	process, err := e.sandbox.Prepare(ctx, launch.ProcessRequest{Workspace: created.WorkingDirectory(), SessionsDirectory: created.SessionsDirectory(), SessionDirectory: created.RootDirectory(), SessionHome: created.HomeDirectory(), TemporaryDirectory: created.TemporaryDirectory(), Executable: recipe.Executable, RuntimeInputs: recipe.RuntimeInputs, Arguments: append([]string(nil), arguments...), Terminal: terminal})
	if err != nil {
		return nil, err
	}
	process, err = created.RetainUntilProcessDone(process)
	if err != nil {
		return nil, err
	}
	// RunAttached captures signals immediately before Start. A successful Start
	// is therefore reaped once; a failed Start is never waited a second time.
	runErr := launch.RunAttached(process)
	if cleanupErr := launch.AwaitRetainedSessionCleanup(process); cleanupErr != nil {
		if runErr != nil {
			return nil, errors.Join(runErr, cleanupErr)
		}
		return nil, cleanupErr
	}
	return output.Bytes(), runErr
}

func copyFileIfPresent(source, destination string) error {
	contents, err := os.ReadFile(source)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("project contained credential: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	return os.WriteFile(destination, contents, 0o600)
}
