package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/alcimerio/ai-config-selector/internal/sessionops"
)

type sessionOperations interface {
	List(sessionops.State) (sessionops.ListResult, error)
	Inspect(string) (sessionops.InspectResult, error)
	Recover(string) (sessionops.RecoverResult, error)
}

type sessionDiagnostic struct {
	SchemaVersion int    `json:"schemaVersion"`
	ID            string `json:"id,omitempty"`
	Outcome       string `json:"outcome"`
	Diagnostic    string `json:"diagnostic"`
}

type codexSessionRecovery struct{ store *codexauthresource.Store }
type codexSessionRecoveryBinding struct {
	binding *codexauthresource.RecoveryBinding
}

func (recovery codexSessionRecovery) AcquireBySession(ctx context.Context, id string) (sessionops.AuthRecoveryBinding, bool, error) {
	binding, exists, err := recovery.store.AcquireRecoveryBySession(ctx, id)
	if errors.Is(err, codexauthresource.ErrIdentityBusy) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		err = sessionops.ErrAuthBusy
	}
	if binding == nil {
		return nil, exists, err
	}
	return codexSessionRecoveryBinding{binding: binding}, exists, err
}
func (binding codexSessionRecoveryBinding) CleanupChallenge() string {
	return binding.binding.CleanupChallenge()
}
func (binding codexSessionRecoveryBinding) Prepared() bool { return binding.binding.Prepared() }
func (binding codexSessionRecoveryBinding) FinalizeRecovery(ctx context.Context, root string) error {
	_, err := binding.binding.FinalizeRecovery(ctx, root)
	return err
}
func (binding codexSessionRecoveryBinding) DeleteMarkerAfterProjectionRemoval(ctx context.Context) error {
	return binding.binding.DeleteMarkerAfterProjectionRemoval(ctx)
}
func (binding codexSessionRecoveryBinding) Release() error { return binding.binding.Release() }

// RunSessionOperations dispatches after syntax/help but before target, Profile,
// provider, working-directory, terminal or Session setup.
func (app App) RunSessionOperations(args []string, home func() (string, error)) (bool, int) {
	inv, problem := parseCommand(args)
	if problem != "" || inv.help || !stringsHasSessionPath(inv.command.path) {
		return false, 0
	}
	operations := app.SessionOperations
	if operations == nil {
		directory, err := home()
		if err != nil {
			return true, app.sessionFailure(inv, "session_registry_unavailable")
		}
		acsHome := filepath.Join(directory, ".acs")
		operations = sessionops.Store{SessionsDirectory: filepath.Join(acsHome, "sessions"), AuthRecovery: func() (sessionops.AuthRecovery, error) {
			locks := filepath.Join(acsHome, "locks", "codex-auth")
			quarantine := filepath.Join(acsHome, "quarantine", "codex-auth")
			for _, path := range []string{acsHome, filepath.Dir(locks), locks, filepath.Dir(quarantine), quarantine} {
				if err := os.MkdirAll(path, 0o700); err != nil {
					return nil, err
				}
				if err := os.Chmod(path, 0o700); err != nil {
					return nil, err
				}
			}
			store, err := codexauthresource.New(locks, quarantine)
			if err != nil {
				return nil, err
			}
			return codexSessionRecovery{store: store}, nil
		}}
	}
	switch inv.command.path {
	case "session list":
		var filter sessionops.State
		if inv.value != "" {
			filter, _ = sessionops.ParseState(inv.value)
		}
		result, err := operations.List(filter)
		if err != nil {
			return true, app.sessionFailure(inv, sessionops.Diagnostic(err))
		}
		if inv.enabled {
			return true, app.encodeSessionJSON(result)
		}
		fmt.Fprintln(app.Output, "Durable Sessions:")
		if len(result.Sessions) == 0 {
			fmt.Fprintln(app.Output, "  (none)")
		}
		for _, item := range result.Sessions {
			fmt.Fprintf(app.Output, "  %s  %s  %s  recovery=%s\n", item.ID, item.State, item.Target, item.Recovery.Action)
		}
		fmt.Fprintf(app.Output, "Untracked roots: %d\n", result.UntrackedCount)
		return true, 0
	case "session inspect":
		result, err := operations.Inspect(inv.operand)
		if err != nil {
			return true, app.sessionFailure(inv, sessionops.Diagnostic(err))
		}
		if inv.enabled {
			return true, app.encodeSessionJSON(result)
		}
		item := result.Session
		fmt.Fprintf(app.Output, "Session %s\n  state: %s\n  observation: %s\n  target: %s\n  revision: %d\n  recovery: %s\n", item.ID, item.State, item.Observation, item.Target, item.Revision, item.Recovery.Action)
		return true, 0
	case "session recover":
		result, err := operations.Recover(inv.operand)
		if inv.enabled {
			if err != nil {
				return true, app.encodeSessionJSON(sessionDiagnostic{SchemaVersion: sessionops.SchemaVersion, ID: inv.operand, Outcome: result.Outcome, Diagnostic: sessionops.Diagnostic(err)}) | 1
			}
			return true, app.encodeSessionJSON(result)
		}
		if err != nil {
			return true, app.sessionFailure(inv, sessionops.Diagnostic(err))
		}
		fmt.Fprintln(app.Output, result.String())
		return true, 0
	}
	return false, 0
}

func stringsHasSessionPath(path string) bool {
	return path == "session list" || path == "session inspect" || path == "session recover"
}

func (app App) encodeSessionJSON(value any) int {
	if err := json.NewEncoder(app.Output).Encode(value); err != nil {
		return 1
	}
	return 0
}

func (app App) sessionFailure(inv invocation, diagnostic string) int {
	if inv.enabled {
		return app.encodeSessionJSON(sessionDiagnostic{SchemaVersion: sessionops.SchemaVersion, ID: inv.operand, Outcome: "failed", Diagnostic: diagnostic}) | 1
	}
	fmt.Fprintf(app.ErrorOutput, "acs: %s\n", diagnostic)
	return 1
}
