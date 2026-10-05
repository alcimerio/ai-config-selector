package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
)

// ProfileRecoveryRequested recognizes the public command before launch assembly.
func ProfileRecoveryRequested(args []string) bool {
	inv, _ := parseCommand(args)
	return inv.command.path == "profile recover"
}

// RunProfileRecovery completes previously authorized repository transactions.
// It needs neither a codec nor a runtime and never bootstraps absent storage.
func (app App) RunProfileRecovery(ctx context.Context, args []string, home func() (string, error)) (bool, int) {
	inv, problem := parseCommand(args)
	if inv.command.path != "profile recover" {
		return false, 0
	}
	if problem != "" || inv.help {
		return app.RunInformational(args)
	}
	// Keep cancellation ahead of HOME lookup and all storage work. NotCommitted
	// here is the repository's initial outcome, not proof of journal inspection.
	out := profilerepo.Outcome{State: profilerepo.NotCommitted}
	if err := ctx.Err(); err != nil {
		return true, app.writeProfileRecovery(inv, out, err)
	}
	if app.Repository == nil {
		existingHome, err := home()
		if err != nil {
			return true, app.writeProfileRecovery(inv, out, errors.New("home lookup failed"))
		}
		app.Repository = profilerepo.New(filepath.Join(existingHome, ".acs"))
	}
	out, err := app.Repository.Recover(ctx)
	// Do not recheck ctx here. A later signal cannot rewrite the returned outcome.
	return true, app.writeProfileRecovery(inv, out, err)
}

type profileRecoveryDiagnostic struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}
type profileRecoveryHistory struct {
	LineageID string `json:"lineageId"`
	EventID   string `json:"eventId"`
}
type profileRecoveryResult struct {
	SchemaVersion    int                        `json:"schemaVersion"`
	Operation        string                     `json:"operation"`
	State            profilerepo.State          `json:"state"`
	RecoveryRequired bool                       `json:"recoveryRequired"`
	History          *profileRecoveryHistory    `json:"history,omitempty"`
	Diagnostic       *profileRecoveryDiagnostic `json:"diagnostic,omitempty"`
	Guidance         string                     `json:"guidance"`
}

func (app App) writeProfileRecovery(inv invocation, out profilerepo.Outcome, err error) int {
	result := profileRecoveryResult{SchemaVersion: 1, Operation: "profile.recover", State: out.State, RecoveryRequired: out.RecoveryRequired}
	if out.History != nil {
		result.History = &profileRecoveryHistory{LineageID: out.History.LineageID, EventID: out.History.EventID}
	}
	result.Guidance = "Profile transactions only. Recovery completes earlier authorization; it is not rollback. Inspect stored Profiles before another mutation. Session and authentication recovery use their separate commands."
	code := 0
	if err != nil || out.RecoveryRequired || out.State == profilerepo.Unknown {
		code = 1
		category := "recovery_failed"
		switch {
		case errors.Is(err, profilerepo.ErrBusy):
			category = "busy"
		case errors.Is(err, profilerepo.ErrUnsafe):
			category = "unsafe"
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			category = "cancelled"
		case err == nil && out.State == profilerepo.Unknown:
			category = "outcome_unknown"
		case err == nil:
			category = "recovery_required"
		}
		message := "Recovery did not finish cleanly. Preserve transaction evidence; do not delete artifacts or bypass a live lock."
		if out.State == profilerepo.NotCommitted {
			message += " The returned not_committed state does not prove inspection of a pending transaction or its absence."
		} else if out.State == profilerepo.Committed {
			message += " The transaction committed; cleanup or reporting failed. Do not replay it."
		} else {
			message += " Publication may have occurred. Do not blindly retry a mutation."
		}
		result.Diagnostic = &profileRecoveryDiagnostic{category, message}
		if category == "cancelled" && out.State == profilerepo.NotCommitted && !out.RecoveryRequired {
			code = 130
		}
	}
	var writeErr error
	if inv.enabled {
		writeErr = json.NewEncoder(app.Output).Encode(result)
	} else {
		_, writeErr = fmt.Fprintf(app.Output, "Profile transaction recovery: %s\nRecovery required: %t\n", result.State, result.RecoveryRequired)
		if writeErr == nil && result.History != nil {
			_, writeErr = fmt.Fprintf(app.Output, "History: %s %s\n", result.History.LineageID, result.History.EventID)
		}
		if writeErr == nil && result.Diagnostic != nil {
			_, writeErr = fmt.Fprintf(app.Output, "%s: %s\n", result.Diagnostic.Code, result.Diagnostic.Message)
		}
		if writeErr == nil {
			_, writeErr = fmt.Fprintln(app.Output, result.Guidance)
		}
	}
	if writeErr != nil {
		return app.fail("Profile recovery outcome %s (recovery required: %t) reporting failed; inspect stored Profiles before another mutation", out.State, out.RecoveryRequired)
	}
	return code
}
