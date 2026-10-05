package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
)

// profileCompletion owns acknowledgment delivery and outcome precedence after
// persistence or terminal settlement. It never mutates, recovers, retries, or
// checks a later context: only the persistence owner can establish commitment.
// Command-specific formats remain adapters over this completion policy.
type profileCompletion struct {
	outcome profilerepo.Outcome
	err     error
}

// Apply requires a clean committed result. Recovery deliberately does not use
// this constructor because a clean recovery may have nothing new to commit.
func appliedProfile(out profilerepo.Outcome, err error) profileCompletion {
	if err == nil && out.State == profilerepo.Committed && !out.RecoveryRequired {
		return profileCompletion{outcome: out}
	}
	if err == nil {
		err = errors.New("Profile transaction requires outcome inspection")
	}
	return profileCompletion{outcome: out, err: &profilerepo.OutcomeError{Outcome: out, Err: err}}
}

// A nil error here is evidence from a persistence-backed saver, not merely a
// Builder's user-acceptance flag. Preserve any returned transaction outcome.
func savedProfile(err error) profileCompletion {
	out := profilerepo.Outcome{State: profilerepo.Committed}
	if err != nil {
		out.State = profilerepo.NotCommitted
		var transaction *profilerepo.OutcomeError
		if errors.As(err, &transaction) {
			out = transaction.Outcome
		}
	}
	return profileCompletion{outcome: out, err: err}
}

func (c profileCompletion) acknowledge(output io.Writer, receipt []byte) error {
	written, err := output.Write(receipt)
	if err == nil && written != len(receipt) {
		err = io.ErrShortWrite
	}
	if err == nil {
		return nil
	}
	return &profilerepo.OutcomeError{Outcome: c.outcome, Err: errors.Join(c.err, err)}
}

type profileCompletionFormat uint8

const (
	creationCompletion profileCompletionFormat = iota
	mutationCompletion
	legacyCreationCompletion
)

func (app App) completeProfile(action string, c profileCompletion, receipt string, format profileCompletionFormat) int {
	if c.err != nil {
		return app.profileCompletionError(action, c.err, format)
	}
	if err := c.acknowledge(app.Output, []byte(receipt)); err != nil {
		return app.profileCompletionError(action, err, format)
	}
	return 0
}

func (app App) profileCompletionError(action string, err error, format profileCompletionFormat) int {
	var transaction *profilerepo.OutcomeError
	if errors.As(err, &transaction) {
		switch {
		case transaction.Outcome.State == profilerepo.Committed && !transaction.Outcome.RecoveryRequired:
			if format == mutationCompletion {
				return app.fail("%s: Profile mutation committed; reporting failed. %s\nInspect stored Profiles before deciding what to do.", action, safeTerminalText(err.Error()))
			}
			if format == legacyCreationCompletion {
				return app.fail("%s: Profile transaction committed; reporting failed. %s\nInspect the stored Profile before deciding what to do.", action, safeTerminalText(err.Error()))
			}
			return app.fail("%s: Profile transaction committed; reporting failed. Inspect the stored Profile before deciding what to do", action)
		case transaction.Outcome.State == profilerepo.Committed:
			if format == mutationCompletion {
				return app.fail("%s Profile mutation committed; cleanup or reporting failed.\nRecover with: acs profile recover\nThen inspect stored Profiles before deciding what to do. Do not delete transaction artifacts.", action)
			}
			return app.fail("%s: Profile transaction committed; cleanup requires recovery. Do not retry.\nRecover with: acs profile recover\nThen inspect the stored Profile. Do not delete transaction artifacts", action)
		case transaction.Outcome.State != profilerepo.NotCommitted:
			if format == mutationCompletion {
				return app.fail("%s Outcome unknown; publication may have occurred. Do not blindly retry.\nRecover with: acs profile recover\nThen inspect stored Profiles before deciding what to do. Do not delete transaction artifacts.", action)
			}
			return app.fail("%s: Profile transaction outcome unknown; publication may have occurred. Do not retry.\nRecover with: acs profile recover\nThen inspect the stored Profile. Do not delete transaction artifacts", action)
		case transaction.Outcome.RecoveryRequired:
			if format == mutationCompletion {
				return app.fail("%s Requested mutation not committed; preceding transaction or cleanup needs recovery.\nRecover with: acs profile recover\nThen inspect stored Profiles before deciding what to do. Do not delete transaction artifacts.", action)
			}
			return app.fail("%s: requested Profile transaction not committed; a preceding repository operation requires recovery.\nRecover with: acs profile recover\nThen inspect stored Profiles. Do not delete transaction artifacts", action)
		case transaction.Outcome.State == profilerepo.NotCommitted && format != mutationCompletion:
			if errors.Is(err, profile.ErrProfileExists) {
				return app.fail("Profile transaction not committed: destination Profile is occupied; nothing was overwritten")
			}
			if errors.Is(err, context.Canceled) {
				fmt.Fprintln(app.Output, "Profile transaction not committed: creation cancelled before publication.")
				return 130
			}
			return app.fail("%s: Profile transaction not committed; nothing was published", action)
		}
	}
	if format == mutationCompletion {
		if errors.Is(err, profilerepo.ErrConflict) {
			return app.fail("storage changed; mutation not committed. Inspect and explicitly reload before making a new preview")
		}
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(app.Output, "Profile mutation cancelled before commit.")
			return 130
		}
		return app.fail("%s: %s", action, safeTerminalText(err.Error()))
	}
	if errors.Is(err, profile.ErrProfileExists) {
		return app.fail("destination Profile is occupied; nothing was overwritten")
	}
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(app.Output, "Profile creation cancelled before publication.")
		return 130
	}
	if format == legacyCreationCompletion {
		return app.fail("%s: %s", action, safeTerminalText(err.Error()))
	}
	return app.fail("%s failed; Profile was not reported as committed", action)
}

func (app App) restoreApplyError(inv historyInvocation, c profileCompletion) int {
	switch {
	case c.outcome.State == profilerepo.Committed && !c.outcome.RecoveryRequired:
		return app.historyError(inv, 1, "committed_reporting_failed", "restore committed; reporting failed. Inspect stored Profiles before deciding what to do; do not retry")
	case c.outcome.State != profilerepo.NotCommitted || c.outcome.RecoveryRequired:
		return app.historyError(inv, 1, "recovery_required", "restore outcome requires repository recovery or inspection")
	case errors.Is(c.err, profilerepo.ErrConflict):
		return app.historyError(inv, 1, "conflict", "restore destination or expected revision changed; nothing was committed")
	case errors.Is(c.err, context.Canceled):
		return app.historyError(inv, 1, "cancelled", "restore was cancelled before commit")
	default:
		return app.historyError(inv, 1, "not_committed", "restore was not committed")
	}
}
