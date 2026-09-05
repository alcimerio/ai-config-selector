package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type ProfileRepository interface {
	Read(context.Context, string) (profilerepo.Snapshot, error)
	Apply(context.Context, profilerepo.Request) (profilerepo.Outcome, error)
	Recover(context.Context) (profilerepo.Outcome, error)
}

type ProfileMutationBuilder interface {
	MutateProfile(context.Context, string, category.Draft, builder.MutationOptions, io.Reader, io.Writer) (builder.Outcome, error)
}

// RunProfileMutations is a narrow pre-runtime dispatch. Name, grammar and stream
// checks precede home lookup, recovery and assembly; no launch collaborators exist.
func (app App) RunProfileMutations(ctx context.Context, args []string, home func() (string, error)) (bool, int) {
	inv, problem := parseCommand(args)
	if !isMutation(inv.command.path) {
		return false, 0
	}
	if problem != "" || inv.help {
		handled, code := app.RunInformational(args)
		return handled, code
	}
	if !(inv.command.path == "profile delete" && inv.value == inv.operand) && (app.Interactive == nil || !app.Interactive(app.Input, app.Output)) {
		return true, app.fail("%s requires interactive stdin and stdout", inv.command.path)
	}
	if err := ctx.Err(); err != nil {
		return true, app.fail("Profile mutation was not started: %v", err)
	}
	if app.Repository == nil || app.MutationBuilder == nil || app.Categories == nil {
		existingHome, err := home()
		if err != nil {
			return true, app.fail("resolve user home for Profile mutation")
		}
		editor, err := devin.NewProfileEditor(existingHome)
		if err != nil {
			return true, app.fail("configure Profile editor: %v", err)
		}
		app.Repository, app.MutationBuilder, app.Categories = profilerepo.New(filepath.Join(existingHome, ".acs")), editor, editor.Categories()
	}
	return true, app.mutateProfile(ctx, inv)
}

type mutationSnapshot struct {
	source      profilerepo.Snapshot
	destination profilerepo.Revision
	entry       profileinspect.Entry
	draft       category.Draft
}

func (app App) readMutation(ctx context.Context, inv invocation) (mutationSnapshot, error) {
	var snapshot mutationSnapshot
	source, err := app.Repository.Read(ctx, inv.operand)
	if err != nil {
		return snapshot, fmt.Errorf("read stored Profile: %w", err)
	}
	if !source.Exists {
		return snapshot, errors.New("stored Profile does not exist")
	}
	snapshot.source = source
	snapshot.entry = profileinspect.InspectBytes(inv.operand, source.Bytes)
	snapshot.draft = app.Categories.NewDraft()
	if inv.command.path != "profile delete" {
		if snapshot.entry.Status != "valid" {
			return snapshot, fmt.Errorf("Profile cannot be rewritten: %s", snapshot.entry.Diagnostic.Message)
		}
		decoded, err := app.Categories.Decode(source.Bytes)
		if err != nil {
			return snapshot, fmt.Errorf("decode strictly inspected Profile: %w", err)
		}
		snapshot.draft, err = app.Categories.DraftFromProfile(decoded)
		if err != nil {
			return snapshot, err
		}
	}
	if inv.command.valueFlag == "--name" {
		destination, err := app.Repository.Read(ctx, inv.value)
		if err != nil {
			return snapshot, fmt.Errorf("read destination: %w", err)
		}
		if destination.Exists {
			return snapshot, errors.New("destination Profile is occupied; nothing is overwritten")
		}
		snapshot.destination = destination.Revision
	}
	return snapshot, nil
}

func (app App) mutateProfile(ctx context.Context, inv invocation) int {
	// Apply owns recovery under the same transaction lock after confirmation.
	// Passive preparation and cancellation do not create lock or journal files.
	captured, err := app.readMutation(ctx, inv)
	if err != nil {
		return app.fail("%s: %v", inv.command.path, err)
	}
	label := map[string]string{"profile edit": "Edit", "profile clone": "Clone", "profile rename": "Rename", "profile delete": "Delete"}[inv.command.path]
	destination := inv.operand
	if inv.command.valueFlag == "--name" {
		destination = inv.value
	}
	options := builder.MutationOptions{Label: label, Compact: inv.command.path == "profile rename" || inv.command.path == "profile delete"}
	if inv.command.path == "profile delete" {
		options.Confirmation = inv.operand
	}
	options.Reload = func(reloadContext context.Context) (category.Draft, error) {
		fresh, err := app.readMutation(reloadContext, inv)
		if err != nil {
			return category.Draft{}, err
		}
		captured = fresh
		return fresh.draft, nil
	}
	options.Prepare = func(draft category.Draft) (builder.PreparedMutation, error) {
		// Copy the captured revision and bytes into this preview. Later reloads or
		// draft changes cannot alter the approved request.
		snapshot := captured
		var desired []byte
		var text strings.Builder
		fmt.Fprintf(&text, "Operation: %s\nStored name: %s\nResulting name: %s\n", label, inv.operand, destination)
		if inv.command.path == "profile delete" {
			fmt.Fprintf(&text, "Stored content status: %s\n", snapshot.entry.Status)
			if snapshot.entry.Status != "valid" {
				text.WriteString("Warning: unsupported or corrupt regular document. Deletion removes its original bytes without decoding or converting them.\n")
			}
			text.WriteString("Only this stored Profile is removed. Active Session copies, identities and other Profiles are preserved.\n")
		} else {
			candidate, err := app.Categories.NewProfile(destination, draft)
			if err != nil {
				return builder.PreparedMutation{}, err
			}
			var canonical bytes.Buffer
			encoder := json.NewEncoder(&canonical)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(candidate); err != nil {
				return builder.PreparedMutation{}, err
			}
			desired = append([]byte(nil), canonical.Bytes()...)
			entry := profileinspect.InspectBytes(destination, desired)
			if entry.Status != "valid" {
				return builder.PreparedMutation{}, errors.New("desired Profile has unsupported structure")
			}
			fmt.Fprintf(&text, "Stored v%d -> v2 canonical representation.\n", *snapshot.entry.StoredVersion)
			if *snapshot.entry.StoredVersion == 1 {
				text.WriteString("Explicit legacy conversion: v1 skillReferences becomes v2 categories.skills (schemaVersion 1).\n")
			}
			text.WriteString("Category envelopes/defaults, selection sorting, JSON field order, indentation and trailing newline are canonicalized.\n")
			if bytes.Equal(snapshot.source.Bytes, desired) {
				text.WriteString("The representation is already canonical and unchanged.\n")
			}
			describeSelections(&text, snapshot.entry, entry)
			text.WriteString("\nExact resulting canonical JSON (including final newline):\n")
			text.Write(desired)
		}
		var request profilerepo.Request
		switch inv.command.path {
		case "profile edit":
			request = profilerepo.ReplaceRequest{Name: inv.operand, Expected: snapshot.source.Revision, Bytes: desired}
		case "profile clone":
			request = profilerepo.CloneRequest{Source: inv.operand, Destination: destination, ExpectedSource: snapshot.source.Revision, ExpectedDestination: snapshot.destination, Bytes: desired}
		case "profile rename":
			request = profilerepo.RenameRequest{Source: inv.operand, Destination: destination, ExpectedSource: snapshot.source.Revision, ExpectedDestination: snapshot.destination, Bytes: desired}
		case "profile delete":
			request = profilerepo.DeleteRequest{Name: inv.operand, Expected: snapshot.source.Revision}
		}
		return builder.PreparedMutation{Text: text.String(), Save: func(commitContext context.Context, _ category.Draft) (string, error) {
			outcome, err := app.Repository.Apply(commitContext, request)
			if err != nil || outcome.State != profilerepo.Committed || outcome.RecoveryRequired {
				if err == nil {
					err = errors.New("Profile transaction requires outcome inspection")
				}
				return "", &profilerepo.OutcomeError{Outcome: outcome, Err: err}
			}
			return destination, nil
		}}, nil
	}
	if inv.command.path == "profile delete" && inv.value == inv.operand {
		prepared, err := options.Prepare(captured.draft)
		if err != nil {
			return app.fail("prepare deletion: %v", err)
		}
		fmt.Fprint(app.Output, prepared.Text)
		_, err = prepared.Save(ctx, captured.draft)
		if err != nil {
			return app.mutationError(destination, "delete Profile", err)
		}
	} else {
		outcome, err := app.MutationBuilder.MutateProfile(ctx, destination, captured.draft, options, app.Input, app.Output)
		if err != nil {
			return app.mutationError(destination, strings.ToLower(label)+" Profile", err)
		}
		if outcome.Cancelled {
			fmt.Fprintln(app.Output, "Profile mutation cancelled before commit.")
			return 130
		}
		if !outcome.Create {
			return app.fail("Profile editor ended without a confirmed outcome")
		}
	}
	fmt.Fprintf(app.Output, "%s Profile committed: %s\n", label, destination)
	return 0
}

func describeSelections(output io.Writer, before, after profileinspect.Entry) {
	old, new := map[skills.SkillReference]bool{}, map[skills.SkillReference]bool{}
	for _, c := range before.Categories {
		for _, ref := range c.Selection {
			old[ref] = true
		}
	}
	for _, c := range after.Categories {
		for _, ref := range c.Selection {
			new[ref] = true
			action := "Retain"
			if !old[ref] {
				action = "Add"
			}
			fmt.Fprintf(output, "%s: %s:%s\n", action, safeTerminalText(string(ref.Source)), safeTerminalText(ref.RelativePath))
		}
	}
	for _, c := range before.Categories {
		for _, ref := range c.Selection {
			if !new[ref] {
				fmt.Fprintf(output, "Remove: %s:%s\n", safeTerminalText(string(ref.Source)), safeTerminalText(ref.RelativePath))
			}
		}
	}
}

func (app App) mutationError(name, action string, err error) int {
	var transaction *profilerepo.OutcomeError
	if errors.As(err, &transaction) && (transaction.Outcome.State != profilerepo.NotCommitted || transaction.Outcome.RecoveryRequired) {
		state := "Outcome unknown; publication may have occurred. Do not blindly retry."
		if transaction.Outcome.State == profilerepo.Committed {
			state = "Profile mutation committed; cleanup or reporting failed."
		}
		if transaction.Outcome.State == profilerepo.NotCommitted {
			state = "Requested mutation not committed; preceding transaction or cleanup needs recovery."
		}
		return app.fail("%s %s\nRecover interactively with: acs devin create-profile --name %s\nCancel the builder if it opens, then inspect stored Profiles before deciding what to do. Do not delete transaction artifacts.", action, state, name)
	}
	if errors.Is(err, profilerepo.ErrConflict) {
		return app.fail("storage changed; mutation not committed. Inspect and explicitly reload before making a new preview")
	}
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(app.Output, "Profile mutation cancelled before commit.")
		return 130
	}
	return app.fail("%s: %s", action, safeTerminalText(err.Error()))
}
