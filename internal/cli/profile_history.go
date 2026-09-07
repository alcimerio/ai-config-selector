package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profileexchange"
	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type historyInvocation struct {
	action, name, lineage, revision, to, as, bindings, expect, confirm string
	limit, keep                                                        int
	json, dryRun, help                                                 bool
}

type historyRepository interface {
	ProfileRepository
	History(context.Context, profilerepo.HistorySelector, int) (profilerepo.HistoryResult, error)
	RestoreSnapshot(context.Context, profilerepo.HistorySelector, string) (profilerepo.RestoreSnapshot, error)
	SetHistoryPin(context.Context, string, string, bool) error
	PreviewPrune(context.Context, string, int) (profilerepo.PrunePreview, error)
	Prune(context.Context, string, int, string) (profilerepo.PrunePreview, error)
}

func parseProfileHistory(args []string) (historyInvocation, bool, string) {
	inv := historyInvocation{limit: 100, keep: 100}
	if len(args) < 2 || args[0] != "profile" {
		return inv, false, ""
	}
	switch args[1] {
	case "history":
		inv.action = "history"
	case "diff":
		inv.action = "diff"
	case "restore":
		inv.action = "restore"
	default:
		return inv, false, ""
	}
	i := 2
	if inv.action == "history" && i < len(args) {
		switch args[i] {
		case "pin", "unpin", "prune":
			inv.action = args[i]
			i++
		}
	}
	seen := map[string]bool{}
	for i < len(args) {
		arg := args[i]
		if arg == "--help" {
			if seen[arg] {
				return inv, true, "duplicate --help"
			}
			seen[arg] = true
			inv.help = true
			i++
			continue
		}
		if arg == "--json" || arg == "--dry-run" {
			if seen[arg] {
				return inv, true, "duplicate " + arg
			}
			seen[arg] = true
			if arg == "--json" {
				inv.json = true
			} else {
				inv.dryRun = true
			}
			i++
			continue
		}
		if strings.HasPrefix(arg, "--") {
			if seen[arg] {
				return inv, true, "duplicate " + arg
			}
			seen[arg] = true
			if i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
				return inv, true, "missing value for " + arg
			}
			value := args[i+1]
			i += 2
			switch arg {
			case "--lineage":
				inv.lineage = value
			case "--revision":
				inv.revision = value
			case "--to":
				inv.to = value
			case "--as":
				inv.as = value
			case "--bindings":
				inv.bindings = value
			case "--expect":
				inv.expect = value
			case "--confirm":
				inv.confirm = value
			case "--limit":
				n, e := strconv.Atoi(value)
				if e != nil {
					return inv, true, "invalid --limit"
				}
				inv.limit = n
			case "--keep":
				n, e := strconv.Atoi(value)
				if e != nil {
					return inv, true, "invalid --keep"
				}
				inv.keep = n
			default:
				return inv, true, "unknown flag " + arg
			}
			continue
		}
		if inv.name != "" {
			return inv, true, "unexpected extra operand"
		}
		inv.name = arg
		i++
	}
	if inv.help {
		return inv, true, ""
	}
	if inv.name != "" && profile.ValidateName(inv.name) != nil {
		return inv, true, "invalid Profile name"
	}
	if inv.as != "" && profile.ValidateName(inv.as) != nil {
		return inv, true, "invalid --as Profile name"
	}
	if inv.lineage != "" && !historyLineageToken.MatchString(inv.lineage) {
		return inv, true, "invalid lineage ID"
	}
	if inv.revision != "" && !historyEventToken.MatchString(inv.revision) {
		return inv, true, "invalid revision event ID"
	}
	if inv.to != "" && !historyEventToken.MatchString(inv.to) {
		return inv, true, "invalid --to event ID"
	}
	selectorCount := 0
	if inv.name != "" {
		selectorCount++
	}
	if inv.lineage != "" {
		selectorCount++
	}
	switch inv.action {
	case "history":
		if selectorCount != 1 {
			return inv, true, "exactly one NAME or --lineage is required"
		}
		if inv.limit < 1 || inv.limit > 100 {
			return inv, true, "--limit must be from 1 through 100"
		}
		if inv.revision != "" || inv.to != "" || inv.as != "" || inv.bindings != "" || inv.expect != "" || inv.confirm != "" || inv.dryRun {
			return inv, true, "unsupported history option"
		}
	case "diff":
		if selectorCount != 1 || inv.revision == "" {
			return inv, true, "exactly one selector and --revision are required"
		}
		if inv.as != "" || inv.bindings != "" || inv.expect != "" || inv.confirm != "" || inv.dryRun || inv.limit != 100 || inv.keep != 100 {
			return inv, true, "unsupported diff option"
		}
	case "restore":
		if selectorCount != 1 || inv.revision == "" {
			return inv, true, "exactly one selector and --revision are required"
		}
		preview := inv.dryRun && inv.expect == "" && inv.confirm == ""
		apply := !inv.dryRun && inv.expect != "" && inv.confirm != ""
		if !preview && !apply {
			return inv, true, "restore requires either --dry-run or both --expect and --confirm"
		}
		if inv.to != "" || inv.limit != 100 || inv.keep != 100 {
			return inv, true, "unsupported restore option"
		}
		if apply && (!historyDigestToken.MatchString(inv.expect) || profile.ValidateName(inv.confirm) != nil) {
			return inv, true, "restore requires a valid preview digest and Profile name confirmation"
		}
	case "pin":
		if inv.lineage == "" || inv.revision == "" || selectorCount != 1 || inv.name != "" || inv.dryRun || inv.to != "" || inv.as != "" || inv.bindings != "" || inv.expect != "" || inv.confirm != "" || inv.limit != 100 || inv.keep != 100 {
			return inv, true, "pin requires --lineage and --revision"
		}
	case "unpin":
		if inv.lineage == "" || inv.revision == "" || inv.confirm != inv.revision || selectorCount != 1 || inv.name != "" || inv.dryRun || inv.to != "" || inv.as != "" || inv.bindings != "" || inv.expect != "" || inv.limit != 100 || inv.keep != 100 {
			return inv, true, "unpin requires --lineage, --revision and matching --confirm"
		}
	case "prune":
		if inv.lineage == "" || selectorCount != 1 || inv.name != "" || inv.keep < 1 || inv.keep > 100 || inv.revision != "" || inv.to != "" || inv.as != "" || inv.bindings != "" || inv.limit != 100 {
			return inv, true, "prune requires --lineage and --keep from 1 through 100"
		}
		preview := inv.dryRun && inv.expect == "" && inv.confirm == ""
		apply := !inv.dryRun && inv.expect != "" && inv.confirm == inv.lineage
		if !preview && !apply {
			return inv, true, "prune requires --dry-run or matching --expect and --confirm"
		}
		if apply && !historyDigestToken.MatchString(inv.expect) {
			return inv, true, "prune requires a valid preview digest"
		}
	}
	return inv, true, ""
}

var (
	historyLineageToken = regexp.MustCompile(`^ln_[0-9a-f]{32}$`)
	historyEventToken   = regexp.MustCompile(`^ev_[0-9a-f]{32}$`)
	historyDigestToken  = regexp.MustCompile(`^hg_[0-9a-f]{64}$`)
)

func (app App) RunProfileHistory(ctx context.Context, args []string, home func() (string, error)) (bool, int) {
	inv, handled, problem := parseProfileHistory(args)
	if !handled {
		return false, 0
	}
	if inv.help {
		for _, c := range commands {
			if c.path == historyHelpPath(inv.action) {
				app.printProfileHistoryHelp(c, inv.action)
				return true, 0
			}
		}
	}
	if problem != "" {
		return true, app.historyError(inv, 2, "invalid_invocation", problem)
	}
	if err := ctx.Err(); err != nil {
		return true, app.historyError(inv, 1, "cancelled", "operation was cancelled")
	}
	var repository historyRepository
	var existingHome string
	if app.Repository != nil {
		repository, _ = app.Repository.(historyRepository)
	}
	if repository == nil {
		var err error
		existingHome, err = home()
		if err != nil {
			return true, app.historyError(inv, 1, "storage_unavailable", "Profile history storage is unavailable")
		}
		repository = profilerepo.New(filepath.Join(existingHome, ".acs"))
	}
	if inv.action == "restore" && app.Categories == nil {
		if existingHome == "" {
			var err error
			existingHome, err = home()
			if err != nil {
				return true, app.historyError(inv, 1, "storage_unavailable", "Profile codec is unavailable")
			}
		}
		editor, err := devin.NewProfileEditor(existingHome)
		if err != nil {
			return true, app.historyError(inv, 1, "storage_unavailable", "Profile codec is unavailable")
		}
		app.Categories = editor.Categories()
	}
	selector := profilerepo.HistorySelector{Name: inv.name, Lineage: inv.lineage}
	switch inv.action {
	case "history":
		result, err := repository.History(ctx, selector, inv.limit)
		if err != nil {
			return true, app.historyOperationalError(inv, err)
		}
		return true, app.writeHistory(inv, result)
	case "pin", "unpin":
		err := repository.SetHistoryPin(ctx, inv.lineage, inv.revision, inv.action == "pin")
		if err != nil {
			return true, app.historyOperationalError(inv, err)
		}
		return true, app.writeSimpleHistory(inv, map[string]any{"schemaVersion": 1, "operation": "profile.history." + inv.action, "status": "committed", "lineageId": inv.lineage, "eventId": inv.revision})
	case "prune":
		var preview profilerepo.PrunePreview
		var err error
		if inv.dryRun {
			preview, err = repository.PreviewPrune(ctx, inv.lineage, inv.keep)
		} else {
			preview, err = repository.Prune(ctx, inv.lineage, inv.keep, inv.expect)
		}
		if err != nil {
			return true, app.historyOperationalError(inv, err)
		}
		return true, app.writePrune(inv, preview)
	case "diff":
		result, err := app.profileDiff(ctx, repository, selector, inv)
		if err != nil {
			return true, app.historyOperationalError(inv, err)
		}
		return true, app.writeSimpleHistory(inv, result)
	case "restore":
		return true, app.profileRestore(ctx, repository, selector, inv)
	}
	return true, 2
}

func (app App) printProfileHistoryHelp(command commandSpec, action string) {
	fmt.Fprintf(app.Output, "Usage: %s\n\n%s\n\nFlags:\n", command.syntax, command.description)
	switch action {
	case "history":
		fmt.Fprintln(app.Output, "  --lineage ID  Select an adopted lineage instead of a live Profile name")
		fmt.Fprintln(app.Output, "  --limit N  Return 1 through 100 newest events (default 100)")
	case "diff":
		fmt.Fprintln(app.Output, "  --lineage ID  Select a lineage instead of a live Profile name")
		fmt.Fprintln(app.Output, "  --revision EVENT  Select the starting history event")
		fmt.Fprintln(app.Output, "  --to EVENT  Compare with another event instead of current intent")
	case "restore":
		fmt.Fprintln(app.Output, "  --lineage ID  Select a lineage instead of a live Profile name")
		fmt.Fprintln(app.Output, "  --revision EVENT  Select the history event to restore")
		fmt.Fprintln(app.Output, "  --as NAME  Choose a no-clobber destination")
		fmt.Fprintln(app.Output, "  --bindings FILE  Supply bounded declarative choices not available from current intent")
		fmt.Fprintln(app.Output, "  --dry-run  Passively preview the exact candidate and digest")
		fmt.Fprintln(app.Output, "  --expect DIGEST  Require the exact preview digest when applying")
		fmt.Fprintln(app.Output, "  --confirm NAME  Confirm the exact destination when applying")
	case "pin":
		fmt.Fprintln(app.Output, "  --lineage ID  Select the exact lineage")
		fmt.Fprintln(app.Output, "  --revision EVENT  Protect the exact history event")
	case "unpin":
		fmt.Fprintln(app.Output, "  --lineage ID  Select the exact lineage")
		fmt.Fprintln(app.Output, "  --revision EVENT  Select the exact history event")
		fmt.Fprintln(app.Output, "  --confirm EVENT  Confirm that same event before unpinning")
	case "prune":
		fmt.Fprintln(app.Output, "  --lineage ID  Select the exact lineage")
		fmt.Fprintln(app.Output, "  --keep N  Keep 1 through 100 ordinary events (default 100)")
		fmt.Fprintln(app.Output, "  --dry-run  Passively preview the exact candidate set and digest")
		fmt.Fprintln(app.Output, "  --expect DIGEST  Require the exact preview digest when applying")
		fmt.Fprintln(app.Output, "  --confirm ID  Confirm the exact lineage when applying")
	}
	fmt.Fprintln(app.Output, "  --json  Emit one bounded schema-version-1 JSON object")
	fmt.Fprintln(app.Output, "  --help  Show this help without discovering HOME or runtime state")
}

func historyHelpPath(action string) string {
	if action == "pin" || action == "unpin" || action == "prune" {
		return "profile history " + action
	}
	return "profile " + action
}
func (app App) historyError(inv historyInvocation, code int, kind, message string) int {
	if inv.json {
		_ = json.NewEncoder(app.Output).Encode(map[string]any{"schemaVersion": 1, "operation": "profile." + inv.action, "status": "error", "code": kind, "message": safeTerminalText(message)})
		return code
	}
	fmt.Fprintf(app.ErrorOutput, "acs: %s\n", safeTerminalText(message))
	return code
}
func (app App) historyOperationalError(inv historyInvocation, err error) int {
	kind := "history_unavailable"
	switch {
	case errors.Is(err, profilerepo.ErrConflict):
		kind = "conflict"
	case errors.Is(err, profilerepo.ErrNotFound):
		kind = "not_found"
	case errors.Is(err, profilerepo.ErrQuota):
		kind = "limit"
	case errors.Is(err, profilerepo.ErrUnsafe):
		kind = "corrupt"
	}
	return app.historyError(inv, 1, kind, "Profile history operation could not be completed safely")
}
func (app App) writeSimpleHistory(inv historyInvocation, value any) int {
	if inv.json {
		encoded, err := json.Marshal(value)
		encoded = append(encoded, '\n')
		if err != nil || len(encoded) > 1<<20 {
			return 1
		}
		if written, err := app.Output.Write(encoded); err != nil || written != len(encoded) {
			return 1
		}
		return 0
	}
	encoded, _ := json.Marshal(value)
	fmt.Fprintln(app.Output, safeTerminalText(string(encoded)))
	return 0
}
func (app App) writeHistory(inv historyInvocation, result profilerepo.HistoryResult) int {
	if inv.json {
		return app.writeSimpleHistory(inv, result)
	}
	if len(result.Events) == 0 {
		fmt.Fprintln(app.Output, "No Profile history.")
		return 0
	}
	fmt.Fprintf(app.Output, "Profile lineage %s\n", result.LineageID)
	for _, e := range result.Events {
		fmt.Fprintf(app.Output, "%s  %s  %s  %s\n", e.EventID, e.Operation, e.Profile.State, e.CreatedAt)
	}
	return 0
}
func (app App) writePrune(inv historyInvocation, p profilerepo.PrunePreview) int {
	if inv.json {
		return app.writeSimpleHistory(inv, p)
	}
	fmt.Fprintf(app.Output, "Profile history prune %s: %d candidate(s), keep %d, digest %s\n", map[bool]string{true: "preview", false: "committed"}[inv.dryRun], p.CandidateCount, p.Keep, p.Digest)
	return 0
}

type semanticDiff struct {
	SchemaVersion int      `json:"schemaVersion"`
	LineageID     string   `json:"lineageId"`
	From          string   `json:"from"`
	To            string   `json:"to"`
	Added         []string `json:"added"`
	Removed       []string `json:"removed"`
	Changed       []string `json:"changed"`
	Bindings      string   `json:"bindings"`
}

func semanticFacts(name string, data []byte) ([]string, error) {
	entry := profileinspect.InspectBytes(name, data)
	if entry.Status != "valid" {
		return nil, profilerepo.ErrUnsafe
	}
	facts := []string{"profile.name=" + name, fmt.Sprintf("profile.version=%d", *entry.StoredVersion)}
	if entry.Workspace != nil {
		facts = append(facts, "common.workspace="+*entry.Workspace)
	}
	for _, c := range entry.Categories {
		for _, s := range c.Selection {
			facts = append(facts, "common."+c.ID+"="+string(s.Source)+":"+s.RelativePath)
		}
	}
	for _, o := range entry.Overlays {
		facts = append(facts, "overlay."+o.ID+".support="+o.Support)
	}
	sort.Strings(facts)
	return facts, nil
}
func diffFacts(a, b []string) (added, removed, changed []string) {
	added, removed, changed = []string{}, []string{}, []string{}
	am, bm := map[string]bool{}, map[string]bool{}
	av, bv := map[string][]string{}, map[string][]string{}
	for _, v := range a {
		am[v] = true
		parts := strings.SplitN(v, "=", 2)
		if len(parts) == 2 {
			av[parts[0]] = append(av[parts[0]], parts[1])
		}
	}
	for _, v := range b {
		bm[v] = true
		parts := strings.SplitN(v, "=", 2)
		if len(parts) == 2 {
			bv[parts[0]] = append(bv[parts[0]], parts[1])
		}
		if !am[v] {
			added = append(added, v)
		}
	}
	for _, v := range a {
		if !bm[v] {
			removed = append(removed, v)
		}
	}
	for key, old := range av {
		if now, ok := bv[key]; ok && len(old) == 1 && len(now) == 1 && old[0] != now[0] {
			changed = append(changed, key)
			added = slices.DeleteFunc(added, func(value string) bool { return strings.HasPrefix(value, key+"=") })
			removed = slices.DeleteFunc(removed, func(value string) bool { return strings.HasPrefix(value, key+"=") })
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	sort.Strings(changed)
	return added, removed, changed
}
func (app App) profileDiff(ctx context.Context, r historyRepository, selector profilerepo.HistorySelector, inv historyInvocation) (semanticDiff, error) {
	from, err := r.RestoreSnapshot(ctx, selector, inv.revision)
	if err != nil {
		return semanticDiff{}, err
	}
	toID := "current"
	var toName string
	var toBytes []byte
	if inv.to != "" {
		to, err := r.RestoreSnapshot(ctx, selector, inv.to)
		if err != nil {
			return semanticDiff{}, err
		}
		toID, toName, toBytes = inv.to, to.Name, to.Bytes
	} else {
		h, err := r.History(ctx, selector, 1)
		if err != nil {
			return semanticDiff{}, err
		}
		if len(h.Events) > 0 && h.Events[0].Profile.State == "live" {
			toName = h.Events[0].Profile.Name
			s, err := r.Read(ctx, toName)
			if err != nil {
				return semanticDiff{}, err
			}
			if s.Exists {
				toBytes = s.Bytes
			}
		}
	}
	a, err := semanticFacts(from.Name, from.Bytes)
	if err != nil {
		return semanticDiff{}, err
	}
	b := []string{}
	if toBytes != nil {
		b, err = semanticFacts(toName, toBytes)
		if err != nil {
			return semanticDiff{}, err
		}
	}
	added, removed, changed := diffFacts(a, b)
	return semanticDiff{1, from.LineageID, inv.revision, toID, added, removed, changed, "references_redacted"}, nil
}

type restorePreview struct {
	SchemaVersion  int          `json:"schemaVersion"`
	LineageID      string       `json:"lineageId"`
	EventID        string       `json:"eventId"`
	Destination    string       `json:"destination"`
	TargetRevision string       `json:"targetRevision"`
	Digest         string       `json:"digest"`
	Diff           semanticDiff `json:"diff"`
	Bindings       string       `json:"bindings"`
}

func restoreDigest(lineage, event, destination, current, bindingDecision string, intended []byte) string {
	h := sha256.New()
	for _, v := range []string{"acs-profile-restore-v1", lineage, event, destination, current, bindingDecision} {
		h.Write([]byte(v))
		h.Write([]byte{0})
	}
	h.Write(intended)
	return "hg_" + hex.EncodeToString(h.Sum(nil))
}
func (app App) profileRestore(ctx context.Context, r historyRepository, selector profilerepo.HistorySelector, inv historyInvocation) int {
	selected, err := r.RestoreSnapshot(ctx, selector, inv.revision)
	if err != nil {
		return app.historyOperationalError(inv, err)
	}
	destination := inv.as
	lineageHead, headErr := r.History(ctx, selector, 1)
	if headErr != nil {
		return app.historyOperationalError(inv, headErr)
	}
	if destination == "" {
		destination = selected.Name
		if len(lineageHead.Events) > 0 && lineageHead.Events[0].Profile.State == "live" {
			destination = lineageHead.Events[0].Profile.Name
		}
	}
	if profile.ValidateName(destination) != nil {
		return app.historyError(inv, 2, "invalid_invocation", "invalid restore destination")
	}
	if app.Categories == nil {
		return app.historyError(inv, 1, "unavailable", "Profile codec is unavailable")
	}
	candidate, err := app.Categories.DecodeNamed(selected.Name, selected.Bytes)
	if err != nil {
		return app.historyError(inv, 1, "incompatible", "selected revision is unsupported by the current Profile codec")
	}
	candidate.Name = destination
	current, err := r.Read(ctx, destination)
	if err != nil {
		return app.historyOperationalError(inv, err)
	}
	if inv.as != "" && current.Exists {
		return app.historyError(inv, 1, "conflict", "--as destination is occupied")
	}
	bindingDecision := "none"
	cloneSourceName := ""
	cloneSource := profilerepo.Snapshot{}
	if current.Exists {
		destinationHistory, historyErr := r.History(ctx, profilerepo.HistorySelector{Name: destination}, 1)
		if historyErr != nil {
			return app.historyOperationalError(inv, historyErr)
		}
		if destinationHistory.LineageID == "" || destinationHistory.LineageID != selected.LineageID {
			return app.historyError(inv, 1, "conflict", "restore destination belongs to another or unadopted lineage")
		}
		existing, decodeErr := app.Categories.DecodeNamed(destination, current.Bytes)
		if decodeErr != nil {
			return app.historyError(inv, 1, "incompatible", "current destination intent is corrupt or unsupported")
		}
		needsBindings, mergeErr := preserveCurrentRestoreBindings(&candidate, existing)
		if mergeErr != nil {
			return app.historyError(inv, 1, "incompatible", "current destination bindings cannot be interpreted safely")
		}
		if needsBindings {
			bound, rawBindings, bindErr := app.bindAbsentRestoreCandidate(candidate, destination, inv.bindings)
			if bindErr != nil {
				return app.restoreBindingError(inv, bindErr)
			}
			candidate = bound
			if _, mergeErr = preserveCurrentRestoreBindings(&candidate, existing); mergeErr != nil {
				return app.historyError(inv, 1, "incompatible", "current destination bindings cannot be preserved safely")
			}
			sum := sha256.Sum256(rawBindings)
			bindingDecision = "current+declarative:" + hex.EncodeToString(sum[:])
		} else if inv.bindings != "" {
			return app.historyError(inv, 2, "invalid_invocation", "--bindings is unnecessary because the current destination supplies every binding decision")
		} else {
			bindingDecision = "current:" + current.Revision.String()
		}
	} else if inv.as != "" && len(lineageHead.Events) > 0 && lineageHead.Events[0].Profile.State == "live" {
		cloneSourceName = lineageHead.Events[0].Profile.Name
		cloneSource, err = r.Read(ctx, cloneSourceName)
		if err != nil || !cloneSource.Exists {
			return app.historyError(inv, 1, "conflict", "current lineage head could not be revalidated for derived restore")
		}
		existing, decodeErr := app.Categories.DecodeNamed(cloneSourceName, cloneSource.Bytes)
		if decodeErr != nil {
			return app.historyError(inv, 1, "incompatible", "current lineage head is corrupt or unsupported")
		}
		needsBindings, mergeErr := preserveCurrentRestoreBindings(&candidate, existing)
		if mergeErr != nil {
			return app.historyError(inv, 1, "incompatible", "current lineage bindings cannot be interpreted safely")
		}
		if needsBindings {
			bound, rawBindings, bindErr := app.bindAbsentRestoreCandidate(candidate, destination, inv.bindings)
			if bindErr != nil {
				return app.restoreBindingError(inv, bindErr)
			}
			candidate = bound
			if _, mergeErr = preserveCurrentRestoreBindings(&candidate, existing); mergeErr != nil {
				return app.historyError(inv, 1, "incompatible", "current lineage bindings cannot be preserved safely")
			}
			sum := sha256.Sum256(rawBindings)
			bindingDecision = "source-current+declarative:" + cloneSource.Revision.String() + ":" + hex.EncodeToString(sum[:])
		} else if inv.bindings != "" {
			return app.historyError(inv, 2, "invalid_invocation", "--bindings is unnecessary because the current lineage supplies every binding decision")
		} else {
			bindingDecision = "source-current:" + cloneSource.Revision.String()
		}
	} else {
		bound, bindingData, bindErr := app.bindAbsentRestoreCandidate(candidate, destination, inv.bindings)
		if bindErr != nil {
			return app.restoreBindingError(inv, bindErr)
		}
		candidate = bound
		bindingDecision = "declarative:empty"
		if bindingData != nil {
			sum := sha256.Sum256(bindingData)
			bindingDecision = "declarative:" + hex.EncodeToString(sum[:])
		}
	}
	_, canonical, err := profile.Canonicalize(app.Categories, candidate)
	if err != nil {
		return app.historyError(inv, 1, "incompatible", "selected revision cannot be represented by the current Profile codec")
	}
	currentRevision := current.Revision.String()
	fromFacts := []string{}
	if current.Exists {
		fromFacts, err = semanticFacts(destination, current.Bytes)
		if err != nil {
			return app.historyError(inv, 1, "incompatible", "current destination intent is corrupt or unsupported")
		}
	}
	toFacts, err := semanticFacts(destination, canonical)
	if err != nil {
		return app.historyError(inv, 1, "incompatible", "restored intent cannot be described safely")
	}
	added, removed, changed := diffFacts(fromFacts, toFacts)
	diff := semanticDiff{1, selected.LineageID, "current", selected.EventID, added, removed, changed, "references_redacted"}
	preview := restorePreview{1, selected.LineageID, selected.EventID, destination, currentRevision, restoreDigest(selected.LineageID, selected.EventID, destination, currentRevision, bindingDecision, canonical), diff, bindingDecisionStatus(bindingDecision)}
	if inv.dryRun {
		return app.writeSimpleHistory(inv, preview)
	}
	if inv.confirm != destination || inv.expect != preview.Digest {
		return app.historyError(inv, 1, "conflict", "restore preview digest or confirmation does not match current state")
	}
	var request profilerepo.Request
	if current.Exists {
		request = profilerepo.ReplaceRequest{Name: destination, Expected: current.Revision, Bytes: canonical}
	} else if cloneSourceName != "" {
		request = profilerepo.CloneRequest{Source: cloneSourceName, Destination: destination, ExpectedSource: cloneSource.Revision, ExpectedDestination: current.Revision, Bytes: canonical}
	} else {
		request = profilerepo.CreateRequest{Name: destination, Expected: current.Revision, Bytes: canonical}
	}
	requestedLineage := selected.LineageID
	if cloneSourceName != "" {
		requestedLineage = ""
	}
	out, err := r.Apply(ctx, profilerepo.HistoryRequest{Request: request, Operation: "restore", Lineage: requestedLineage})
	if err != nil || out.State != profilerepo.Committed || out.RecoveryRequired {
		return app.restoreApplyError(inv, out, err)
	}
	committed, inspectErr := r.History(ctx, profilerepo.HistorySelector{Name: destination}, 1)
	if inspectErr != nil || len(committed.Events) != 1 || committed.Events[0].Operation != "restore" {
		return app.historyError(inv, 1, "committed_inspection_failed", "restore committed, but its new history event could not be inspected; do not retry")
	}
	return app.writeSimpleHistory(inv, map[string]any{"schemaVersion": 1, "operation": "profile.restore", "status": "committed", "lineageId": committed.LineageID, "sourceLineageId": selected.LineageID, "eventId": committed.Events[0].EventID, "selectedEventId": selected.EventID, "destination": destination})
}

func bindingDecisionStatus(decision string) string {
	if strings.HasPrefix(decision, "current:") {
		return "preserved_current"
	}
	if strings.HasPrefix(decision, "current+declarative:") {
		return "preserved_current_and_explicit_declarative"
	}
	if strings.HasPrefix(decision, "source-current+declarative:") {
		return "preserved_source_current_and_explicit_declarative"
	}
	if strings.HasPrefix(decision, "source-current:") {
		return "preserved_source_current"
	}
	if strings.HasPrefix(decision, "declarative:") {
		return "explicit_declarative"
	}
	return "none_required"
}

var (
	errRestoreBindingRequired    = errors.New("restore bindings required")
	errRestoreBindingUnavailable = errors.New("restore bindings unavailable")
	errRestoreBindingInvalid     = errors.New("restore bindings invalid")
)

func (app App) bindAbsentRestoreCandidate(candidate profile.Profile, destination, path string) (profile.Profile, []byte, error) {
	exchange, _, err := profileexchange.Export(candidate)
	if err != nil {
		return profile.Profile{}, nil, errRestoreBindingInvalid
	}
	var bindingData []byte
	if path != "" {
		reader := app.ReadProfileDocument
		if reader == nil {
			reader = readProfileDocument
		}
		bindingData, err = reader(path)
		if err != nil {
			return profile.Profile{}, nil, errRestoreBindingUnavailable
		}
	}
	bound := profileexchange.Decode(exchange, bindingData, destination)
	if bound.Code == profileexchange.CodeBindingRequired {
		return profile.Profile{}, nil, errRestoreBindingRequired
	}
	if bound.Code != profileexchange.CodeValid || bound.Candidate == nil {
		return profile.Profile{}, nil, errRestoreBindingInvalid
	}
	return *bound.Candidate, bindingData, nil
}

func (app App) restoreBindingError(inv historyInvocation, err error) int {
	switch {
	case errors.Is(err, errRestoreBindingRequired):
		return app.historyError(inv, 1, "unresolved_binding", "restore destination requires explicit supported local bindings")
	case errors.Is(err, errRestoreBindingUnavailable):
		return app.historyError(inv, 1, "binding_unavailable", "restore binding document is unavailable")
	default:
		return app.historyError(inv, 1, "invalid_binding", "restore binding document is invalid, conflicting, or unsupported")
	}
}

func preserveCurrentRestoreBindings(candidate *profile.Profile, current profile.Profile) (bool, error) {
	selectedPayload, selectedOK := candidate.Common[commonprofile.SkillsCapabilityID]
	currentPayload, currentOK := current.Common[commonprofile.SkillsCapabilityID]
	if selectedOK {
		selected, err := commonprofile.DecodeSkillSelection(selectedPayload.Selection)
		if err != nil {
			return false, err
		}
		currentByPath := map[string]string{}
		ambiguous := map[string]bool{}
		if currentOK {
			currentSelection, err := commonprofile.DecodeSkillSelection(currentPayload.Selection)
			if err != nil {
				return false, err
			}
			for _, reference := range currentSelection {
				source := string(reference.Source)
				if previous, ok := currentByPath[reference.RelativePath]; ok && previous != source {
					ambiguous[reference.RelativePath] = true
				} else {
					currentByPath[reference.RelativePath] = source
				}
			}
		}
		needs := false
		for index := range selected {
			if source, ok := currentByPath[selected[index].RelativePath]; ok && !ambiguous[selected[index].RelativePath] {
				selected[index].Source = skills.Source(source)
			} else {
				needs = true
			}
		}
		encoded, err := commonprofile.EncodeSkillSelection(selected)
		if err != nil {
			return false, err
		}
		selectedPayload.Selection = encoded
		candidate.Common[commonprofile.SkillsCapabilityID] = selectedPayload
		for id, overlay := range candidate.Overlays {
			if now, ok := current.Overlays[id]; ok {
				overlay.AuthRef = now.AuthRef
				candidate.Overlays[id] = overlay
			} else if overlay.AuthRef != "" {
				needs = true
			}
		}
		return needs, nil
	}
	return false, nil
}

func (app App) restoreApplyError(inv historyInvocation, outcome profilerepo.Outcome, err error) int {
	switch {
	case outcome.State == profilerepo.Unknown || outcome.RecoveryRequired || outcome.State == profilerepo.Committed:
		return app.historyError(inv, 1, "recovery_required", "restore outcome requires repository recovery or inspection")
	case errors.Is(err, profilerepo.ErrConflict):
		return app.historyError(inv, 1, "conflict", "restore destination or expected revision changed; nothing was committed")
	case errors.Is(err, context.Canceled):
		return app.historyError(inv, 1, "cancelled", "restore was cancelled before commit")
	default:
		return app.historyError(inv, 1, "not_committed", "restore was not committed")
	}
}
