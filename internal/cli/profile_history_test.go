package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
)

func historyDocument(name, auth string) []byte {
	return []byte(`{"version":3,"name":"` + name + `","common":{"skills":{"version":1,"selection":[{"source":"shared-agents","relativePath":"review"}]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"codex":{"version":1,"authRef":"` + auth + `"},"devin":{"version":1}}}`)
}

func historyApp(t *testing.T) (cli.App, *profilerepo.Repository, string) {
	t.Helper()
	home := t.TempDir()
	editor, err := devin.NewProfileEditor(home)
	if err != nil {
		t.Fatal(err)
	}
	repository := profilerepo.New(filepath.Join(home, ".acs"))
	return cli.App{Repository: repository, Categories: editor.Categories(), Output: &bytes.Buffer{}, ErrorOutput: &bytes.Buffer{}}, repository, home
}

func applyHistory(t *testing.T, r *profilerepo.Repository, name string, old, new []byte) {
	t.Helper()
	ctx := context.Background()
	snapshot, err := r.Read(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.Exists {
		if _, err = r.Apply(ctx, profilerepo.CreateRequest{Name: name, Expected: snapshot.Revision, Bytes: old}); err != nil {
			t.Fatal(err)
		}
		snapshot, _ = r.Read(ctx, name)
	}
	if new != nil {
		if _, err = r.Apply(ctx, profilerepo.ReplaceRequest{Name: name, Expected: snapshot.Revision, Bytes: new}); err != nil {
			t.Fatal(err)
		}
	}
}

func treeContents(t *testing.T, root string) []string {
	t.Helper()
	values := []string{}
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		relative, _ := filepath.Rel(root, path)
		if info.IsDir() {
			values = append(values, relative+"/")
			return nil
		}
		data, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		values = append(values, relative+":"+string(data))
		return nil
	})
	sort.Strings(values)
	return values
}

func TestProfileHistoryGrammarIsRejectedBeforeHomeDiscovery(t *testing.T) {
	for _, args := range [][]string{{"profile", "history"}, {"profile", "history", "alpha", "--lineage", "ln_0123456789abcdef0123456789abcdef"}, {"profile", "history", "--lineage", "LN_0123456789abcdef0123456789abcdef"}, {"profile", "diff", "alpha"}, {"profile", "diff", "alpha", "--revision", "../event"}, {"profile", "restore", "alpha", "--revision", "ev_0123456789abcdef0123456789abcdef"}, {"profile", "restore", "alpha", "--revision", "ev_0123456789abcdef0123456789abcdef", "--expect", "hg_short", "--confirm", "alpha"}, {"profile", "history", "prune", "--lineage", "ln_0123456789abcdef0123456789abcdef", "--keep", "0", "--dry-run"}} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var out, errOut bytes.Buffer
			app := cli.App{Output: &out, ErrorOutput: &errOut}
			handled, code := app.RunProfileHistory(context.Background(), args, func() (string, error) { t.Fatal("grammar discovered HOME"); return "", nil })
			if !handled || code != 2 {
				t.Fatalf("handled=%v code=%d out=%s err=%s", handled, code, out.String(), errOut.String())
			}
		})
	}
	var out bytes.Buffer
	app := cli.App{Output: &out, ErrorOutput: &bytes.Buffer{}}
	if handled, code := app.RunProfileHistory(context.Background(), []string{"profile", "restore", "--help"}, func() (string, error) { t.Fatal("help discovered HOME"); return "", nil }); !handled || code != 0 || !strings.Contains(out.String(), "--bindings FILE") {
		t.Fatalf("handled=%v code=%d help=%s", handled, code, out.String())
	}
}

type forcedHistoryOutcomeRepository struct {
	*profilerepo.Repository
	outcome profilerepo.Outcome
	err     error
}

func (r forcedHistoryOutcomeRepository) Apply(context.Context, profilerepo.Request) (profilerepo.Outcome, error) {
	return r.outcome, r.err
}

func TestProfileRestoreReportsTruthfulApplyOutcomes(t *testing.T) {
	baseApp, repository, home := historyApp(t)
	applyHistory(t, repository, "alpha", historyDocument("alpha", "old-auth"), historyDocument("alpha", "current-auth"))
	history, _ := repository.History(context.Background(), profilerepo.HistorySelector{Name: "alpha"}, 100)
	previewArgs := []string{"profile", "restore", "alpha", "--revision", history.Events[1].EventID, "--dry-run", "--json"}
	var previewOut, previewErr bytes.Buffer
	baseApp.Output, baseApp.ErrorOutput = &previewOut, &previewErr
	if _, code := baseApp.RunProfileHistory(context.Background(), previewArgs, func() (string, error) { return home, nil }); code != 0 {
		t.Fatalf("preview code=%d err=%s", code, previewErr.String())
	}
	var preview restorePreviewResult
	if err := json.Unmarshal(previewOut.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		outcome profilerepo.Outcome
		err     error
		code    string
	}{
		{"conflict", profilerepo.Outcome{State: profilerepo.NotCommitted}, profilerepo.ErrConflict, "conflict"},
		{"ordinary failure", profilerepo.Outcome{State: profilerepo.NotCommitted}, errors.New("injected"), "not_committed"},
		{"unknown", profilerepo.Outcome{State: profilerepo.Unknown, RecoveryRequired: true}, errors.New("injected"), "recovery_required"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			app := baseApp
			app.Repository = forcedHistoryOutcomeRepository{repository, test.outcome, test.err}
			app.Output, app.ErrorOutput = &out, &errOut
			args := []string{"profile", "restore", "alpha", "--revision", history.Events[1].EventID, "--expect", preview.Digest, "--confirm", "alpha", "--json"}
			if _, code := app.RunProfileHistory(context.Background(), args, func() (string, error) { return home, nil }); code != 1 || !strings.Contains(out.String(), `"code":"`+test.code+`"`) {
				t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
			}
		})
	}
}

func TestProfileHistoryDiffAndRestoreDryRunsArePassiveAndRedacted(t *testing.T) {
	app, r, home := historyApp(t)
	applyHistory(t, r, "alpha", historyDocument("alpha", "private-old-auth"), historyDocument("alpha", "private-current-auth"))
	history, err := r.History(context.Background(), profilerepo.HistorySelector{Name: "alpha"}, 100)
	if err != nil || len(history.Events) != 2 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	selected := history.Events[1].EventID
	before := treeContents(t, filepath.Join(home, ".acs", "profiles"))
	var out, errOut bytes.Buffer
	app.Output, app.ErrorOutput = &out, &errOut
	if handled, code := app.RunProfileHistory(context.Background(), []string{"profile", "diff", "alpha", "--revision", selected, "--json"}, func() (string, error) { return "", errors.New("unused") }); !handled || code != 0 {
		t.Fatalf("diff code=%d err=%s", code, errOut.String())
	}
	if strings.Contains(out.String(), "private-old-auth") || strings.Contains(out.String(), "private-current-auth") {
		t.Fatalf("diff leaked binding: %s", out.String())
	}
	out.Reset()
	if _, code := app.RunProfileHistory(context.Background(), []string{"profile", "restore", "alpha", "--revision", selected, "--dry-run", "--json"}, func() (string, error) { return "", errors.New("unused") }); code != 0 {
		t.Fatalf("restore code=%d err=%s", code, errOut.String())
	}
	after := treeContents(t, filepath.Join(home, ".acs", "profiles"))
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("dry-run changed storage\nbefore=%q\nafter=%q", before, after)
	}
}

func TestProfileRestoreRequiresDigestAndPreservesCurrentBinding(t *testing.T) {
	home := t.TempDir()
	editor, err := devin.NewProfileEditor(home)
	if err != nil {
		t.Fatal(err)
	}
	repository := profilerepo.New(filepath.Join(home, ".acs"))
	applyHistory(t, repository, "alpha", historyDocument("alpha", "old-auth"), historyDocument("alpha", "current-auth"))
	history, _ := repository.History(context.Background(), profilerepo.HistorySelector{Name: "alpha"}, 100)
	event := history.Events[1].EventID
	app := cli.App{Repository: repository, Categories: editor.Categories()}
	var out, errOut bytes.Buffer
	app.Output, app.ErrorOutput = &out, &errOut
	_, code := app.RunProfileHistory(context.Background(), []string{"profile", "restore", "alpha", "--revision", event, "--dry-run", "--json"}, func() (string, error) { return home, nil })
	if code != 0 {
		t.Fatal(errOut.String())
	}
	var preview struct {
		Digest string `json:"digest"`
	}
	if json.Unmarshal(out.Bytes(), &preview) != nil || preview.Digest == "" {
		t.Fatalf("preview=%s", out.String())
	}
	out.Reset()
	_, code = app.RunProfileHistory(context.Background(), []string{"profile", "restore", "alpha", "--revision", event, "--expect", preview.Digest, "--confirm", "alpha", "--json"}, func() (string, error) { return home, nil })
	if code != 0 {
		t.Fatalf("apply code=%d err=%s", code, errOut.String())
	}
	current, err := repository.Read(context.Background(), "alpha")
	if err != nil || !bytes.Contains(current.Bytes, []byte(`"authRef": "current-auth"`)) {
		t.Fatalf("current=%s err=%v", current.Bytes, err)
	}
	updated, _ := repository.History(context.Background(), profilerepo.HistorySelector{Name: "alpha"}, 100)
	if len(updated.Events) != 3 || updated.Events[0].Operation != "restore" {
		t.Fatalf("events=%+v", updated.Events)
	}
}

func TestProfileRestoreOfDeletedLineageRequiresAndBindsDeclarativeBindings(t *testing.T) {
	app, repository, home := historyApp(t)
	applyHistory(t, repository, "alpha", historyDocument("alpha", "old-auth"), nil)
	lineage := mustHistoryLineage(t, repository, "alpha")
	current, err := repository.Read(context.Background(), "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Apply(context.Background(), profilerepo.HistoryRequest{Request: profilerepo.DeleteRequest{Name: "alpha", Expected: current.Revision}, Operation: "delete"}); err != nil {
		t.Fatal(err)
	}
	history, err := repository.History(context.Background(), profilerepo.HistorySelector{Lineage: lineage}, 100)
	if err != nil || len(history.Events) < 2 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	args := []string{"profile", "restore", "--lineage", history.LineageID, "--revision", history.Events[0].EventID, "--as", "restored", "--dry-run", "--json"}
	var out, errOut bytes.Buffer
	app.Output, app.ErrorOutput = &out, &errOut
	if _, code := app.RunProfileHistory(context.Background(), args, func() (string, error) { return home, nil }); code != 1 || !strings.Contains(out.String(), `"code":"unresolved_binding"`) {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	bindingOne := []byte(`{"bindingVersion":1,"sources":{"source-1":"shared-agents"},"authentications":{"authentication-1":"restored-one"}}`)
	app.ReadProfileDocument = func(path string) ([]byte, error) {
		if path != "bindings.json" {
			t.Fatalf("unexpected binding path %q", path)
		}
		return append([]byte(nil), bindingOne...), nil
	}
	out.Reset()
	args = append(args[:len(args)-1], "--bindings", "bindings.json", "--json")
	if _, code := app.RunProfileHistory(context.Background(), args, func() (string, error) { return home, nil }); code != 0 {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	var first restorePreviewResult
	if err := json.Unmarshal(out.Bytes(), &first); err != nil || first.Digest == "" || first.Bindings != "explicit_declarative" {
		t.Fatalf("preview=%s err=%v", out.String(), err)
	}
	app.ReadProfileDocument = func(string) ([]byte, error) {
		return []byte(`{"bindingVersion":1,"sources":{"source-1":"shared-agents"},"authentications":{"authentication-1":"restored-two"}}`), nil
	}
	out.Reset()
	if _, code := app.RunProfileHistory(context.Background(), args, func() (string, error) { return home, nil }); code != 0 {
		t.Fatalf("second preview code=%d out=%s", code, out.String())
	}
	var second restorePreviewResult
	if err := json.Unmarshal(out.Bytes(), &second); err != nil || first.Digest == second.Digest {
		t.Fatalf("binding choice was not digest-bound: first=%+v second=%+v err=%v", first, second, err)
	}
	app.ReadProfileDocument = func(string) ([]byte, error) { return append([]byte(nil), bindingOne...), nil }
	out.Reset()
	applyArgs := []string{"profile", "restore", "--lineage", history.LineageID, "--revision", history.Events[0].EventID, "--as", "restored", "--bindings", "bindings.json", "--expect", first.Digest, "--confirm", "restored", "--json"}
	if _, code := app.RunProfileHistory(context.Background(), applyArgs, func() (string, error) { return home, nil }); code != 0 {
		t.Fatalf("apply code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	for i := 0; i < 2; i++ {
		if recovery, err := repository.Recover(context.Background()); err != nil || recovery.RecoveryRequired {
			t.Fatalf("recover %d=%+v err=%v", i, recovery, err)
		}
	}
	restored, err := repository.History(context.Background(), profilerepo.HistorySelector{Name: "restored"}, 100)
	if err != nil || restored.LineageID != history.LineageID || len(restored.Events) != 3 || restored.Events[0].Operation != "restore" {
		t.Fatalf("restored=%+v err=%v", restored, err)
	}
}

type restorePreviewResult struct {
	Digest   string `json:"digest"`
	Bindings string `json:"bindings"`
}

func mustHistoryLineage(t *testing.T, repository *profilerepo.Repository, name string) string {
	t.Helper()
	history, err := repository.History(context.Background(), profilerepo.HistorySelector{Name: name}, 1)
	if err != nil || history.LineageID == "" {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	return history.LineageID
}

func TestProfileDiffPreservesExactRepeatedSelectionsAndEmptyArrays(t *testing.T) {
	app, repository, home := historyApp(t)
	first := []byte(`{"version":3,"name":"alpha","common":{"skills":{"version":1,"selection":[{"source":"shared-agents","relativePath":"a"},{"source":"shared-agents","relativePath":"b"}]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"devin":{"version":1}}}`)
	second := []byte(`{"version":3,"name":"alpha","common":{"skills":{"version":1,"selection":[{"source":"shared-agents","relativePath":"a"},{"source":"shared-agents","relativePath":"c"}]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"devin":{"version":1}}}`)
	applyHistory(t, repository, "alpha", first, second)
	history, err := repository.History(context.Background(), profilerepo.HistorySelector{Name: "alpha"}, 100)
	if err != nil || len(history.Events) != 2 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	var out, errOut bytes.Buffer
	app.Output, app.ErrorOutput = &out, &errOut
	args := []string{"profile", "diff", "alpha", "--revision", history.Events[1].EventID, "--to", history.Events[0].EventID, "--json"}
	if _, code := app.RunProfileHistory(context.Background(), args, func() (string, error) { return home, nil }); code != 0 {
		t.Fatalf("code=%d err=%s", code, errOut.String())
	}
	var diff semanticDiffResult
	if err := json.Unmarshal(out.Bytes(), &diff); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(diff.Added, []string{"common.skills=shared-agents:c"}) || !reflect.DeepEqual(diff.Removed, []string{"common.skills=shared-agents:b"}) || diff.Changed == nil || len(diff.Changed) != 0 {
		t.Fatalf("diff=%+v", diff)
	}
	out.Reset()
	args[6] = history.Events[1].EventID
	if _, code := app.RunProfileHistory(context.Background(), args, func() (string, error) { return home, nil }); code != 0 {
		t.Fatalf("identity code=%d err=%s", code, errOut.String())
	}
	if err := json.Unmarshal(out.Bytes(), &diff); err != nil || diff.Added == nil || diff.Removed == nil || diff.Changed == nil {
		t.Fatalf("identity diff arrays were not stable: %s err=%v", out.String(), err)
	}
}

type semanticDiffResult struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Changed []string `json:"changed"`
}

func TestProfileDiffReportsRenameAndRestoreAsPreviewName(t *testing.T) {
	app, repository, home := historyApp(t)
	ctx := context.Background()
	alpha := []byte(`{"version":3,"name":"alpha","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"devin":{"version":1}}}`)
	beta := bytes.Replace(alpha, []byte(`"alpha"`), []byte(`"beta"`), 1)
	applyHistory(t, repository, "alpha", alpha, nil)
	source, _ := repository.Read(ctx, "alpha")
	destination, _ := repository.Read(ctx, "beta")
	if out, err := repository.Apply(ctx, profilerepo.HistoryRequest{Request: profilerepo.RenameRequest{Source: "alpha", Destination: "beta", ExpectedSource: source.Revision, ExpectedDestination: destination.Revision, Bytes: beta}, Operation: "rename"}); err != nil || out.State != profilerepo.Committed {
		t.Fatalf("rename=%+v err=%v", out, err)
	}
	history, err := repository.History(ctx, profilerepo.HistorySelector{Name: "beta"}, 100)
	if err != nil || len(history.Events) != 2 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	createdEvent := history.Events[1].EventID
	var out, errOut bytes.Buffer
	app.Output, app.ErrorOutput = &out, &errOut
	diffArgs := []string{"profile", "diff", "--lineage", history.LineageID, "--revision", createdEvent, "--to", history.Events[0].EventID, "--json"}
	if _, code := app.RunProfileHistory(ctx, diffArgs, func() (string, error) { return home, nil }); code != 0 {
		t.Fatalf("diff code=%d err=%s", code, errOut.String())
	}
	var diff semanticDiffResult
	if err := json.Unmarshal(out.Bytes(), &diff); err != nil || !reflect.DeepEqual(diff.Changed, []string{"profile.name"}) {
		t.Fatalf("rename diff=%s err=%v", out.String(), err)
	}
	out.Reset()
	previewArgs := []string{"profile", "restore", "--lineage", history.LineageID, "--revision", createdEvent, "--as", "gamma", "--dry-run", "--json"}
	if _, code := app.RunProfileHistory(ctx, previewArgs, func() (string, error) { return home, nil }); code != 0 {
		t.Fatalf("preview code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	var preview struct {
		Destination string             `json:"destination"`
		Digest      string             `json:"digest"`
		Bindings    string             `json:"bindings"`
		Diff        semanticDiffResult `json:"diff"`
	}
	if err := json.Unmarshal(out.Bytes(), &preview); err != nil || preview.Destination != "gamma" || preview.Digest == "" || preview.Bindings != "preserved_source_current" || !slices.Contains(preview.Diff.Added, "profile.name=gamma") {
		t.Fatalf("preview=%s err=%v", out.String(), err)
	}
	changedBeta := bytes.Replace(beta, []byte(`"read-only"`), []byte(`"read-write"`), 1)
	source, _ = repository.Read(ctx, "beta")
	if changed, err := repository.Apply(ctx, profilerepo.HistoryRequest{Request: profilerepo.ReplaceRequest{Name: "beta", Expected: source.Revision, Bytes: changedBeta}, Operation: "edit"}); err != nil || changed.State != profilerepo.Committed {
		t.Fatalf("concurrent source edit=%+v err=%v", changed, err)
	}
	out.Reset()
	applyArgs := []string{"profile", "restore", "--lineage", history.LineageID, "--revision", createdEvent, "--as", "gamma", "--expect", preview.Digest, "--confirm", "gamma", "--json"}
	if _, code := app.RunProfileHistory(ctx, applyArgs, func() (string, error) { return home, nil }); code != 1 || !strings.Contains(out.String(), `"code":"conflict"`) {
		t.Fatalf("stale apply code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	out.Reset()
	if _, code := app.RunProfileHistory(ctx, previewArgs, func() (string, error) { return home, nil }); code != 0 {
		t.Fatalf("fresh preview code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	if err := json.Unmarshal(out.Bytes(), &preview); err != nil || preview.Digest == "" {
		t.Fatalf("fresh preview=%s err=%v", out.String(), err)
	}
	applyArgs[9] = preview.Digest
	out.Reset()
	if _, code := app.RunProfileHistory(ctx, applyArgs, func() (string, error) { return home, nil }); code != 0 {
		t.Fatalf("fresh apply code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	var applied struct {
		LineageID       string `json:"lineageId"`
		SourceLineageID string `json:"sourceLineageId"`
		EventID         string `json:"eventId"`
		SelectedEventID string `json:"selectedEventId"`
	}
	if err := json.Unmarshal(out.Bytes(), &applied); err != nil || applied.LineageID == "" || applied.LineageID == history.LineageID || applied.SourceLineageID != history.LineageID || applied.EventID == "" || applied.EventID == createdEvent || applied.SelectedEventID != createdEvent {
		t.Fatalf("applied identity=%s err=%v", out.String(), err)
	}
	betaState, betaErr := repository.Read(ctx, "beta")
	gammaHistory, gammaErr := repository.History(ctx, profilerepo.HistorySelector{Name: "gamma"}, 100)
	if betaErr != nil || !betaState.Exists || !bytes.Equal(betaState.Bytes, changedBeta) || gammaErr != nil || gammaHistory.LineageID != applied.LineageID || len(gammaHistory.Events) != 1 || gammaHistory.Events[0].Operation != "restore" || gammaHistory.Events[0].EventID != applied.EventID {
		t.Fatalf("beta=%+v betaErr=%v gamma=%+v gammaErr=%v", betaState, betaErr, gammaHistory, gammaErr)
	}
}

func TestProfileRestoreRejectsCorruptCurrentDestination(t *testing.T) {
	app, repository, home := historyApp(t)
	applyHistory(t, repository, "alpha", historyDocument("alpha", "old-auth"), historyDocument("alpha", "current-auth"))
	history, _ := repository.History(context.Background(), profilerepo.HistorySelector{Name: "alpha"}, 100)
	if err := os.WriteFile(filepath.Join(home, ".acs", "profiles", "alpha.json"), []byte(`{"broken":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	app.Output, app.ErrorOutput = &out, &errOut
	if _, code := app.RunProfileHistory(context.Background(), []string{"profile", "restore", "alpha", "--revision", history.Events[1].EventID, "--dry-run", "--json"}, func() (string, error) { return home, nil }); code != 1 || !strings.Contains(out.String(), `"code":"incompatible"`) {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
}

func TestProfileRestoreRequiresDeclarativeChoicesCurrentCannotSupply(t *testing.T) {
	app, repository, home := historyApp(t)
	selected := []byte(`{"version":3,"name":"alpha","common":{"skills":{"version":1,"selection":[{"source":"shared-agents","relativePath":"old-only"}]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"codex":{"version":1,"authRef":"old-auth"},"devin":{"version":1}}}`)
	current := []byte(`{"version":3,"name":"alpha","common":{"skills":{"version":1,"selection":[{"source":"devin-config","relativePath":"current-only"}]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"devin":{"version":1}}}`)
	applyHistory(t, repository, "alpha", selected, current)
	history, err := repository.History(context.Background(), profilerepo.HistorySelector{Name: "alpha"}, 100)
	if err != nil || len(history.Events) != 2 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	args := []string{"profile", "restore", "alpha", "--revision", history.Events[1].EventID, "--dry-run", "--json"}
	var out, errOut bytes.Buffer
	app.Output, app.ErrorOutput = &out, &errOut
	if _, code := app.RunProfileHistory(context.Background(), args, func() (string, error) { return home, nil }); code != 1 || !strings.Contains(out.String(), `"code":"unresolved_binding"`) {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	app.ReadProfileDocument = func(string) ([]byte, error) {
		return []byte(`{"bindingVersion":1,"sources":{"source-1":"shared-agents"},"authentications":{"authentication-1":"replacement-auth"}}`), nil
	}
	out.Reset()
	args = append(args[:len(args)-1], "--bindings", "bindings.json", "--json")
	if _, code := app.RunProfileHistory(context.Background(), args, func() (string, error) { return home, nil }); code != 0 {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errOut.String())
	}
	var preview restorePreviewResult
	if err := json.Unmarshal(out.Bytes(), &preview); err != nil || preview.Bindings != "preserved_current_and_explicit_declarative" {
		t.Fatalf("preview=%s err=%v", out.String(), err)
	}
}
