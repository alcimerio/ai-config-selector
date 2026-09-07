package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
)

type historyRaceRepository struct {
	*profilerepo.Repository
	before func(profilerepo.Request)
	after  func(profilerepo.Request)
}

func (r historyRaceRepository) Apply(ctx context.Context, request profilerepo.Request) (profilerepo.Outcome, error) {
	if r.before != nil {
		r.before(request)
	}
	out, err := r.Repository.Apply(ctx, request)
	if err == nil && out.State == profilerepo.Committed {
		if h, ok := request.(profilerepo.HistoryRequest); ok && h.Operation == "restore" && r.after != nil {
			r.after(request)
		}
	}
	return out, err
}

func TestReviewRestoreSuccessIdentityCannotRaceSameOperation(t *testing.T) {
	home := t.TempDir()
	editor, err := devin.NewProfileEditor(home)
	if err != nil {
		t.Fatal(err)
	}
	repo := profilerepo.New(filepath.Join(home, ".acs"))
	ctx := context.Background()
	first := []byte(`{"version":3,"name":"alpha","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"devin":{"version":1}}}`)
	second := bytes.Replace(first, []byte(`"read-only"`), []byte(`"read-write"`), 1)
	s, _ := repo.Read(ctx, "alpha")
	if _, err = repo.Apply(ctx, profilerepo.CreateRequest{Name: "alpha", Expected: s.Revision, Bytes: first}); err != nil {
		t.Fatal(err)
	}
	s, _ = repo.Read(ctx, "alpha")
	if _, err = repo.Apply(ctx, profilerepo.ReplaceRequest{Name: "alpha", Expected: s.Revision, Bytes: second}); err != nil {
		t.Fatal(err)
	}
	history, _ := repo.History(ctx, profilerepo.HistorySelector{Name: "alpha"}, 100)
	selected := history.Events[1].EventID
	var firstEvent string
	var out bytes.Buffer
	app := App{Repository: historyRaceRepository{Repository: repo, after: func(request profilerepo.Request) {
		applied, ok := request.(profilerepo.HistoryRequest)
		if !ok || applied.Operation != "restore" {
			t.Fatalf("unexpected request: %#v", request)
		}
		latest, err := repo.History(ctx, profilerepo.HistorySelector{Name: "alpha"}, 1)
		if err != nil || len(latest.Events) != 1 {
			t.Fatalf("first restore history: %v %+v", err, latest)
		}
		firstEvent = latest.Events[0].EventID
		s, _ := repo.Read(ctx, "alpha")
		if _, err = repo.Apply(ctx, profilerepo.HistoryRequest{Request: profilerepo.ReplaceRequest{Name: "alpha", Expected: s.Revision, Bytes: second}, Operation: "restore", Lineage: latest.LineageID}); err != nil {
			t.Fatalf("second restore: %v", err)
		}
	}}, Categories: editor.Categories(), Output: &out, ErrorOutput: &bytes.Buffer{}}
	if code := app.profileRestore(ctx, app.Repository.(historyRepository), profilerepo.HistorySelector{Name: "alpha"}, historyInvocation{action: "restore", name: "alpha", revision: selected, dryRun: true, json: true}); code != 0 {
		t.Fatalf("preview code=%d", code)
	}
	var preview restorePreview
	if err := json.Unmarshal(out.Bytes(), &preview); err != nil {
		t.Fatalf("preview=%q err=%v", out.String(), err)
	}
	out.Reset()
	code := app.profileRestore(ctx, app.Repository.(historyRepository), profilerepo.HistorySelector{Name: "alpha"}, historyInvocation{action: "restore", name: "alpha", revision: selected, expect: preview.Digest, confirm: "alpha", json: true})
	if code != 0 {
		t.Fatalf("apply code=%d out=%s", code, out.String())
	}
	var result struct {
		EventID string `json:"eventId"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.EventID != firstEvent {
		t.Fatalf("restore reported intervening restore event: first=%s result=%s", firstEvent, out.String())
	}
	latest, _ := repo.History(ctx, profilerepo.HistorySelector{Name: "alpha"}, 1)
	if len(latest.Events) != 1 || latest.Events[0].EventID == firstEvent {
		t.Fatalf("expected a distinct intervening restore: latest=%+v", latest)
	}
}

func TestReviewDerivedRestoreRejectsSourceNameReuseInsideApply(t *testing.T) {
	home := t.TempDir()
	editor, err := devin.NewProfileEditor(home)
	if err != nil {
		t.Fatal(err)
	}
	repo := profilerepo.New(filepath.Join(home, ".acs"))
	ctx := context.Background()
	alpha := []byte(`{"version":3,"name":"alpha","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"devin":{"version":1}}}`)
	beta := bytes.Replace(alpha, []byte(`"alpha"`), []byte(`"beta"`), 1)
	delta := bytes.Replace(beta, []byte(`"beta"`), []byte(`"delta"`), 1)
	s, _ := repo.Read(ctx, "alpha")
	if _, err = repo.Apply(ctx, profilerepo.CreateRequest{Name: "alpha", Expected: s.Revision, Bytes: alpha}); err != nil {
		t.Fatal(err)
	}
	original, _ := repo.History(ctx, profilerepo.HistorySelector{Name: "alpha"}, 100)
	s, _ = repo.Read(ctx, "alpha")
	absent, _ := repo.Read(ctx, "beta")
	if _, err = repo.Apply(ctx, profilerepo.RenameRequest{Source: "alpha", Destination: "beta", ExpectedSource: s.Revision, ExpectedDestination: absent.Revision, Bytes: beta}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	app := App{Repository: repo, Categories: editor.Categories(), Output: &out, ErrorOutput: &bytes.Buffer{}}
	selected := original.Events[0].EventID
	if code := app.profileRestore(ctx, repo, profilerepo.HistorySelector{Lineage: original.LineageID}, historyInvocation{action: "restore", lineage: original.LineageID, revision: selected, as: "gamma", dryRun: true, json: true}); code != 0 {
		t.Fatalf("preview=%d %s", code, out.String())
	}
	var preview restorePreview
	if err := json.Unmarshal(out.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	mutated := false
	racing := historyRaceRepository{Repository: repo, before: func(request profilerepo.Request) {
		h, ok := request.(profilerepo.HistoryRequest)
		if !ok || h.Operation != "restore" || mutated {
			return
		}
		mutated = true
		s, _ := repo.Read(ctx, "beta")
		absent, _ := repo.Read(ctx, "delta")
		if _, err = repo.Apply(ctx, profilerepo.RenameRequest{Source: "beta", Destination: "delta", ExpectedSource: s.Revision, ExpectedDestination: absent.Revision, Bytes: delta}); err != nil {
			t.Fatalf("rename selected source: %v", err)
		}
		absent, _ = repo.Read(ctx, "beta")
		if _, err = repo.Apply(ctx, profilerepo.CreateRequest{Name: "beta", Expected: absent.Revision, Bytes: beta}); err != nil {
			t.Fatalf("reuse source name: %v", err)
		}
	}}
	out.Reset()
	code := app.profileRestore(ctx, racing, profilerepo.HistorySelector{Lineage: original.LineageID}, historyInvocation{action: "restore", lineage: original.LineageID, revision: selected, as: "gamma", expect: preview.Digest, confirm: "gamma", json: true})
	if !mutated {
		t.Fatal("race hook was not reached")
	}
	if code == 0 {
		t.Fatalf("derived restore accepted source-name reuse inside Apply: %s", out.String())
	}
	gamma, readErr := repo.Read(ctx, "gamma")
	if readErr != nil || gamma.Exists {
		t.Fatalf("destination changed after rejected source reuse: %+v err=%v", gamma, readErr)
	}
}
