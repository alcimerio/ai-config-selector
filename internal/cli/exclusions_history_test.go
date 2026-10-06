package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
	"strings"
	"testing"
)

func TestProfileRestorePreservesCurrentExclusionBindingAndWorkspaceIntent(t *testing.T) {
	app, repository, home := historyApp(t)
	historical := []byte(`{"version":3,"name":"alpha","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"exclusions":{"version":1,"selection":{"entries":[{"id":"local","type":"file","reference":{"kind":"local-absolute","path":"/historical/private"}},{"id":"relative","type":"file","reference":{"kind":"workspace-relative","path":"configs/current"}}]} }},"overlays":{"devin":{"version":1}}}`)
	current := []byte(`{"version":3,"name":"alpha","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"exclusions":{"version":1,"selection":{"entries":[{"id":"local","type":"file","reference":{"kind":"local-absolute","path":"/current/safe"}},{"id":"relative","type":"file","reference":{"kind":"workspace-relative","path":"configs/changed"}}]} }},"overlays":{"devin":{"version":1}}}`)
	applyHistory(t, repository, "alpha", historical, current)
	history, err := repository.History(context.Background(), profilerepo.HistorySelector{Name: "alpha"}, 100)
	if err != nil || len(history.Events) < 2 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	var out, errOut bytes.Buffer
	app.Output, app.ErrorOutput = &out, &errOut
	args := []string{"profile", "restore", "alpha", "--revision", history.Events[1].EventID, "--dry-run", "--json"}
	if _, code := app.RunProfileHistory(context.Background(), args, func() (string, error) { return home, nil }); code != 0 {
		t.Fatalf("preview code=%d err=%s", code, errOut.String())
	}
	var preview restorePreviewResult
	if err := json.Unmarshal(out.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if preview.Bindings != "preserved_current" {
		t.Fatalf("bindings=%q", preview.Bindings)
	}
	out.Reset()
	applyArgs := append([]string{"profile", "restore", "alpha", "--revision", history.Events[1].EventID, "--expect", preview.Digest, "--confirm", "alpha", "--json"}, []string{}...)
	if _, code := app.RunProfileHistory(context.Background(), applyArgs, func() (string, error) { return home, nil }); code != 0 {
		t.Fatalf("apply code=%d err=%s", code, errOut.String())
	}
	stored, err := repository.Read(context.Background(), "alpha")
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := app.Categories.DecodeNamed("alpha", stored.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	paths, err := commonprofile.DecodeExclusionSelection(decoded.Common[commonprofile.ExclusionsCapabilityID].Selection)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths.Entries) != 2 {
		t.Fatalf("restored entries=%d", len(paths.Entries))
	}
	seen := map[string]bool{}
	for _, entry := range paths.Entries {
		seen[entry.ID] = true
		switch entry.ID {
		case "local":
			if entry.Reference.Path != "/current/safe" || entry.Reference.Path == "/historical/private" {
				t.Fatalf("local path=%q", entry.Reference.Path)
			}
		case "relative":
			if entry.Reference.Path != "configs/current" {
				t.Fatalf("relative path=%q", entry.Reference.Path)
			}
		}
	}
	if !seen["local"] || !seen["relative"] {
		t.Fatalf("restored IDs=%v", seen)
	}
}

func TestProfileRestoreRequiresBindingsForMissingOrIncompatibleCurrentExclusion(t *testing.T) {
	cases := []struct {
		name, currentEntry string
	}{
		{"missing", ""},
		{"incompatible-type", `{"id":"local","type":"directory","reference":{"kind":"local-absolute","path":"/current/safe"}}`},
		{"incompatible-reference", `{"id":"local","type":"file","reference":{"kind":"workspace-relative","path":"current/safe"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			app, repository, home := historyApp(t)
			historical := []byte(`{"version":3,"name":"alpha","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"exclusions":{"version":1,"selection":{"entries":[{"id":"local","type":"file","reference":{"kind":"local-absolute","path":"/historical/private"}}]}}},"overlays":{"devin":{"version":1}}}`)
			current := []byte(`{"version":3,"name":"alpha","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"exclusions":{"version":1,"selection":{"entries":[` + tc.currentEntry + `]}}},"overlays":{"devin":{"version":1}}}`)
			if tc.currentEntry == "" {
				current = []byte(`{"version":3,"name":"alpha","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"devin":{"version":1}}}`)
			}
			applyHistory(t, repository, "alpha", historical, current)
			snapshot, err := repository.Read(context.Background(), "alpha")
			if err != nil {
				t.Fatal(err)
			}
			history, _ := repository.History(context.Background(), profilerepo.HistorySelector{Name: "alpha"}, 100)
			var out, errOut bytes.Buffer
			app.Output, app.ErrorOutput = &out, &errOut
			args := []string{"profile", "restore", "alpha", "--revision", history.Events[1].EventID, "--dry-run", "--json"}
			if _, code := app.RunProfileHistory(context.Background(), args, func() (string, error) { return home, nil }); code != 1 || !strings.Contains(out.String(), `"code":"unresolved_binding"`) {
				t.Fatalf("case=%s code=%d out=%s", tc.name, code, out.String())
			}
			after, err := repository.Read(context.Background(), "alpha")
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Revision != after.Revision || !bytes.Equal(snapshot.Bytes, after.Bytes) {
				t.Fatalf("case=%s mutated current profile", tc.name)
			}
		})
	}
}

func TestProfileRestoreRejectsStalePreviewAfterExclusionBindingChange(t *testing.T) {
	app, repository, home := historyApp(t)
	historical := []byte(`{"version":3,"name":"alpha","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"exclusions":{"version":1,"selection":{"entries":[{"id":"local","type":"file","reference":{"kind":"local-absolute","path":"/historical/private"}}]}}},"overlays":{"devin":{"version":1}}}`)
	current := []byte(`{"version":3,"name":"alpha","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"exclusions":{"version":1,"selection":{"entries":[{"id":"local","type":"file","reference":{"kind":"local-absolute","path":"/current/safe"}}]}}},"overlays":{"devin":{"version":1}}}`)
	applyHistory(t, repository, "alpha", historical, current)
	history, err := repository.History(context.Background(), profilerepo.HistorySelector{Name: "alpha"}, 100)
	if err != nil || len(history.Events) < 2 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	var out, errOut bytes.Buffer
	app.Output, app.ErrorOutput = &out, &errOut
	args := []string{"profile", "restore", "alpha", "--revision", history.Events[1].EventID, "--dry-run", "--json"}
	if _, code := app.RunProfileHistory(context.Background(), args, func() (string, error) { return home, nil }); code != 0 {
		t.Fatalf("preview code=%d", code)
	}
	var preview restorePreviewResult
	if err := json.Unmarshal(out.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	snapshot, err := repository.Read(context.Background(), "alpha")
	if err != nil {
		t.Fatal(err)
	}
	mutated := []byte(`{"version":3,"name":"alpha","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"exclusions":{"version":1,"selection":{"entries":[{"id":"local","type":"file","reference":{"kind":"local-absolute","path":"/current/changed"}}]}}},"overlays":{"devin":{"version":1}}}`)
	if _, err := repository.Apply(context.Background(), profilerepo.ReplaceRequest{Name: "alpha", Expected: snapshot.Revision, Bytes: mutated}); err != nil {
		t.Fatal(err)
	}
	post, _ := repository.Read(context.Background(), "alpha")
	out.Reset()
	applyArgs := []string{"profile", "restore", "alpha", "--revision", history.Events[1].EventID, "--expect", preview.Digest, "--confirm", "alpha", "--json"}
	if _, code := app.RunProfileHistory(context.Background(), applyArgs, func() (string, error) { return home, nil }); code != 1 || !strings.Contains(out.String(), `"code":"conflict"`) {
		t.Fatalf("stale code=%d out=%s", code, out.String())
	}
	after, _ := repository.Read(context.Background(), "alpha")
	if after.Revision != post.Revision || !bytes.Equal(after.Bytes, post.Bytes) {
		t.Fatal("stale refusal mutated current profile")
	}
}
