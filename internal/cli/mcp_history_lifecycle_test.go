package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
)

func TestMCPChangedHistoryRestorePreservesCurrentBindingsAndRejectsStalePreview(t *testing.T) {
	app, repo, home := historyApp(t)
	ctx := context.Background()
	document := func(binding, filter string, reverse bool) []byte {
		t.Helper()
		args := []map[string]string{{"kind": "environment", "ref": "flag"}, {"kind": "path", "ref": "input"}}
		if reverse {
			args[0], args[1] = args[1], args[0]
		}
		server := map[string]any{"id": "fixture", "transport": "stdio", "executableRef": "exe", "arguments": args, "inputRefs": []string{"input"}, "environmentRefs": []string{"flag", "token"}, "disabledTools": []string{filter}}
		capability := func(selection any) map[string]any { return map[string]any{"version": 1, "selection": selection} }
		entries := func(v ...any) map[string]any { return map[string]any{"entries": v} }
		doc := map[string]any{"version": 3, "name": "alpha", "common": map[string]any{
			"skills": capability([]any{}), "workspace": capability(map[string]any{"access": "read-only"}),
			"executables": capability(entries(map[string]any{"id": "exe", "reference": map[string]string{"kind": "local-absolute", "path": "/" + binding + "/tool"}})),
			"paths":       capability(entries(map[string]any{"id": "input", "access": "read-only", "type": "file", "reference": map[string]string{"kind": "local-absolute", "path": "/" + binding + "/input"}})),
			"environment": capability(entries(map[string]any{"id": "flag", "destination": "MCP_FLAG", "scope": "attached-process-tree", "source": map[string]string{"kind": "host-environment", "name": "HOST_FLAG"}, "classification": "non-secret", "required": true}, map[string]any{"id": "token", "destination": "MCP_TOKEN", "scope": "attached-process-tree", "source": map[string]string{"kind": "secret-reference", "provider": "host-environment", "reference": strings.ToUpper(binding) + "_TOKEN"}, "classification": "secret", "required": true})),
			"mcp":         capability(map[string]any{"servers": []any{server}}),
		}, "overlays": map[string]any{"devin": map[string]any{"version": 1}}}
		b, e := json.Marshal(doc)
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	old := document("historical", "old_blocked", false)
	current := document("current", "current_blocked", true)
	for _, data := range [][]byte{old, current} {
		if _, err := app.Categories.Decode(data); err != nil {
			t.Fatal("invalid fixture", err)
		}
	}
	applyHistory(t, repo, "alpha", old, current)
	history, e := repo.History(ctx, profilerepo.HistorySelector{Name: "alpha"}, 100)
	if e != nil || len(history.Events) != 2 {
		t.Fatal(e, history)
	}
	event := history.Events[1].EventID
	var out, errOut bytes.Buffer
	app.Output, app.ErrorOutput = &out, &errOut
	run := func(args []string, want int) []byte {
		t.Helper()
		out.Reset()
		errOut.Reset()
		_, code := app.RunProfileHistory(ctx, args, func() (string, error) { return home, nil })
		if code != want {
			t.Fatalf("code=%d output=%s stderr=%s", code, out.String(), errOut.String())
		}
		return append([]byte{}, out.Bytes()...)
	}
	historyOut := run([]string{"profile", "history", "alpha", "--json"}, 0)
	if !bytes.Contains(historyOut, []byte(event)) {
		t.Fatal("public history omitted old event")
	}
	previewArgs := []string{"profile", "restore", "alpha", "--revision", event, "--dry-run", "--json"}
	var preview restorePreviewResult
	if e = json.Unmarshal(run(previewArgs, 0), &preview); e != nil || preview.Digest == "" || preview.Bindings != "preserved_current" {
		t.Fatal("preview missing current bindings", e, preview)
	}
	applied := run([]string{"profile", "restore", "alpha", "--revision", event, "--expect", preview.Digest, "--confirm", "alpha", "--json"}, 0)
	restored, e := repo.Read(ctx, "alpha")
	if e != nil {
		t.Fatal(e)
	}
	decode := func(b []byte) map[string]json.RawMessage {
		t.Helper()
		var doc struct{ Common map[string]json.RawMessage }
		if e := json.Unmarshal(b, &doc); e != nil {
			t.Fatal(e)
		}
		return doc.Common
	}
	original := decode(old)
	actual := decode(restored.Bytes)
	latest := decode(current)
	selection := func(raw json.RawMessage) commonprofile.MCPSelection {
		t.Helper()
		var cap struct{ Selection json.RawMessage }
		if e := json.Unmarshal(raw, &cap); e != nil {
			t.Fatal(e)
		}
		v, e := commonprofile.DecodeMCPSelection(cap.Selection)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	if !reflect.DeepEqual(selection(actual["mcp"]), selection(original["mcp"])) {
		t.Fatal("successful restore lost old ordered arguments/filter/reference selection")
	}
	for _, id := range []string{"executables", "paths", "environment"} {
		var a, b any
		if json.Unmarshal(actual[id], &a) != nil || json.Unmarshal(latest[id], &b) != nil || !reflect.DeepEqual(a, b) {
			t.Fatalf("restore did not retain current %s binding", id)
		}
	}
	for _, b := range [][]byte{restored.Bytes, applied} {
		if bytes.Contains(b, []byte("/historical/")) || bytes.Contains(b, []byte("HISTORICAL_TOKEN")) {
			t.Fatal("historical local binding replayed")
		}
	}
	afterHistory, e := repo.History(ctx, profilerepo.HistorySelector{Name: "alpha"}, 100)
	if e != nil || len(afterHistory.Events) != 3 || afterHistory.Events[0].Operation != "restore" {
		t.Fatal("no actual restore event", e, afterHistory)
	}
	if e = json.Unmarshal(run(previewArgs, 0), &preview); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.Apply(ctx, profilerepo.HistoryRequest{Request: profilerepo.ReplaceRequest{Name: "alpha", Expected: restored.Revision, Bytes: document("newest", "newest_blocked", true)}, Operation: "edit"}); e != nil {
		t.Fatal(e)
	}
	before, e := repo.Read(ctx, "alpha")
	if e != nil {
		t.Fatal(e)
	}
	historyBefore, e := repo.History(ctx, profilerepo.HistorySelector{Name: "alpha"}, 100)
	if e != nil {
		t.Fatal(e)
	}
	result := run([]string{"profile", "restore", "alpha", "--revision", event, "--expect", preview.Digest, "--confirm", "alpha", "--json"}, 1)
	if !strings.Contains(string(result), `"code":"conflict"`) {
		t.Fatalf("wrong stale refusal: %s", result)
	}
	after, e := repo.Read(ctx, "alpha")
	if e != nil || after.Revision != before.Revision || !bytes.Equal(after.Bytes, before.Bytes) {
		t.Fatal("stale restore changed bytes/revision", e)
	}
	historyAfter, e := repo.History(ctx, profilerepo.HistorySelector{Name: "alpha"}, 100)
	if e != nil || !reflect.DeepEqual(historyBefore, historyAfter) {
		t.Fatal("stale restore wrote history", e)
	}
}
