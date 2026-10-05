package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"

	codexadapter "github.com/alcimerio/ai-config-selector/internal/adapter/codex"
	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
)

// Deliberately violate io.Writer's short-write contract to verify that command
// completion does not treat an incomplete acknowledgment as success.
type completionWriter struct {
	short bool
	calls int
	allow int
}

func (w *completionWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls <= w.allow {
		return len(p), nil
	}
	if w.short {
		return len(p) / 2, nil
	}
	return 0, io.ErrClosedPipe
}

type completionStore struct {
	*profile.Store
	creates int
}

func (s *completionStore) CreateContext(ctx context.Context, value profile.Profile) (string, error) {
	s.creates++
	return s.Store.CreateContext(ctx, value)
}

func (s *completionStore) Create(value profile.Profile) (string, error) {
	return s.CreateContext(context.Background(), value)
}

type completionDraftEditor struct{}

func (completionDraftEditor) EditProfileDraft(_ context.Context, draft category.Draft, _ io.Reader, _ io.Writer) (category.Draft, error) {
	return draft, nil
}

func TestProfileCreationAcknowledgmentFailurePreservesCommit(t *testing.T) {
	for _, mode := range []string{"declarative", "unified", "devin", "codex", "draft-editor"} {
		for _, short := range []bool{false, true} {
			t.Run(mode+map[bool]string{false: "/error", true: "/short"}[short], func(t *testing.T) {
				home := t.TempDir()
				editor, err := devin.NewProfileEditor(home)
				if err != nil {
					t.Fatal(err)
				}
				registry := editor.Categories()
				if mode == "codex" {
					target, err := codexadapter.New(codexadapter.Config{BinaryPath: "/missing/codex", ExistingHomeDir: home})
					if err != nil {
						t.Fatal(err)
					}
					registry = target.Categories()
				}
				root := filepath.Join(home, ".acs")
				store := &completionStore{Store: profile.NewStore(root, registry)}
				writer := &completionWriter{short: short}
				var stderr bytes.Buffer
				app := cli.App{Categories: registry, Profiles: store, Output: writer, ErrorOutput: &stderr, Input: strings.NewReader(""), Interactive: func(io.Reader, io.Writer) bool { return true }}
				args := []string{"profile", "create", "--name", "acknowledged"}
				switch mode {
				case "declarative":
					args = []string{"profile", "create", "--file", "ignored"}
					app.ReadProfileDocument = func(string) ([]byte, error) { return declarativeDocument("acknowledged"), nil }
				case "unified":
					app.UnifiedBuilder = &unifiedBuilder{}
				case "draft-editor":
					args = []string{"devin", "create-profile", "--name", "acknowledged"}
					app.DraftEditor = completionDraftEditor{}
					writer.allow = 1
				case "devin":
					args = []string{"devin", "create-profile", "--name", "acknowledged"}
					app.Builder = &staticBuilder{outcome: builder.Outcome{Create: true, Draft: registry.NewDraft()}}
				case "codex":
					args = []string{"codex", "create-profile", "--name", "acknowledged"}
					app.CodexCategories, app.CodexProfiles = registry, store
					app.CodexBuilder = &staticBuilder{outcome: builder.Outcome{Create: true, Draft: registry.NewDraft()}}
				}
				code := app.Run(context.Background(), args)
				if _, err := store.Load("acknowledged"); err != nil {
					t.Fatalf("lost commit: %v", err)
				}
				history, err := profilerepo.New(root).History(context.Background(), profilerepo.HistorySelector{Name: "acknowledged"}, 100)
				if err != nil || len(history.Events) != 1 || store.creates != 1 {
					t.Fatalf("replayed commit: calls=%d history=%+v err=%v", store.creates, history, err)
				}
				if code != 1 || !strings.Contains(stderr.String(), "committed") || !strings.Contains(stderr.String(), "reporting failed") || strings.Contains(stderr.String(), "acs profile recover") || strings.Contains(stderr.String(), "cancelled") {
					t.Fatalf("code=%d stderr=%s", code, stderr.String())
				}
				if writer.calls != writer.allow+1 {
					t.Fatalf("retried failed acknowledgment: %d writes", writer.calls)
				}
			})
		}
	}
}

func TestProfileRestoreAcknowledgmentFailurePreservesCommit(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		for _, short := range []bool{false, true} {
			t.Run(map[bool]string{false: "human", true: "json"}[jsonOutput]+map[bool]string{false: "/error", true: "/short"}[short], func(t *testing.T) {
				app, repository, home := historyApp(t)
				applyHistory(t, repository, "alpha", historyDocument("alpha", "old-auth"), historyDocument("alpha", "current-auth"))
				before, err := repository.History(context.Background(), profilerepo.HistorySelector{Name: "alpha"}, 100)
				if err != nil {
					t.Fatal(err)
				}
				var previewOut, stderr bytes.Buffer
				app.Output, app.ErrorOutput = &previewOut, &stderr
				selected := before.Events[1].EventID
				args := []string{"profile", "restore", "alpha", "--revision", selected, "--dry-run", "--json"}
				if _, code := app.RunProfileHistory(context.Background(), args, func() (string, error) { return home, nil }); code != 0 {
					t.Fatal(code, stderr.String())
				}
				var preview restorePreviewResult
				if err := json.Unmarshal(previewOut.Bytes(), &preview); err != nil {
					t.Fatal(err)
				}
				writer := &completionWriter{short: short}
				app.Output = writer
				args = []string{"profile", "restore", "alpha", "--revision", selected, "--expect", preview.Digest, "--confirm", "alpha"}
				if jsonOutput {
					args = append(args, "--json")
				}
				_, code := app.RunProfileHistory(context.Background(), args, func() (string, error) { return home, nil })
				after, err := repository.History(context.Background(), profilerepo.HistorySelector{Name: "alpha"}, 100)
				if err != nil || len(after.Events) != len(before.Events)+1 || after.Events[0].Operation != "restore" {
					t.Fatalf("lost or replayed restore: %+v %v", after, err)
				}
				if code != 1 || !strings.Contains(stderr.String(), "restore committed") || !strings.Contains(stderr.String(), "reporting failed") || strings.Contains(stderr.String(), "acs profile recover") {
					t.Fatalf("code=%d stderr=%s", code, stderr.String())
				}
				if writer.calls != writer.allow+1 {
					t.Fatalf("retried failed acknowledgment: %d", writer.calls)
				}
			})
		}
	}
}

func TestProfileImportAcknowledgmentFailurePreservesCommit(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "short"}[short], func(t *testing.T) {
			document, err := profileexchangeExportFixture(t)
			if err != nil {
				t.Fatal(err)
			}
			app, _, stderr := exchangeApp(t, filepath.Join(t.TempDir(), ".acs"))
			app.ReadProfileDocument = func(path string) ([]byte, error) {
				if path == "exchange" {
					return document, nil
				}
				return []byte(`{"bindingVersion":1,"sources":{"source-1":"shared-agents"},"authentications":{"authentication-1":"work"}}`), nil
			}
			writer := &completionWriter{short: short}
			app.Output = writer
			args := []string{"profile", "import", "--file", "exchange", "--as", "imported", "--bindings", "bindings"}
			code := app.Run(context.Background(), args)
			snapshot, err := app.Repository.Read(context.Background(), "imported")
			if err != nil || !snapshot.Exists {
				t.Fatalf("lost import: %+v %v", snapshot, err)
			}
			history, err := app.Repository.(*profilerepo.Repository).History(context.Background(), profilerepo.HistorySelector{Name: "imported"}, 100)
			if err != nil || len(history.Events) != 1 || history.Events[0].Operation != "import" {
				t.Fatalf("lost/replayed import: %+v %v", history, err)
			}
			if code != 1 || writer.calls != 1 || !strings.Contains(stderr.String(), "committed; reporting failed") || strings.Contains(stderr.String(), "acs profile recover") {
				t.Fatalf("code=%d writes=%d stderr=%s", code, writer.calls, stderr.String())
			}
		})
	}
}
