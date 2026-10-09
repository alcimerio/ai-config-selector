package cli_test

import (
	"bytes"
	"context"
	"io"
	"testing"

	codexadapter "github.com/alcimerio/ai-config-selector/internal/adapter/codex"
	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

type unifiedBuilder struct {
	options   builder.CreationOptions
	called    bool
	cancelled bool
}

func (b *unifiedBuilder) BuildUnifiedProfile(ctx context.Context, name string, draft category.Draft, save builder.CreationSaveFunc, in io.Reader, out io.Writer) (builder.Outcome, error) {
	b.called = true
	if b.cancelled {
		return builder.Outcome{Cancelled: true}, nil
	}
	path, err := save(ctx, draft, b.options)
	return builder.Outcome{Create: err == nil, Path: path, Draft: draft}, err
}
func TestUnifiedCreateStoresExplicitOverlayCombinationsWithoutCredentials(t *testing.T) {
	for _, options := range []builder.CreationOptions{{}, {Devin: true}, {Codex: true}, {Devin: true, Codex: true}} {
		t.Run(string(rune('a'+boolInt(options.Devin)+2*boolInt(options.Codex))), func(t *testing.T) {
			editor, err := devin.NewProfileEditor(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			store := profile.NewStore(t.TempDir(), editor.Categories())
			build := &unifiedBuilder{options: options}
			var output, errors bytes.Buffer
			app := cli.App{Categories: editor.Categories(), Profiles: store, UnifiedBuilder: build, Input: &bytes.Buffer{}, Output: &output, ErrorOutput: &errors, Interactive: func(io.Reader, io.Writer) bool { return true }}
			args := []string{"profile", "create", "--name", "review"}
			if code := app.Run(context.Background(), args); code != 0 {
				t.Fatalf("code %d: %s", code, &errors)
			}
			saved, err := store.Load("review")
			if err != nil {
				t.Fatal(err)
			}
			if saved.Version != profile.CurrentVersion || len(saved.Overlays) != boolInt(options.Devin)+boolInt(options.Codex) {
				t.Fatalf("Profile %+v", saved)
			}
			for target, overlay := range saved.Overlays {
				if overlay.AuthRef != "" || (target == "devin" && !options.Devin) || (target == "codex" && !options.Codex) {
					t.Fatalf("overlay %s: %+v", target, overlay)
				}
			}
			if !bytes.Contains(saved.Common["workspace"].Selection, []byte("read-only")) {
				t.Fatal("default workspace expanded")
			}
			if _, err := editor.Categories().ResolveSyntaxFor(context.Background(), saved, ""); err != nil {
				t.Fatalf("common conformance: %v", err)
			}
			if options.Devin {
				if _, err := editor.Categories().ResolveSyntaxFor(context.Background(), saved, "devin"); err != nil {
					t.Fatal(err)
				}
			}
			if options.Codex {
				target, err := codexadapter.New(codexadapter.Config{BinaryPath: "not-installed", ExistingHomeDir: t.TempDir()})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := target.Categories().ResolveSyntaxFor(context.Background(), saved, "codex"); err != nil {
					t.Fatal(err)
				}
			}
			build.called = false
			if code := app.Run(context.Background(), args); code != 1 || build.called {
				t.Fatal("occupied destination opened builder")
			}
		})
	}
}
func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func TestUnifiedCreationCancellationAndTerminalRequirementPublishNothing(t *testing.T) {
	editor, err := devin.NewProfileEditor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := profile.NewStore(t.TempDir(), editor.Categories())
	build := &unifiedBuilder{cancelled: true}
	var output, errors bytes.Buffer
	app := cli.App{Categories: editor.Categories(), Profiles: store, UnifiedBuilder: build, Input: &bytes.Buffer{}, Output: &output, ErrorOutput: &errors, Interactive: func(io.Reader, io.Writer) bool { return true }}
	args := []string{"profile", "create", "--name", "cancelled"}
	if code := app.Run(context.Background(), args); code != 130 {
		t.Fatalf("cancel code %d: %s", code, &errors)
	}
	if _, err := store.Load("cancelled"); err == nil {
		t.Fatal("cancelled Profile exists")
	}
	build.called = false
	app.Interactive = func(io.Reader, io.Writer) bool { return false }
	if code := app.Run(context.Background(), args); code != 1 || build.called {
		t.Fatal("nonterminal opened builder")
	}
}
