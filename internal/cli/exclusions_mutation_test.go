package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"io"
	"strings"
	"testing"
)

func TestLegacyMutationRefusesNonemptyExclusionsWithoutExplicitMigration(t *testing.T) {
	app, repository, _, _, editor := mutationFixtureWithEditor(t, legacyMutationDocument)
	before, err := repository.Read(context.Background(), "old")
	if err != nil {
		t.Fatal(err)
	}
	app.MutationBuilder = mutationEditorFunc(func(ctx context.Context, name string, draft category.Draft, options builder.MutationOptions, _ io.Reader, _ io.Writer) (builder.Outcome, error) {
		selection := commonprofile.ExclusionSelection{Entries: []commonprofile.ExclusionEntry{{ID: "data", Type: "directory", Reference: commonprofile.ExclusionReference{Kind: string(launch.PathReferenceWorkspaceRelative), Path: "data"}}}}
		if err := editor.SetExclusionSelection(&draft, selection); err != nil {
			t.Fatal(err)
		}
		if _, err := options.Prepare(draft); err == nil || !strings.Contains(err.Error(), "requires explicit Profile migration") {
			t.Fatalf("legacy mutation did not refuse nonempty paths: %v", err)
		}
		return builder.Outcome{Cancelled: true}, nil
	})
	if code := app.Run(context.Background(), []string{"profile", "edit", "old"}); code != 130 {
		t.Fatalf("cancelled mutation exit = %d", code)
	}
	after, err := repository.Read(context.Background(), "old")
	if err != nil || !bytes.Equal(after.Bytes, before.Bytes) || after.Revision != before.Revision {
		t.Fatalf("legacy bytes changed: %v", err)
	}
}

func TestVersionThreeMutationsPreserveExclusionIntent(t *testing.T) {
	for _, operation := range []string{"edit", "clone", "rename"} {
		t.Run(operation, func(t *testing.T) {
			raw := []byte(`{"version":3,"name":"old","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"exclusions":{"version":1,"selection":{"entries":[{"id":"local","type":"file","reference":{"kind":"local-absolute","path":"/owner/private"}},{"id":"repo","type":"directory","reference":{"kind":"workspace-relative","path":".agents/skills"}}]}}},"overlays":{"devin":{"version":1}}}`)
			app, repository, _, output := mutationFixture(t, raw)
			app.MutationBuilder = mutationEditorFunc(func(ctx context.Context, _ string, draft category.Draft, options builder.MutationOptions, _ io.Reader, _ io.Writer) (builder.Outcome, error) {
				prepared, err := options.Prepare(draft)
				if err != nil {
					return builder.Outcome{}, err
				}
				path, err := prepared.Save(ctx, draft)
				return builder.Outcome{Create: err == nil, Draft: draft, Path: path}, err
			})
			args := []string{"profile", operation, "old"}
			name := "old"
			if operation != "edit" {
				args = append(args, "--name", "new")
				name = "new"
			}
			if code := app.Run(context.Background(), args); code != 0 {
				t.Fatalf("mutation=%d %s", code, output)
			}
			stored, err := repository.Read(context.Background(), name)
			if err != nil {
				t.Fatal(err)
			}
			var before, after struct {
				Common map[string]struct{ Selection json.RawMessage }
			}
			if err := json.Unmarshal(raw, &before); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(stored.Bytes, &after); err != nil {
				t.Fatal(err)
			}
			want, err := commonprofile.DecodeExclusionSelection(before.Common["exclusions"].Selection)
			if err != nil {
				t.Fatal(err)
			}
			got, err := commonprofile.DecodeExclusionSelection(after.Common["exclusions"].Selection)
			if err != nil {
				t.Fatal(err)
			}
			wantBytes, _ := commonprofile.EncodeExclusionSelection(want)
			gotBytes, _ := commonprofile.EncodeExclusionSelection(got)
			if !bytes.Equal(wantBytes, gotBytes) {
				t.Fatalf("exclusions changed: %s", gotBytes)
			}
		})
	}
}

func TestExplicitMigrationRetainsNewExclusionIntent(t *testing.T) {
	app, repository, _, output, editor := mutationFixtureWithEditor(t, legacyMutationDocument)
	app.MutationBuilder = mutationEditorFunc(func(ctx context.Context, _ string, draft category.Draft, options builder.MutationOptions, _ io.Reader, _ io.Writer) (builder.Outcome, error) {
		selection := commonprofile.ExclusionSelection{Entries: []commonprofile.ExclusionEntry{{ID: "hidden", Type: "directory", Reference: commonprofile.ExclusionReference{Kind: "workspace-relative", Path: ".agents/skills"}}}}
		if err := editor.SetExclusionSelection(&draft, selection); err != nil {
			t.Fatal(err)
		}
		prepared, err := options.Prepare(draft)
		if err != nil {
			return builder.Outcome{}, err
		}
		path, err := prepared.Save(ctx, draft)
		return builder.Outcome{Create: err == nil, Draft: draft, Path: path}, err
	})
	if code := app.Run(context.Background(), []string{"profile", "migrate", "old"}); code != 0 {
		t.Fatalf("migrate=%d %s", code, output)
	}
	stored, err := repository.Read(context.Background(), "old")
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := editor.Categories().DecodeNamed("old", stored.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	selected, err := commonprofile.DecodeExclusionSelection(candidate.Common["exclusions"].Selection)
	if err != nil || candidate.Version != 3 || len(selected.Entries) != 1 || selected.Entries[0].Reference.Path != ".agents/skills" {
		t.Fatalf("migrated=%+v %v", candidate, err)
	}
}
