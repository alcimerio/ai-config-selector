package commonprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/instructions"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func TestExclusionSelectionStrictCanonicalContract(t *testing.T) {
	selection := ExclusionSelection{Entries: []ExclusionEntry{
		{ID: "z", Type: "directory", Reference: ExclusionReference{Kind: string(launch.PathReferenceWorkspaceRelative), Path: "data/./cache"}},
		{ID: "a", Type: "file", Reference: ExclusionReference{Kind: string(launch.PathReferenceLocalAbsolute), Path: "/tmp/file"}},
	}}
	encoded, err := EncodeExclusionSelection(selection)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"id":"a"`)) || bytes.Index(encoded, []byte(`"id":"a"`)) > bytes.Index(encoded, []byte(`"id":"z"`)) {
		t.Fatalf("not canonical: %s", encoded)
	}
	decoded, err := DecodeExclusionSelection(encoded)
	if err != nil || decoded.Entries[1].Reference.Path != "data/cache" {
		t.Fatalf("decode = %#v, %v", decoded, err)
	}

	for name, raw := range map[string]string{
		"missing entries":       `{}`,
		"null entries":          `{"entries":null}`,
		"unknown":               `{"entries":[],"future":true}`,
		"trailing":              `{"entries":[]} {}`,
		"duplicate ID":          `{"entries":[{"id":"a","type":"file","reference":{"kind":"workspace-relative","path":"one"}},{"id":"a","type":"file","reference":{"kind":"workspace-relative","path":"two"}}]}`,
		"duplicate destination": `{"entries":[{"id":"a","type":"file","reference":{"kind":"workspace-relative","path":"one"}},{"id":"b","type":"file","reference":{"kind":"workspace-relative","path":"one"}}]}`,
		"traversal":             `{"entries":[{"id":"a","type":"file","reference":{"kind":"workspace-relative","path":"../one"}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeExclusionSelection(json.RawMessage(raw)); err == nil {
				t.Fatal("accepted invalid selection")
			}
		})
	}
}

func TestEmptyExclusionSelectionEncodesAsArray(t *testing.T) {
	encoded, err := EncodeExclusionSelection(ExclusionSelection{Entries: []ExclusionEntry{}})
	if err != nil || string(encoded) != `{"entries":[]}` {
		t.Fatalf("encoded = %s, %v", encoded, err)
	}
}

func exclusionAuthorityPlan(entries []launch.PathExclusionIntent) authority.Plan {
	contribution := ExclusionContribution{entries: append([]launch.PathExclusionIntent(nil), entries...)}
	return authority.New([]authority.Contribution{{ID: ExclusionsCapabilityID, Value: contribution}}, launch.WorkspaceAccessReadOnly, 3, "")
}

func TestExclusionSemanticDigestTracksPortableIntentAndExcludesPrivateBindings(t *testing.T) {
	baseEntry := launch.PathExclusionIntent{
		ID: "documents", Type: launch.PathTypeDirectory,
		ReferenceKind: launch.PathReferenceWorkspaceRelative, Path: "docs/reference",
	}
	base := exclusionAuthorityPlan([]launch.PathExclusionIntent{baseEntry})
	for _, test := range []struct {
		name   string
		mutate func(*launch.PathExclusionIntent)
	}{
		{name: "relative logical path", mutate: func(entry *launch.PathExclusionIntent) { entry.Path = "docs/other" }},
		{name: "type", mutate: func(entry *launch.PathExclusionIntent) { entry.Type = launch.PathTypeFile }},
		{name: "reference kind", mutate: func(entry *launch.PathExclusionIntent) {
			entry.ReferenceKind, entry.Path = launch.PathReferenceLocalAbsolute, "/Users/private/documents"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := baseEntry
			test.mutate(&changed)
			if exclusionAuthorityPlan([]launch.PathExclusionIntent{changed}).AuthorityDigest() == base.AuthorityDigest() {
				t.Fatalf("%s mutation did not change common.exclusions semantic digest", test.name)
			}
		})
	}

	firstPrivate := baseEntry
	firstPrivate.ReferenceKind, firstPrivate.Path = launch.PathReferenceLocalAbsolute, "/Users/private-one/documents"
	secondPrivate := firstPrivate
	secondPrivate.Path = "/Volumes/private-two/documents"
	firstPlan, secondPlan := exclusionAuthorityPlan([]launch.PathExclusionIntent{firstPrivate}), exclusionAuthorityPlan([]launch.PathExclusionIntent{secondPrivate})
	if firstPlan.AuthorityDigest() != secondPlan.AuthorityDigest() {
		t.Fatal("private local-absolute binding changed common.exclusions semantic digest")
	}
	encoded, err := json.Marshal(firstPlan.Explanation())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), firstPrivate.Path) || strings.Contains(string(encoded), secondPrivate.Path) {
		t.Fatalf("common.exclusions explanation exposed a private binding: %s", encoded)
	}
}

func TestExclusionSemanticDigestIsOrderIndependentAndAuthorityValuesAreImmutable(t *testing.T) {
	entries := []launch.PathExclusionIntent{
		{ID: "zeta", Type: launch.PathTypeFile, ReferenceKind: launch.PathReferenceLocalAbsolute, Path: "/Users/private/zeta"},
		{ID: "alpha", Type: launch.PathTypeDirectory, ReferenceKind: launch.PathReferenceWorkspaceRelative, Path: "docs/alpha"},
	}
	contribution := ExclusionContribution{entries: append([]launch.PathExclusionIntent(nil), entries...)}
	plan := authority.New([]authority.Contribution{{ID: ExclusionsCapabilityID, Value: contribution}}, launch.WorkspaceAccessReadOnly, 3, "")
	reversed := exclusionAuthorityPlan([]launch.PathExclusionIntent{entries[1], entries[0]})
	if plan.AuthorityDigest() != reversed.AuthorityDigest() || !reflect.DeepEqual(plan.Explanation(), reversed.Explanation()) {
		t.Fatal("common.exclusions entry ordering changed canonical semantic authority")
	}

	digest := plan.AuthorityDigest()
	entries[0].ID, entries[0].Path = "mutated-input", "/Users/private/mutated-input"
	returnedIntents := contribution.PathExclusionIntents()
	returnedIntents[0].ID, returnedIntents[0].Path = "mutated-return", "/Users/private/mutated-return"
	returnedExplanation := plan.Explanation()
	alpha := findSemanticFact(returnedExplanation.Requested, "common.exclusions.alpha")
	if alpha == nil || len(alpha.Value.Names) != 1 {
		t.Fatalf("common.exclusions semantic fact missing: %#v", returnedExplanation.Requested)
	}
	alpha.ID = "mutated-fact"
	alpha.Value.Names[0] = "mutated-reference"
	alpha.Value.LogicalReference = "mutated/path"
	fresh := plan.Explanation()
	freshAlpha := findSemanticFact(fresh.Requested, "common.exclusions.alpha")
	if freshAlpha == nil || !reflect.DeepEqual(freshAlpha.Value.Names, []string{string(launch.PathReferenceWorkspaceRelative)}) || freshAlpha.Value.LogicalReference != "docs/alpha" {
		t.Fatalf("returned values mutated common.exclusions authority: %#v", fresh.Requested)
	}
	if plan.AuthorityDigest() != digest {
		t.Fatal("caller mutation changed immutable common.exclusions semantic digest")
	}
}

func TestExclusionPlanShowsIntentWithoutPrivateBindings(t *testing.T) {
	plan := exclusionAuthorityPlan([]launch.PathExclusionIntent{{ID: "repo", Type: launch.PathTypeDirectory, ReferenceKind: launch.PathReferenceWorkspaceRelative, Path: ".agents/skills"}, {ID: "local", Type: launch.PathTypeFile, ReferenceKind: launch.PathReferenceLocalAbsolute, Path: "/owner/private/file"}})
	rendered, err := plan.Plan(context.Background(), "unused")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(rendered)
	if err != nil || !bytes.Contains(raw, []byte(".agents/skills")) || !bytes.Contains(raw, []byte("denied")) || bytes.Contains(raw, []byte("/owner/private")) {
		t.Fatalf("plan=%s %v", raw, err)
	}
}

func TestExclusionsRejectSelectedCommonMaterialOrigins(t *testing.T) {
	workspace := t.TempDir()
	instructionPath := filepath.Join(workspace, ".acs", "instructions", "rule.md")
	if err := os.MkdirAll(filepath.Dir(instructionPath), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(instructionPath, []byte("synthetic rule"), 0600); err != nil {
		t.Fatal(err)
	}
	captured, err := instructions.Resolve(workspace, []instructions.Reference{{Source: instructions.SourceID, RelativePath: "rule.md"}})
	if err != nil {
		t.Fatal(err)
	}
	bundle := filepath.Join(workspace, "bundle")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "SKILL.md"), []byte("synthetic skill"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, path string
		kind       launch.PathType
		material   launch.Contribution
	}{
		{"instruction", ".acs/instructions/rule.md", launch.PathTypeFile, InstructionsContribution{selected: captured, projection: reviewInstructionProjection{"codex"}}},
		{"skill", "bundle", launch.PathTypeDirectory, SkillsContribution{selected: []skills.SkillBundle{{Reference: skills.SkillReference{Source: "shared-agents", RelativePath: "bundle"}, BundlePath: bundle}}, projection: &testProjection{}}},
		{"skill-descendant", "bundle/SKILL.md", launch.PathTypeFile, SkillsContribution{selected: []skills.SkillBundle{{Reference: skills.SkillReference{Source: "shared-agents", RelativePath: "bundle"}, BundlePath: bundle}}, projection: &testProjection{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			denial := ExclusionContribution{entries: []launch.PathExclusionIntent{{ID: "hidden", Type: tc.kind, ReferenceKind: launch.PathReferenceWorkspaceRelative, Path: tc.path}}}
			plan := authority.New([]authority.Contribution{{ID: "exclusions", Value: denial}, {ID: "material", Value: tc.material}}, launch.WorkspaceAccessReadOnly, 3, "codex")
			_, err := plan.ResolveFilesystemExclusions(workspace, filepath.Join(t.TempDir(), "sessions"))
			var classified *launch.SandboxError
			if !errors.As(err, &classified) || !strings.Contains(err.Error(), `excluded path "hidden"`) || strings.Contains(err.Error(), workspace) {
				t.Fatalf("source conflict=%v", err)
			}
		})
	}
}
