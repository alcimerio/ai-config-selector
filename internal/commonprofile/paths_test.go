package commonprofile

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestPathSelectionStrictCanonicalContract(t *testing.T) {
	selection := PathSelection{Entries: []PathEntry{
		{ID: "z", Access: launch.PathAccessReadOnly, Type: launch.PathTypeDirectory, Reference: PathReference{Kind: string(launch.PathReferenceWorkspaceRelative), Path: "data/./cache"}},
		{ID: "a", Access: launch.PathAccessReadWrite, Type: launch.PathTypeFile, Reference: PathReference{Kind: string(launch.PathReferenceLocalAbsolute), Path: "/tmp/file"}},
	}}
	encoded, err := EncodePathSelection(selection)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"id":"a"`)) || bytes.Index(encoded, []byte(`"id":"a"`)) > bytes.Index(encoded, []byte(`"id":"z"`)) {
		t.Fatalf("not canonical: %s", encoded)
	}
	decoded, err := DecodePathSelection(encoded)
	if err != nil || decoded.Entries[1].Reference.Path != "data/cache" {
		t.Fatalf("decode = %#v, %v", decoded, err)
	}

	for name, raw := range map[string]string{
		"missing entries":       `{}`,
		"null entries":          `{"entries":null}`,
		"unknown":               `{"entries":[],"future":true}`,
		"trailing":              `{"entries":[]} {}`,
		"duplicate ID":          `{"entries":[{"id":"a","access":"read-only","type":"file","reference":{"kind":"workspace-relative","path":"one"}},{"id":"a","access":"read-only","type":"file","reference":{"kind":"workspace-relative","path":"two"}}]}`,
		"duplicate destination": `{"entries":[{"id":"a","access":"read-only","type":"file","reference":{"kind":"workspace-relative","path":"one"}},{"id":"b","access":"read-write","type":"file","reference":{"kind":"workspace-relative","path":"one"}}]}`,
		"traversal":             `{"entries":[{"id":"a","access":"read-only","type":"file","reference":{"kind":"workspace-relative","path":"../one"}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodePathSelection(json.RawMessage(raw)); err == nil {
				t.Fatal("accepted invalid selection")
			}
		})
	}
}

func TestEmptyPathSelectionEncodesAsArray(t *testing.T) {
	encoded, err := EncodePathSelection(PathSelection{Entries: []PathEntry{}})
	if err != nil || string(encoded) != `{"entries":[]}` {
		t.Fatalf("encoded = %s, %v", encoded, err)
	}
}

func pathAuthorityPlan(entries []launch.PathGrantIntent) authority.Plan {
	contribution := PathContribution{entries: append([]launch.PathGrantIntent(nil), entries...)}
	return authority.New([]authority.Contribution{{ID: PathsCapabilityID, Value: contribution}}, launch.WorkspaceAccessReadOnly, 3, "")
}

func TestPathSemanticDigestTracksPortableIntentAndExcludesPrivateBindings(t *testing.T) {
	baseEntry := launch.PathGrantIntent{
		ID: "documents", Access: launch.PathAccessReadOnly, Type: launch.PathTypeDirectory,
		ReferenceKind: launch.PathReferenceWorkspaceRelative, Path: "docs/reference",
	}
	base := pathAuthorityPlan([]launch.PathGrantIntent{baseEntry})
	for _, test := range []struct {
		name   string
		mutate func(*launch.PathGrantIntent)
	}{
		{name: "relative logical path", mutate: func(entry *launch.PathGrantIntent) { entry.Path = "docs/other" }},
		{name: "access", mutate: func(entry *launch.PathGrantIntent) { entry.Access = launch.PathAccessReadWrite }},
		{name: "type", mutate: func(entry *launch.PathGrantIntent) { entry.Type = launch.PathTypeFile }},
		{name: "reference kind", mutate: func(entry *launch.PathGrantIntent) {
			entry.ReferenceKind, entry.Path = launch.PathReferenceLocalAbsolute, "/Users/private/documents"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := baseEntry
			test.mutate(&changed)
			if pathAuthorityPlan([]launch.PathGrantIntent{changed}).AuthorityDigest() == base.AuthorityDigest() {
				t.Fatalf("%s mutation did not change common.paths semantic digest", test.name)
			}
		})
	}

	firstPrivate := baseEntry
	firstPrivate.ReferenceKind, firstPrivate.Path = launch.PathReferenceLocalAbsolute, "/Users/private-one/documents"
	secondPrivate := firstPrivate
	secondPrivate.Path = "/Volumes/private-two/documents"
	firstPlan, secondPlan := pathAuthorityPlan([]launch.PathGrantIntent{firstPrivate}), pathAuthorityPlan([]launch.PathGrantIntent{secondPrivate})
	if firstPlan.AuthorityDigest() != secondPlan.AuthorityDigest() {
		t.Fatal("private local-absolute binding changed common.paths semantic digest")
	}
	encoded, err := json.Marshal(firstPlan.Explanation())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), firstPrivate.Path) || strings.Contains(string(encoded), secondPrivate.Path) {
		t.Fatalf("common.paths explanation exposed a private binding: %s", encoded)
	}
}

func TestPathSemanticDigestIsOrderIndependentAndAuthorityValuesAreImmutable(t *testing.T) {
	entries := []launch.PathGrantIntent{
		{ID: "zeta", Access: launch.PathAccessReadWrite, Type: launch.PathTypeFile, ReferenceKind: launch.PathReferenceLocalAbsolute, Path: "/Users/private/zeta"},
		{ID: "alpha", Access: launch.PathAccessReadOnly, Type: launch.PathTypeDirectory, ReferenceKind: launch.PathReferenceWorkspaceRelative, Path: "docs/alpha"},
	}
	contribution := PathContribution{entries: append([]launch.PathGrantIntent(nil), entries...)}
	plan := authority.New([]authority.Contribution{{ID: PathsCapabilityID, Value: contribution}}, launch.WorkspaceAccessReadOnly, 3, "")
	reversed := pathAuthorityPlan([]launch.PathGrantIntent{entries[1], entries[0]})
	if plan.AuthorityDigest() != reversed.AuthorityDigest() || !reflect.DeepEqual(plan.Explanation(), reversed.Explanation()) {
		t.Fatal("common.paths entry ordering changed canonical semantic authority")
	}

	digest := plan.AuthorityDigest()
	entries[0].ID, entries[0].Path = "mutated-input", "/Users/private/mutated-input"
	returnedIntents := contribution.PathGrantIntents()
	returnedIntents[0].ID, returnedIntents[0].Path = "mutated-return", "/Users/private/mutated-return"
	returnedExplanation := plan.Explanation()
	alpha := findSemanticFact(returnedExplanation.Requested, "common.paths.alpha")
	if alpha == nil || len(alpha.Value.Names) != 1 {
		t.Fatalf("common.paths semantic fact missing: %#v", returnedExplanation.Requested)
	}
	alpha.ID = "mutated-fact"
	alpha.Value.Names[0] = "mutated-reference"
	alpha.Value.LogicalReference = "mutated/path"
	fresh := plan.Explanation()
	freshAlpha := findSemanticFact(fresh.Requested, "common.paths.alpha")
	if freshAlpha == nil || !reflect.DeepEqual(freshAlpha.Value.Names, []string{string(launch.PathReferenceWorkspaceRelative)}) || freshAlpha.Value.LogicalReference != "docs/alpha" {
		t.Fatalf("returned values mutated common.paths authority: %#v", fresh.Requested)
	}
	if plan.AuthorityDigest() != digest {
		t.Fatal("caller mutation changed immutable common.paths semantic digest")
	}
}
