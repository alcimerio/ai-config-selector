package exclusionintent

import (
	"reflect"
	"strings"
	"testing"
)

func workspaceEntry(id string, kind Type, path string) Entry {
	return Entry{ID: id, Type: kind, Reference: Reference{Kind: string(ReferenceWorkspaceRelative), Path: path}}
}

func localEntry(id string, kind Type, path string) Entry {
	return Entry{ID: id, Type: kind, Reference: Reference{Kind: string(ReferenceLocalAbsolute), Path: path}}
}

func TestAdvisoriesReportNestedEntries(t *testing.T) {
	selection := Selection{Entries: []Entry{
		workspaceEntry("parent", TypeDirectory, "a"),
		workspaceEntry("child", TypeFile, "a/b"),
		workspaceEntry("grandchild", TypeDirectory, "./a/b/c/"),
		workspaceEntry("sibling", TypeDirectory, "ab"),
		localEntry("secret", TypeDirectory, "/owner/private"),
		localEntry("secret-key", TypeFile, "/owner/private/key"),
	}}
	got := Advisories(selection)
	// "child" is a file, so it never covers "grandchild"; "ab" is not under "a".
	want := []Advisory{
		{Kind: AdvisoryNested, ID: "child", Covering: "parent"},
		{Kind: AdvisoryNested, ID: "grandchild", Covering: "parent"},
		{Kind: AdvisoryNested, ID: "secret-key", Covering: "secret"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("advisories = %#v, want %#v", got, want)
	}
	for _, advisory := range got {
		if strings.Contains(advisory.String(), "/owner") {
			t.Fatalf("advisory discloses a local path: %s", advisory)
		}
	}
}

func TestAdvisoriesReportCaseOnlyDuplicates(t *testing.T) {
	selection := Selection{Entries: []Entry{
		workspaceEntry("lower", TypeDirectory, "secrets"),
		workspaceEntry("upper", TypeDirectory, "Secrets"),
		workspaceEntry("nested-mixed", TypeFile, "SECRETS/token"),
		localEntry("home-env", TypeFile, "/owner/.ENV"),
		localEntry("home-env-lower", TypeFile, "/owner/.env"),
	}}
	got := Advisories(selection)
	want := []Advisory{
		{Kind: AdvisoryCaseDuplicate, ID: "home-env-lower", Covering: "home-env"},
		{Kind: AdvisoryNested, ID: "nested-mixed", Covering: "lower"},
		{Kind: AdvisoryCaseDuplicate, ID: "upper", Covering: "lower"},
		{Kind: AdvisoryNested, ID: "nested-mixed", Covering: "upper"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("advisories = %#v, want %#v", got, want)
	}
	if message := got[0].String(); !strings.Contains(message, "differ only by letter case") {
		t.Fatalf("message = %q", message)
	}
}

func TestAdvisoriesIgnoreUnrelatedAndCrossKindEntries(t *testing.T) {
	selection := Selection{Entries: []Entry{
		workspaceEntry("data", TypeDirectory, "data"),
		workspaceEntry("database", TypeFile, "database.sql"),
		localEntry("absolute-data", TypeDirectory, "/data"),
		localEntry("absolute-data-file", TypeFile, "/database"),
	}}
	if got := Advisories(selection); len(got) != 0 {
		t.Fatalf("unexpected advisories: %#v", got)
	}
	if got := Advisories(Selection{Entries: []Entry{workspaceEntry("BAD", TypeFile, "x")}}); got != nil {
		t.Fatalf("invalid selection produced advisories: %#v", got)
	}
}

// Redundant entries are warnings only: decoding and canonicalization must keep
// accepting Profiles that already contain them.
func TestRedundantEntriesRemainValidOnDecode(t *testing.T) {
	raw := []byte(`{"entries":[{"id":"a","type":"directory","reference":{"kind":"workspace-relative","path":"a"}},{"id":"b","type":"file","reference":{"kind":"workspace-relative","path":"a/b"}},{"id":"c","type":"directory","reference":{"kind":"workspace-relative","path":"A"}}]}`)
	selection, err := Decode(raw)
	if err != nil {
		t.Fatalf("redundant selection rejected: %v", err)
	}
	if len(selection.Entries) != 3 || len(Advisories(selection)) == 0 {
		t.Fatalf("selection=%#v advisories=%#v", selection, Advisories(selection))
	}
}
