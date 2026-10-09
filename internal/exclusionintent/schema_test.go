package exclusionintent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExclusionsStrictCanonicalIntent(t *testing.T) {
	valid := `{"entries":[{"id":"repo-skills","type":"directory","reference":{"kind":"workspace-relative","path":".agents/skills"}}]}`
	got, err := Decode(json.RawMessage(valid))
	if err != nil || len(got.Entries) != 1 {
		t.Fatalf("decode: %v %v", got, err)
	}
	for _, bad := range []string{
		strings.Replace(valid, `"id":"repo-skills"`, `"id":"BAD"`, 1),
		strings.Replace(valid, `"type":"directory"`, `"type":"directory","access":"read-only"`, 1),
		strings.Replace(valid, `.agents/skills`, `../skills`, 1),
		strings.Replace(valid, `"directory"`, `"other"`, 1),
		strings.Replace(valid, `"workspace-relative"`, `"glob"`, 1),
		`{"entries":null}`, `{"entries":[] ,"extra":true}`,
	} {
		if _, err := Decode(json.RawMessage(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	dup := Selection{Entries: append(got.Entries, got.Entries[0])}
	if _, err := Canonical(dup); err == nil {
		t.Fatal("duplicate accepted")
	}
	dup.Entries[1].ID = "other"
	if _, err := Canonical(dup); err == nil {
		t.Fatal("duplicate reference accepted")
	}
	got.Entries[0].Reference.Path = strings.Repeat("a", MaximumPathBytes+1)
	if _, err := Canonical(got); err == nil {
		t.Fatal("unbounded path accepted")
	}
}
