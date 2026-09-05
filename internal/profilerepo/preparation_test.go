package profilerepo

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestEveryCanonicalPreparationTruncationIsRecognized(t *testing.T) {
	for _, op := range []string{"create", "replace", "clone", "rename", "delete"} {
		for _, size := range []int64{0, MaxDocumentBytes} {
			id := identity{Device: ^uint64(0), Inode: ^uint64(0), Size: size, Hash: strings.Repeat("a", 64)}
			p := plan{Version: 1, ID: strings.Repeat("0", 32), Operation: op}
			if op != "create" {
				p.Source = strings.Repeat("s", 64)
				p.Before = &id
			}
			if op == "create" || op == "clone" || op == "rename" {
				p.Destination = strings.Repeat("d", 64)
			}
			if op != "delete" {
				p.Stage = &id
			}
			data, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = decodePlan(data); err != nil {
				t.Fatal(err)
			}
			for cut := 0; cut <= len(data); cut++ {
				if !preparationPrefix(data[:cut]) {
					t.Fatalf("legitimate %s size %d prefix rejected at byte %d: %q", op, size, cut, data[:cut])
				}
			}
		}
	}
}
func TestPreparationPrefixRejectsImpossibleScalarsAndFieldOrder(t *testing.T) {
	id := identity{Device: 1, Inode: 1, Size: 0, Hash: strings.Repeat("a", 64)}
	encoded, err := json.Marshal(plan{Version: 1, ID: strings.Repeat("0", 32), Operation: "replace", Source: "source", Before: &id, Stage: &id})
	if err != nil {
		t.Fatal(err)
	}
	base := string(encoded)
	if !preparationPrefix(encoded) {
		t.Fatal("valid canonical base rejected")
	}

	cases := []string{
		`{"Version":1,"ID":"INVALID!`,
		strings.Replace(base, `"Operation":"replace"`, `"Operation":"future"`, 1),
		strings.Replace(base, `"Device":1`, `"Device":01`, 1),
		strings.Replace(base, `"Device":1`, `"Device":18446744073709551616`, 1),
		strings.Replace(base, `"Inode":1`, `"Inode":0`, 1),
		strings.Replace(base, `"Size":0`, `"Size":1048577`, 1),
		strings.Replace(base, `"Source":"source"`, `"Source":"../escape"`, 1),
		strings.Replace(base, `"Source":"source"`, `"Source":"`+strings.Repeat("a", 65)+`"`, 1),
		strings.Replace(base, `"Before":`, `"Unknown":`, 1),
	}
	for _, data := range cases {
		if preparationPrefix([]byte(data)) {
			t.Fatalf("impossible canonical prefix accepted: %q", data)
		}
	}
}
