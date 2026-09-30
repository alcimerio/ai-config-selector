package profileinspect

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestSelectionCountsPreserveScalarAndEmptyCapabilities(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		var body string
		switch version {
		case 1:
			body = `{"version":1,"name":"example","target":"devin","skillReferences":[]}`
		case 2:
			body = `{"version":2,"name":"example","target":"devin","categories":{"skills":{"schemaVersion":1,"selection":[]}}}`
		case 3:
			body = `{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"paths":{"version":1,"selection":{"entries":[]}},"executables":{"version":1,"selection":{"entries":[]}},"environment":{"version":1,"selection":{"entries":[]}},"mcp":{"version":1,"selection":{"servers":[]}},"instructions":{"version":1,"selection":[]}},"overlays":{}}`
		}
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			entry := InspectBytes("example", []byte(body))
			if entry.Status != "valid" {
				t.Fatalf("entry = %#v", entry)
			}
			for _, category := range entry.Categories {
				count, counted := category.SelectionCount()
				if count != 0 || counted != (category.ID != "workspace") {
					t.Errorf("%s count = %d, %v", category.ID, count, counted)
				}
				data, err := json.Marshal(category)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(strings.ToLower(string(data)), "count") {
					t.Fatalf("summary changed JSON contract: %s", data)
				}
			}
		})
	}
}

func TestUnrecognizedCategoryDoesNotInventASelectionCount(t *testing.T) {
	if count, known := (Category{ID: "future"}).SelectionCount(); count != 0 || known {
		t.Fatalf("unknown count = %d, %v", count, known)
	}
}
