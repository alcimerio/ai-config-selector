package profileinspect

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSelectionCountsPreserveScalarAndEmptyCapabilities(t *testing.T) {
	body := `{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"paths":{"version":1,"selection":{"entries":[]}},"exclusions":{"version":1,"selection":{"entries":[]}},"executables":{"version":1,"selection":{"entries":[]}},"environment":{"version":1,"selection":{"entries":[]}},"mcp":{"version":1,"selection":{"servers":[]}},"instructions":{"version":1,"selection":[]}},"overlays":{}}`
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
}

func TestUnrecognizedCategoryDoesNotInventASelectionCount(t *testing.T) {
	if count, known := (Category{ID: "future"}).SelectionCount(); count != 0 || known {
		t.Fatalf("unknown count = %d, %v", count, known)
	}
}
