package profileinspect_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
)

func TestPassiveAndActiveExclusionSchemaAdmissionStayInParity(t *testing.T) {
	selections := []string{
		`{"entries":[]}`,
		`{"entries":[{"id":"data","type":"directory","reference":{"kind":"workspace-relative","path":"fixtures/data"}}]}`,
		`{}`, `{"entries":null}`, `{"entries":[],"future":true}`,
		`{"entries":[{"id":"BAD","type":"file","reference":{"kind":"workspace-relative","path":"a"}}]}`,
		`{"entries":[{"id":"a","type":"file","reference":{"kind":"workspace-relative","path":"same"}},{"id":"b","type":"file","reference":{"kind":"workspace-relative","path":"same"}}]}`,
		`{"entries":[{"id":"escape","type":"file","reference":{"kind":"workspace-relative","path":"../private"}}]}`,
	}
	for _, selection := range selections {
		_, activeErr := commonprofile.DecodeExclusionSelection(json.RawMessage(selection))
		profileBytes := fmt.Sprintf(`{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"exclusions":{"version":1,"selection":%s}},"overlays":{"devin":{"version":1}}}`, selection)
		passiveValid := profileinspect.InspectBytes("example", []byte(profileBytes)).Status == "valid"
		if passiveValid != (activeErr == nil) {
			t.Fatalf("admission drift for %s: activeErr=%v passiveValid=%v", selection, activeErr, passiveValid)
		}
	}
}
