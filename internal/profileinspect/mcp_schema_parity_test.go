package profileinspect_test

import (
	"fmt"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
)

func TestPassiveAndActiveMCPReferenceAdmissionStayInParity(t *testing.T) {
	adapter, err := devin.NewProfileEditor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := `{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"executables":{"version":1,"selection":{"entries":[{"id":"server-bin","reference":{"kind":"fixed-search-name","name":"tool"}}]}},"paths":{"version":1,"selection":{"entries":[]}},"environment":{"version":1,"selection":{"entries":[{"id":"token","destination":"MCP_TOKEN","scope":"attached-process-tree","source":{"kind":"secret-reference","provider":"host-environment","reference":"HOST_MCP_TOKEN"},"required":true,"classification":"secret"}]}},"mcp":{"version":1,"selection":%s}},"overlays":{"devin":{"version":1}}}`
	valid := `{"servers":[{"id":"tool","transport":"stdio","executableRef":"server-bin","arguments":[],"inputRefs":[],"environmentRefs":["token"]}]}`
	assertBoth := func(name, selection string, validExpected bool) {
		t.Helper()
		data := []byte(fmt.Sprintf(base, selection))
		passive := profileinspect.InspectBytes("example", data)
		_, activeErr := adapter.Categories().DecodeNamed("example", data)
		if validExpected {
			if passive.Status != "valid" || activeErr != nil {
				t.Fatalf("%s valid admission: passive=%#v active=%v", name, passive, activeErr)
			}
		} else if passive.Status == "valid" || activeErr == nil {
			t.Fatalf("%s invalid admission: passive=%#v active=%v", name, passive, activeErr)
		}
	}
	assertBoth("secret selected for child environment", valid, true)
	assertBoth("missing executable reference", `{"servers":[{"id":"tool","transport":"stdio","executableRef":"missing","arguments":[],"inputRefs":[],"environmentRefs":[]}]}`, false)
}
