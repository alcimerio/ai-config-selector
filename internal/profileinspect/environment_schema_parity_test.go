package profileinspect_test

import (
	"fmt"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
)

func TestPassiveAndActiveEnvironmentAdmissionStayInParity(t *testing.T) {
	adapter, err := devin.NewProfileEditor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := `{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}%s},"overlays":{"devin":{"version":1}}}`

	t.Run("omitted synthesizes canonical empty", func(t *testing.T) {
		data := []byte(fmt.Sprintf(base, ""))
		if got := profileinspect.InspectBytes("example", data); got.Status != "valid" {
			t.Fatalf("passive admission = %#v", got)
		}
		candidate, err := adapter.Categories().DecodeNamed("example", data)
		if err != nil {
			t.Fatal(err)
		}
		selection, err := commonprofile.DecodeEnvironmentSelection(candidate.Common[commonprofile.EnvironmentCapabilityID].Selection)
		if err != nil || len(selection.Entries) != 0 {
			t.Fatalf("synthesized environment = %+v, %v", selection, err)
		}
	})

	validSelection := `{"entries":[{"id":"mode","destination":"BUILD_MODE","scope":"attached-process-tree","source":{"kind":"host-environment","name":"HOST_MODE"},"required":false,"classification":"non-secret"},{"id":"token","destination":"API_TOKEN","scope":"attached-process-tree","source":{"kind":"secret-reference","provider":"host-environment","reference":"HOST_TOKEN"},"required":true,"classification":"secret"}]}`
	t.Run("present version one is passive and active", func(t *testing.T) {
		data := []byte(fmt.Sprintf(base, `,"environment":{"version":1,"selection":`+validSelection+`}`))
		if got := profileinspect.InspectBytes("example", data); got.Status != "valid" {
			t.Fatalf("passive admission = %#v", got)
		}
		candidate, err := adapter.Categories().DecodeNamed("example", data)
		if err != nil {
			t.Fatal(err)
		}
		selection, err := commonprofile.DecodeEnvironmentSelection(candidate.Common[commonprofile.EnvironmentCapabilityID].Selection)
		if err != nil || len(selection.Entries) != 2 || selection.Entries[1].Source.Reference != "HOST_TOKEN" {
			t.Fatalf("active selection = %+v, %v", selection, err)
		}
	})

	for name, capability := range map[string]string{
		"null payload":    `,"environment":null`,
		"null selection":  `,"environment":{"version":1,"selection":null}`,
		"wrong version":   `,"environment":{"version":2,"selection":{"entries":[]}}`,
		"unknown payload": `,"environment":{"version":1,"selection":{"entries":[]},"future":true}`,
	} {
		t.Run(name, func(t *testing.T) {
			data := []byte(fmt.Sprintf(base, capability))
			if got := profileinspect.InspectBytes("example", data); got.Status == "valid" {
				t.Fatalf("passive admission accepted %s: %#v", capability, got)
			}
			if _, err := adapter.Categories().DecodeNamed("example", data); err == nil {
				t.Fatalf("active admission accepted %s", capability)
			}
		})
	}
}
