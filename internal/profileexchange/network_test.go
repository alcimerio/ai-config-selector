package profileexchange

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/networkintent"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

func TestNetworkPortableRoundTripAndStrictAdmission(t *testing.T) {
	candidate := fixtureProfile(t)
	encoded, err := networkintent.Encode(networkintent.Selection{LoopbackPorts: []int{8080, 1455}})
	if err != nil {
		t.Fatal(err)
	}
	candidate.Common[commonprofile.NetworkCapabilityID] = profile.CommonPayload{Version: 1, Selection: encoded}
	document, _, err := Export(candidate)
	if err != nil {
		t.Fatal(err)
	}
	bindings := []byte(`{"bindingVersion":3,"sources":{"source-1":"devin-config","source-2":"shared-agents"},"authentications":{"authentication-1":"personal"},"paths":{},"executables":{},"environment":{}}`)
	result := Decode(document, bindings, "imported")
	if result.Code != CodeValid || result.Candidate == nil {
		t.Fatalf("round trip: %#v", result)
	}
	selection, err := networkintent.Decode(result.Candidate.Common["network"].Selection)
	if err != nil || !reflect.DeepEqual(selection.LoopbackPorts, []int{1455, 8080}) {
		t.Fatalf("ports lost: %#v %v", selection, err)
	}
	for _, mutation := range [][]byte{
		bytes.Replace(document, []byte(`"network":`), []byte(`"Network":`), 1),
		bytes.Replace(document, []byte(`"loopbackPorts":`), []byte(`"LoopbackPorts":`), 1),
		bytes.Replace(document, []byte(`1455`), []byte(`0`), 1),
		bytes.Replace(document, []byte(`1455`), []byte(`"1455"`), 1),
		bytes.Replace(document, []byte(`"exchangeVersion": 3`), []byte(`"exchangeVersion": 2`), 1),
	} {
		result := Decode(mutation, bindings, "invalid")
		if result.Candidate != nil || result.Code == CodeValid {
			t.Fatalf("bad network exchange admitted: %s", mutation)
		}
	}
	candidate.Common["network"] = profile.CommonPayload{Version: 1, Selection: []byte(`{"loopbackPorts":[0]}`)}
	if _, _, err := Export(candidate); err == nil {
		t.Fatal("export silently accepted invalid network authority")
	}
}
