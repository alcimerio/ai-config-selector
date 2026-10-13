package profileinspect_test

import (
	"fmt"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
)

func TestPassiveAndActiveNetworkAdmissionStayInParity(t *testing.T) {
	codec, err := commonprofile.NewCodec()
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []int{1, 3} {
		for _, selection := range []string{`{"loopbackPorts":[]}`, `{"loopbackPorts":[1,1455,65535]}`, `{}`, `null`, `{"loopbackPorts":null}`, `{"loopbackPorts":[0]}`, `{"loopbackPorts":[1,1]}`, `{"loopbackPorts":[65536]}`, `{"loopbackPorts":["1455"]}`, `{"loopbackPorts":[1.5]}`, `{"LoopbackPorts":[]}`, `{"loopbackPorts":[],"extra":true}`} {
			body := []byte(fmt.Sprintf(`{"version":%d,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"network":{"version":1,"selection":%s}},"overlays":{"devin":{"version":1}}}`, version, selection))
			_, activeErr := codec.Decode(body)
			passiveValid := profileinspect.InspectBytes("example", body).Status == "valid"
			if passiveValid != (activeErr == nil) {
				t.Fatalf("admission drift: %s active=%v passive=%v", body, activeErr, passiveValid)
			}
		}
	}
	for _, body := range []string{
		`{"version":1,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}},"network":{"version":2,"selection":{"loopbackPorts":[]}}},"overlays":{"devin":{"version":1}}}`,
	} {
		_, err := codec.Decode([]byte(body))
		if err == nil || profileinspect.InspectBytes("example", []byte(body)).Status == "valid" {
			t.Fatal("unsupported network schema admitted")
		}
	}
}
