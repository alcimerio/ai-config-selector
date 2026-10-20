package commonprofile

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestNetworkAuthorityDefaultsPortsDigestAndPlan(t *testing.T) {
	binding, err := NewNetworkBinding()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(ports []int) authority.Plan {
		t.Helper()
		draft := registry.NewDraft()
		if err := category.SetSelection(&draft, binding, NetworkSelection{LoopbackPorts: ports}); err != nil {
			t.Fatal(err)
		}
		candidate, err := registry.NewProfile("example", draft)
		if err != nil {
			t.Fatal(err)
		}
		plan, err := registry.Resolve(context.Background(), candidate)
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	denied := resolve(nil)
	allowed := resolve([]int{8080, 1455})
	if len(denied.RuntimeAuthority().LoopbackPorts) != 0 || !reflect.DeepEqual(allowed.RuntimeAuthority().LoopbackPorts, []int{1455, 8080}) {
		t.Fatal("runtime authority lost ports")
	}
	if denied.Explanation().AuthorityDigest == allowed.Explanation().AuthorityDigest {
		t.Fatal("ports missing from digest")
	}
	if allowed.Explanation().AuthorityDigest != resolve([]int{1455, 8080}).Explanation().AuthorityDigest {
		t.Fatal("digest depends on port order")
	}
	if authority.New([]authority.Contribution{{ID: NetworkCapabilityID, Value: NetworkContribution{}}}, launch.WorkspaceAccessReadWrite, "").AuthorityDigest() != authority.New(nil, launch.WorkspaceAccessReadWrite, "").AuthorityDigest() {
		t.Fatal("empty network selection changed default authority")
	}
	returned := allowed.RuntimeAuthority()
	returned.LoopbackPorts[0] = 9
	if allowed.RuntimeAuthority().LoopbackPorts[0] != 1455 {
		t.Fatal("runtime authority aliases stored ports")
	}
	for _, test := range []struct {
		ports []int
		want  string
	}{{nil, "denied"}, {[]int{1455}, "1455"}} {
		var plan launch.Plan
		if err := (NetworkContribution{ports: test.ports}).Plan(context.Background(), "", &plan); err != nil {
			t.Fatal(err)
		}
		body := ""
		for _, section := range plan.Sections {
			for _, item := range section.Items {
				body += item.Label
				for _, detail := range item.Details {
					body += detail.Value
				}
			}
		}
		if !strings.Contains(body, test.want) {
			t.Fatalf("plan missing policy: %s", body)
		}
	}
}
