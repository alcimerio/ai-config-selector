package networkintent

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestLoopbackSelectionStrictAdmission(t *testing.T) {
	for _, bad := range []string{
		`null`, `{}`, `[]`, `{"loopbackPorts":null}`, `{"loopbackPorts":[0]}`,
		`{"loopbackPorts":[-1]}`, `{"loopbackPorts":[65536]}`, `{"loopbackPorts":[1,1]}`,
		`{"loopbackPorts":["1455"]}`, `{"loopbackPorts":["1-20"]}`, `{"loopbackPorts":[1.0]}`,
		`{"loopbackPorts":[1e2]}`, `{"loopbackPorts":[null]}`, `{"loopbackPorts":[true]}`,
		`{"LoopbackPorts":[]}`, `{"loopbackPorts":[],"other":true}`, `{"loopbackPorts":[],"loopbackPorts":[1]}`,
		`{"loopbackPorts":[]} {}`, `{"loopbackPorts":[` + strings.Repeat("1,", MaxLoopbackPorts) + `2]}`,
	} {
		t.Run(bad, func(t *testing.T) {
			if _, err := Decode(json.RawMessage(bad)); err == nil {
				t.Fatalf("accepted %s", bad)
			}
		})
	}
	for _, valid := range []string{`{"loopbackPorts":[]}`, `{"loopbackPorts":[65535,1455,1]}`} {
		value, err := Decode(json.RawMessage(valid))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := Encode(value)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Decode(encoded)
		if err != nil || !reflect.DeepEqual(value, again) {
			t.Fatalf("round trip: %#v %v", again, err)
		}
	}
	ports := []int{65535, 1}
	got, err := Canonical(Selection{LoopbackPorts: ports})
	if err != nil || !reflect.DeepEqual(got.LoopbackPorts, []int{1, 65535}) || ports[0] != 65535 {
		t.Fatalf("canonical=%#v input=%v err=%v", got, ports, err)
	}
	for _, ports := range [][]int{{0}, {1, 1}, make([]int, MaxLoopbackPorts+1)} {
		if _, err := Encode(Selection{LoopbackPorts: ports}); err == nil {
			t.Fatalf("encoded invalid ports %v", ports)
		}
	}
}

func TestLoopbackPortCountBoundary(t *testing.T) {
	ports := make([]int, MaxLoopbackPorts)
	for i := range ports {
		ports[i] = i + 1
	}
	encoded, err := Encode(Selection{LoopbackPorts: ports})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(encoded); err != nil {
		t.Fatal(err)
	}
	ports = append(ports, MaxLoopbackPorts+1)
	if _, err := Encode(Selection{LoopbackPorts: ports}); err == nil {
		t.Fatal("encoded more than 64 unique valid ports")
	}
	overLimit, err := json.Marshal(Selection{LoopbackPorts: ports})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(overLimit); err == nil {
		t.Fatal("decoded more than 64 unique valid ports")
	}
}
