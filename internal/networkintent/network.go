// Package networkintent owns syntax-only loopback network authority.
package networkintent

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"

	"github.com/alcimerio/ai-config-selector/internal/strictjson"
)

const MaxLoopbackPorts = 64

type Selection struct {
	LoopbackPorts []int `json:"loopbackPorts"`
}

func Empty() Selection { return Selection{LoopbackPorts: []int{}} }

// Canonical copies and sorts the port set, refusing ambiguous or broad grants.
func Canonical(selection Selection) (Selection, error) {
	if len(selection.LoopbackPorts) > MaxLoopbackPorts {
		return Selection{}, errors.New("select at most 64 loopback ports")
	}
	ports := append([]int{}, selection.LoopbackPorts...)
	sort.Ints(ports)
	for i, port := range ports {
		if port < 1 || port > 65535 {
			return Selection{}, errors.New("loopback ports must be integers from 1 to 65535")
		}
		if i > 0 && ports[i-1] == port {
			return Selection{}, errors.New("duplicate loopback port")
		}
	}
	return Selection{LoopbackPorts: ports}, nil
}

func Encode(selection Selection) (json.RawMessage, error) {
	value, err := Canonical(selection)
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

func Decode(data json.RawMessage) (Selection, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := strictjson.Scan(decoder, strictjson.Limits{MaxDepth: 2, MaxArray: MaxLoopbackPorts, MaxMembers: 1}, func(key string) bool { return key != "loopbackPorts" }); err != nil {
		return Selection{}, err
	}
	var selection Selection
	// Missing and null arrays are malformed; omission of the capability is valid.
	if err := json.Unmarshal(data, &selection); err != nil {
		return Selection{}, err
	}
	if selection.LoopbackPorts == nil {
		return Selection{}, errors.New("loopbackPorts must be an array of integers")
	}
	return Canonical(selection)
}
