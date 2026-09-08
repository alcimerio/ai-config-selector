// Package environmentintent owns the dependency-light common.environment
// schema. It validates logical intent only and never reads the host environment.
package environmentintent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
)

const (
	MaximumEntries        = 128
	MaximumValueBytes     = 32 * 1024
	MaximumAggregateBytes = 128 * 1024
)

const (
	ScopeAttachedProcessTree = "attached-process-tree"
	SourceHostEnvironment    = "host-environment"
	SourceSecretReference    = "secret-reference"
	ProviderHostEnvironment  = "host-environment"
	ClassificationNonSecret  = "non-secret"
	ClassificationSecret     = "secret"
)

type Source struct {
	Kind      string `json:"kind"`
	Name      string `json:"name,omitempty"`
	Provider  string `json:"provider,omitempty"`
	Reference string `json:"reference,omitempty"`
}

type Entry struct {
	ID             string `json:"id"`
	Destination    string `json:"destination"`
	Scope          string `json:"scope"`
	Source         Source `json:"source"`
	Required       bool   `json:"required"`
	Classification string `json:"classification"`
}

type Selection struct {
	Entries []Entry `json:"entries"`
}

var (
	entryIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	namePattern    = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,127}$`)
)

var reservedExact = map[string]struct{}{
	"HOME": {}, "PATH": {}, "PWD": {}, "TMPDIR": {},
	"XDG_CONFIG_HOME": {}, "XDG_DATA_HOME": {}, "XDG_CACHE_HOME": {}, "XDG_STATE_HOME": {},
	"TERM": {}, "COLORTERM": {}, "LANG": {}, "LC_ALL": {}, "LC_CTYPE": {},
	"BASH_ENV": {}, "ENV": {}, "ZDOTDIR": {}, "SHELLOPTS": {}, "BASHOPTS": {}, "PROMPT_COMMAND": {},
}

var reservedPrefixes = []string{"ACS_", "DYLD_", "LD_", "LC_"}

func Empty() Selection { return Selection{Entries: []Entry{}} }

func ValidName(value string) bool { return namePattern.MatchString(value) }

func ReservedDestination(value string) bool {
	if _, exists := reservedExact[value]; exists {
		return true
	}
	for _, prefix := range reservedPrefixes {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func Encode(selection Selection) (json.RawMessage, error) {
	canonical, err := Canonical(selection)
	if err != nil {
		return nil, err
	}
	return json.Marshal(canonical)
}

func Decode(data json.RawMessage) (Selection, error) {
	var wire struct {
		Entries *[]json.RawMessage `json:"entries"`
	}
	if err := decodeOne(data, &wire); err != nil {
		return Selection{}, err
	}
	if wire.Entries == nil {
		return Selection{}, errors.New("environment selection entries are required")
	}
	selection := Selection{Entries: make([]Entry, 0, len(*wire.Entries))}
	for _, encoded := range *wire.Entries {
		var entryWire struct {
			ID             *string         `json:"id"`
			Destination    *string         `json:"destination"`
			Scope          *string         `json:"scope"`
			Source         json.RawMessage `json:"source"`
			Required       *bool           `json:"required"`
			Classification *string         `json:"classification"`
		}
		if err := decodeOne(encoded, &entryWire); err != nil || entryWire.ID == nil || entryWire.Destination == nil || entryWire.Scope == nil || entryWire.Required == nil || entryWire.Classification == nil || len(entryWire.Source) == 0 || bytes.Equal(entryWire.Source, []byte("null")) {
			return Selection{}, errors.New("environment entry is incomplete")
		}
		var sourceFields map[string]json.RawMessage
		if err := decodeOne(entryWire.Source, &sourceFields); err != nil || sourceFields == nil {
			return Selection{}, errors.New("environment source is invalid")
		}
		kind, ok := requiredString(sourceFields, "kind")
		if !ok {
			return Selection{}, errors.New("environment source kind is invalid")
		}
		source := Source{Kind: kind}
		switch kind {
		case SourceHostEnvironment:
			name, exists := requiredString(sourceFields, "name")
			if !exists || len(sourceFields) != 2 {
				return Selection{}, errors.New("host environment source shape is invalid")
			}
			source.Name = name
		case SourceSecretReference:
			provider, providerExists := requiredString(sourceFields, "provider")
			reference, referenceExists := requiredString(sourceFields, "reference")
			if !providerExists || !referenceExists || len(sourceFields) != 3 {
				return Selection{}, errors.New("secret reference source shape is invalid")
			}
			source.Provider, source.Reference = provider, reference
		default:
			return Selection{}, errors.New("environment source kind is unsupported")
		}
		entry := Entry{ID: *entryWire.ID, Destination: *entryWire.Destination, Scope: *entryWire.Scope, Required: *entryWire.Required, Classification: *entryWire.Classification, Source: source}
		selection.Entries = append(selection.Entries, entry)
	}
	return Canonical(selection)
}

func requiredString(fields map[string]json.RawMessage, name string) (string, bool) {
	encoded, exists := fields[name]
	if !exists {
		return "", false
	}
	var value string
	if json.Unmarshal(encoded, &value) != nil || value == "" {
		return "", false
	}
	return value, true
}

func Canonical(selection Selection) (Selection, error) {
	if selection.Entries == nil {
		selection.Entries = []Entry{}
	}
	if len(selection.Entries) > MaximumEntries {
		return Selection{}, errors.New("too many environment entries")
	}
	result := Selection{Entries: append([]Entry(nil), selection.Entries...)}
	if result.Entries == nil {
		result.Entries = []Entry{}
	}
	seenIDs, seenDestinations := map[string]bool{}, map[string]bool{}
	for _, entry := range result.Entries {
		if !entryIDPattern.MatchString(entry.ID) || seenIDs[entry.ID] {
			return Selection{}, errors.New("environment entry ID is invalid or duplicated")
		}
		seenIDs[entry.ID] = true
		if !ValidName(entry.Destination) || ReservedDestination(entry.Destination) || seenDestinations[entry.Destination] {
			return Selection{}, errors.New("environment destination is invalid, reserved, or duplicated")
		}
		seenDestinations[entry.Destination] = true
		if entry.Scope != ScopeAttachedProcessTree {
			return Selection{}, errors.New("environment scope is unsupported")
		}
		switch entry.Classification {
		case ClassificationNonSecret:
			if entry.Source.Kind != SourceHostEnvironment || !ValidName(entry.Source.Name) || entry.Source.Provider != "" || entry.Source.Reference != "" {
				return Selection{}, errors.New("non-secret environment source is invalid")
			}
		case ClassificationSecret:
			if !entry.Required || entry.Source.Kind != SourceSecretReference || entry.Source.Name != "" || entry.Source.Provider != ProviderHostEnvironment || !ValidName(entry.Source.Reference) {
				return Selection{}, errors.New("secret environment source is invalid")
			}
		default:
			return Selection{}, errors.New("environment classification is unsupported")
		}
	}
	sort.Slice(result.Entries, func(i, j int) bool { return result.Entries[i].ID < result.Entries[j].ID })
	return result, nil
}

func decodeOne(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("environment selection contains invalid trailing data")
	}
	return nil
}
