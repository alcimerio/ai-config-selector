// Package mcpintent owns the dependency-light common.mcp schema. It stores
// references only; it never discovers executables, opens paths, or resolves
// environment values.
package mcpintent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/alcimerio/ai-config-selector/internal/environmentintent"
	"github.com/alcimerio/ai-config-selector/internal/executableintent"
	"github.com/alcimerio/ai-config-selector/internal/pathintent"
)

const (
	MaximumServers            = 64
	MaximumArgumentsPerServer = 128
	MaximumInputsPerServer    = 64
	MaximumEnvironmentRefs    = 128
	MaximumDisabledTools      = 256
	MaximumAggregateItems     = 4096
	MaximumSelectionBytes     = 1 << 20
)

const (
	TransportStdio = "stdio"
	ArgumentPath   = "path"
	ArgumentEnv    = "environment"
)

type Argument struct {
	Kind string `json:"kind"`
	Ref  string `json:"ref"`
}

// Server contains references only. Literal commands, argv values, paths, and
// environment values are excluded from this schema.
type Server struct {
	ID              string     `json:"id"`
	Transport       string     `json:"transport"`
	ExecutableRef   string     `json:"executableRef"`
	Arguments       []Argument `json:"arguments"`
	InputRefs       []string   `json:"inputRefs"`
	EnvironmentRefs []string   `json:"environmentRefs"`
	DisabledTools   []string   `json:"disabledTools,omitempty"`
}

type Selection struct {
	Servers []Server `json:"servers"`
}

var (
	serverIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	refIDPattern    = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	fieldNames      = []string{"servers", "id", "transport", "executableRef", "arguments", "kind", "ref", "inputRefs", "environmentRefs", "disabledTools"}
)

func Empty() Selection { return Selection{Servers: []Server{}} }

func Decode(data json.RawMessage) (Selection, error) {
	if len(data) == 0 || len(data) > MaximumSelectionBytes || !utf8.Valid(data) || !pairedUnicodeEscapes(data) || uniqueJSON(data) != nil {
		return Selection{}, errors.New("MCP selection is invalid")
	}
	var wire struct {
		Servers *[]json.RawMessage `json:"servers"`
	}
	if err := decodeOne(data, &wire); err != nil || wire.Servers == nil {
		return Selection{}, errors.New("MCP selection servers are required")
	}
	selection := Selection{Servers: make([]Server, 0, len(*wire.Servers))}
	for _, encoded := range *wire.Servers {
		var item struct {
			ID              *string            `json:"id"`
			Transport       *string            `json:"transport"`
			ExecutableRef   *string            `json:"executableRef"`
			Arguments       *[]json.RawMessage `json:"arguments"`
			InputRefs       *[]string          `json:"inputRefs"`
			EnvironmentRefs *[]string          `json:"environmentRefs"`
			DisabledTools   json.RawMessage    `json:"disabledTools"`
		}
		if err := decodeOne(encoded, &item); err != nil || item.ID == nil || item.Transport == nil || item.ExecutableRef == nil || item.Arguments == nil || item.InputRefs == nil || item.EnvironmentRefs == nil {
			return Selection{}, errors.New("MCP server entry is incomplete")
		}
		server := Server{ID: *item.ID, Transport: *item.Transport, ExecutableRef: *item.ExecutableRef,
			Arguments: []Argument{}, InputRefs: append([]string{}, (*item.InputRefs)...), EnvironmentRefs: append([]string{}, (*item.EnvironmentRefs)...), DisabledTools: []string{}}
		for _, rawArgument := range *item.Arguments {
			var argument struct {
				Kind *string `json:"kind"`
				Ref  *string `json:"ref"`
			}
			if err := decodeOne(rawArgument, &argument); err != nil || argument.Kind == nil || argument.Ref == nil {
				return Selection{}, errors.New("MCP argument reference is incomplete")
			}
			server.Arguments = append(server.Arguments, Argument{Kind: *argument.Kind, Ref: *argument.Ref})
		}
		if len(item.DisabledTools) != 0 {
			if bytes.Equal(item.DisabledTools, []byte("null")) {
				return Selection{}, errors.New("disabled MCP tool list must not be null")
			}
			var disabled []string
			if err := decodeOne(item.DisabledTools, &disabled); err != nil || disabled == nil {
				return Selection{}, errors.New("disabled MCP tool list is invalid")
			}
			server.DisabledTools = append([]string{}, disabled...)
		}
		selection.Servers = append(selection.Servers, server)
	}
	return Canonical(selection)
}

func Encode(selection Selection) (json.RawMessage, error) {
	canonical, err := Canonical(selection)
	if err != nil {
		return nil, err
	}
	return json.Marshal(canonical)
}

func Canonical(selection Selection) (Selection, error) {
	if selection.Servers == nil {
		selection.Servers = []Server{}
	}
	if len(selection.Servers) > MaximumServers {
		return Selection{}, errors.New("too many MCP servers")
	}
	result := Selection{Servers: make([]Server, len(selection.Servers))}
	copy(result.Servers, selection.Servers)
	seen := map[string]bool{}
	aggregate := 0
	for index := range result.Servers {
		server := &result.Servers[index]
		if !serverIDPattern.MatchString(server.ID) || seen[server.ID] {
			return Selection{}, errors.New("MCP server ID is invalid or duplicated")
		}
		seen[server.ID] = true
		if server.Transport != TransportStdio {
			return Selection{}, errors.New("MCP transport is unsupported; only local stdio is supported")
		}
		if !refIDPattern.MatchString(server.ExecutableRef) {
			return Selection{}, errors.New("MCP executable reference is invalid")
		}
		if server.Arguments == nil || len(server.Arguments) > MaximumArgumentsPerServer || server.InputRefs == nil || len(server.InputRefs) > MaximumInputsPerServer || server.EnvironmentRefs == nil || len(server.EnvironmentRefs) > MaximumEnvironmentRefs {
			return Selection{}, errors.New("MCP reference lists are missing or exceed limits")
		}
		if server.DisabledTools == nil {
			server.DisabledTools = []string{}
		}
		if len(server.DisabledTools) > MaximumDisabledTools {
			return Selection{}, errors.New("too many disabled MCP tool names")
		}
		aggregate += len(server.Arguments) + len(server.InputRefs) + len(server.EnvironmentRefs) + len(server.DisabledTools)
		if aggregate > MaximumAggregateItems {
			return Selection{}, errors.New("MCP selection exceeds aggregate reference limit")
		}
		server.Arguments = append([]Argument{}, server.Arguments...)
		for _, argument := range server.Arguments {
			if (argument.Kind != ArgumentPath && argument.Kind != ArgumentEnv) || !refIDPattern.MatchString(argument.Ref) {
				return Selection{}, errors.New("MCP argument must reference a declared path or environment entry")
			}
		}
		var err error
		server.InputRefs, err = canonicalIDs(server.InputRefs, MaximumInputsPerServer, "MCP input reference")
		if err != nil {
			return Selection{}, err
		}
		server.EnvironmentRefs, err = canonicalIDs(server.EnvironmentRefs, MaximumEnvironmentRefs, "MCP environment reference")
		if err != nil {
			return Selection{}, err
		}
		server.DisabledTools = append([]string(nil), server.DisabledTools...)
		for _, name := range server.DisabledTools {
			if !utf8.ValidString(name) || !toolNamePattern.MatchString(name) || strings.ContainsRune(name, 0) {
				return Selection{}, errors.New("disabled MCP tool name is invalid")
			}
		}
		sort.Strings(server.DisabledTools)
		for toolIndex := 1; toolIndex < len(server.DisabledTools); toolIndex++ {
			if server.DisabledTools[toolIndex] == server.DisabledTools[toolIndex-1] {
				return Selection{}, errors.New("disabled MCP tool names are duplicated")
			}
		}
	}
	sort.Slice(result.Servers, func(i, j int) bool { return result.Servers[i].ID < result.Servers[j].ID })
	return result, nil
}

func canonicalIDs(values []string, limit int, label string) ([]string, error) {
	if len(values) > limit {
		return nil, errors.New(label + " list exceeds limit")
	}
	result := append([]string{}, values...)
	for _, value := range result {
		if !refIDPattern.MatchString(value) {
			return nil, errors.New(label + " is invalid")
		}
	}
	sort.Strings(result)
	for index := 1; index < len(result); index++ {
		if result[index] == result[index-1] {
			return nil, errors.New(label + " is duplicated")
		}
	}
	return result, nil
}

// ValidateReferences binds MCP descriptors to the other selected common
// capabilities. It examines identifiers and classifications only, never
// resolving secret values or host paths.
func ValidateReferences(selection Selection, executables executableintent.Selection, paths pathintent.Selection, environment environmentintent.Selection) error {
	executableIDs := make(map[string]bool, len(executables.Entries))
	for _, entry := range executables.Entries {
		executableIDs[entry.ID] = true
	}
	pathIDs := make(map[string]bool, len(paths.Entries))
	for _, entry := range paths.Entries {
		pathIDs[entry.ID] = true
	}
	environmentByID := make(map[string]environmentintent.Entry, len(environment.Entries))
	for _, entry := range environment.Entries {
		environmentByID[entry.ID] = entry
	}
	for _, server := range selection.Servers {
		if !executableIDs[server.ExecutableRef] {
			return errors.New("MCP executable reference is not selected")
		}
		inputIDs := make(map[string]bool, len(server.InputRefs))
		for _, id := range server.InputRefs {
			if !pathIDs[id] {
				return errors.New("MCP input reference is not selected")
			}
			inputIDs[id] = true
		}
		environmentIDs := make(map[string]bool, len(server.EnvironmentRefs))
		for _, id := range server.EnvironmentRefs {
			if _, exists := environmentByID[id]; !exists {
				return errors.New("MCP environment reference is not selected")
			}
			environmentIDs[id] = true
		}
		for _, argument := range server.Arguments {
			switch argument.Kind {
			case ArgumentPath:
				if !pathIDs[argument.Ref] || !inputIDs[argument.Ref] {
					return errors.New("MCP path argument must reference a declared input")
				}
			case ArgumentEnv:
				entry, exists := environmentByID[argument.Ref]
				if !exists || !environmentIDs[argument.Ref] || entry.Classification != environmentintent.ClassificationNonSecret {
					return errors.New("MCP argv environment reference must select a non-secret entry")
				}
			}
		}
	}
	return nil
}

func decodeOne(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON data")
	}
	return nil
}

func uniqueJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

func uniqueValue(decoder *json.Decoder, depth int) error {
	if depth > 24 {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate object key")
			}
			if hasNoncanonicalFieldCase(name) {
				return errors.New("noncanonical object key")
			}
			seen[name] = true
			if err := uniqueValue(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := uniqueValue(decoder, depth+1); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	_, err = decoder.Token()
	return err
}

func hasNoncanonicalFieldCase(name string) bool {
	for _, expected := range fieldNames {
		if strings.EqualFold(name, expected) && name != expected {
			return true
		}
	}
	return false
}

func pairedUnicodeEscapes(data []byte) bool {
	for index := 0; index < len(data); index++ {
		if data[index] != '\\' {
			continue
		}
		index++
		if index >= len(data) || data[index] != 'u' {
			continue
		}
		if index+4 >= len(data) {
			return false
		}
		first, ok := hex4(data[index+1 : index+5])
		if !ok {
			return false
		}
		if first >= 0xDC00 && first <= 0xDFFF {
			return false
		}
		index += 4
		if first >= 0xD800 && first <= 0xDBFF {
			if index+6 >= len(data) || data[index+1] != '\\' || data[index+2] != 'u' {
				return false
			}
			second, valid := hex4(data[index+3 : index+7])
			if !valid || second < 0xDC00 || second > 0xDFFF {
				return false
			}
			index += 6
		}
	}
	return true
}

func hex4(value []byte) (uint16, bool) {
	if len(value) != 4 {
		return 0, false
	}
	var result uint16
	for _, char := range value {
		result <<= 4
		switch {
		case char >= '0' && char <= '9':
			result |= uint16(char - '0')
		case char >= 'a' && char <= 'f':
			result |= uint16(char-'a') + 10
		case char >= 'A' && char <= 'F':
			result |= uint16(char-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}
