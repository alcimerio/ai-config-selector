// Package executableintent owns the dependency-light common.executables
// schema. It validates logical intent only and never searches the host.
package executableintent

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	MaximumEntries    = 128
	MaximumPathBytes  = 1024
	MaximumComponents = 128
)

type ReferenceKind string

const (
	ReferenceFixedSearchName   ReferenceKind = "fixed-search-name"
	ReferenceWorkspaceRelative ReferenceKind = "workspace-relative"
	ReferenceLocalAbsolute     ReferenceKind = "local-absolute"
)

type Reference struct {
	Kind string `json:"kind"`
	Name string `json:"name,omitempty"`
	Path string `json:"path,omitempty"`
}

type Entry struct {
	ID        string    `json:"id"`
	Reference Reference `json:"reference"`
}

type Selection struct {
	Entries []Entry `json:"entries"`
}

var (
	entryIDPattern    = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)
	searchNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,254}$`)
)

func Empty() Selection { return Selection{Entries: []Entry{}} }

func Encode(selection Selection) (json.RawMessage, error) {
	canonical, err := Canonical(selection)
	if err != nil {
		return nil, err
	}
	return json.Marshal(canonical)
}

func Decode(data json.RawMessage) (Selection, error) {
	var selection Selection
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&selection); err != nil {
		return Selection{}, err
	}
	if selection.Entries == nil {
		return Selection{}, errors.New("executable selection entries are required")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Selection{}, errors.New("executable selection contains invalid trailing data")
	}
	return Canonical(selection)
}

func Canonical(selection Selection) (Selection, error) {
	if selection.Entries == nil {
		selection.Entries = []Entry{}
	}
	if len(selection.Entries) > MaximumEntries {
		return Selection{}, errors.New("too many executable entries")
	}
	// Preserve an explicit empty array on round-trip; append to a nil slice
	// would otherwise re-encode it as null.
	result := Selection{Entries: make([]Entry, len(selection.Entries))}
	copy(result.Entries, selection.Entries)
	seenIDs, seenDestinations := map[string]bool{}, map[string]bool{}
	for index := range result.Entries {
		entry := &result.Entries[index]
		if !entryIDPattern.MatchString(entry.ID) || seenIDs[entry.ID] {
			return Selection{}, errors.New("executable entry ID is invalid or duplicated")
		}
		seenIDs[entry.ID] = true
		kind := ReferenceKind(entry.Reference.Kind)
		switch kind {
		case ReferenceFixedSearchName:
			if entry.Reference.Path != "" || !utf8.ValidString(entry.Reference.Name) || !searchNamePattern.MatchString(entry.Reference.Name) || entry.Reference.Name == "." || entry.Reference.Name == ".." {
				return Selection{}, errors.New("fixed-search executable name is invalid")
			}
		case ReferenceWorkspaceRelative:
			if entry.Reference.Name != "" || !validPath(entry.Reference.Path) || filepath.IsAbs(entry.Reference.Path) || strings.ContainsRune(entry.Reference.Path, '\\') {
				return Selection{}, errors.New("workspace-relative executable path is invalid")
			}
			cleaned := path.Clean(entry.Reference.Path)
			if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || len(strings.Split(cleaned, "/")) > MaximumComponents {
				return Selection{}, errors.New("workspace-relative executable path escapes its anchor")
			}
			entry.Reference.Path = cleaned
		case ReferenceLocalAbsolute:
			if entry.Reference.Name != "" || !validPath(entry.Reference.Path) || !filepath.IsAbs(entry.Reference.Path) {
				return Selection{}, errors.New("local executable path must be absolute")
			}
			cleaned := filepath.Clean(entry.Reference.Path)
			if cleaned == string(filepath.Separator) || len(strings.Split(strings.TrimPrefix(cleaned, string(filepath.Separator)), string(filepath.Separator))) > MaximumComponents {
				return Selection{}, errors.New("local executable root is unsupported")
			}
			entry.Reference.Path = cleaned
		default:
			return Selection{}, errors.New("unsupported executable reference kind")
		}
		destination := entry.Reference.Kind + "\x00" + entry.Reference.Name + "\x00" + entry.Reference.Path
		if seenDestinations[destination] {
			return Selection{}, errors.New("executable semantic destination is duplicated")
		}
		seenDestinations[destination] = true
	}
	sort.Slice(result.Entries, func(i, j int) bool { return result.Entries[i].ID < result.Entries[j].ID })
	return result, nil
}

func validPath(value string) bool {
	return value != "" && len(value) <= MaximumPathBytes && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}
