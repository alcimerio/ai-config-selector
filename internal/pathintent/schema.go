// Package pathintent owns the dependency-light common.paths schema. It
// validates and canonicalizes logical intent only; it never opens host paths.
package pathintent

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

type Access string
type Type string
type ReferenceKind string

const (
	AccessReadOnly             Access        = "read-only"
	AccessReadWrite            Access        = "read-write"
	TypeFile                   Type          = "file"
	TypeDirectory              Type          = "directory"
	ReferenceWorkspaceRelative ReferenceKind = "workspace-relative"
	ReferenceLocalAbsolute     ReferenceKind = "local-absolute"
)

type Reference struct {
	Kind string `json:"kind"`
	Path string `json:"path"`
}

type Entry struct {
	ID        string    `json:"id"`
	Access    Access    `json:"access"`
	Type      Type      `json:"type"`
	Reference Reference `json:"reference"`
}

type Selection struct {
	Entries []Entry `json:"entries"`
}

var entryIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

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
		return Selection{}, errors.New("path selection entries are required")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Selection{}, errors.New("path selection contains invalid trailing data")
	}
	return Canonical(selection)
}

func Canonical(selection Selection) (Selection, error) {
	if selection.Entries == nil {
		selection.Entries = []Entry{}
	}
	if len(selection.Entries) > MaximumEntries {
		return Selection{}, errors.New("too many path entries")
	}
	result := Selection{Entries: make([]Entry, len(selection.Entries))}
	copy(result.Entries, selection.Entries)
	seen, destinations := map[string]bool{}, map[string]bool{}
	for index := range result.Entries {
		entry := &result.Entries[index]
		if !entryIDPattern.MatchString(entry.ID) || seen[entry.ID] {
			return Selection{}, errors.New("path entry ID is invalid or duplicated")
		}
		seen[entry.ID] = true
		if entry.Access != AccessReadOnly && entry.Access != AccessReadWrite {
			return Selection{}, errors.New("path access must be read-only or read-write")
		}
		if entry.Type != TypeFile && entry.Type != TypeDirectory {
			return Selection{}, errors.New("path type must be file or directory")
		}
		if !utf8.ValidString(entry.Reference.Path) || entry.Reference.Path == "" || len(entry.Reference.Path) > MaximumPathBytes || strings.ContainsRune(entry.Reference.Path, 0) {
			return Selection{}, errors.New("path reference is invalid")
		}
		switch ReferenceKind(entry.Reference.Kind) {
		case ReferenceWorkspaceRelative:
			if filepath.IsAbs(entry.Reference.Path) || strings.ContainsRune(entry.Reference.Path, '\\') {
				return Selection{}, errors.New("workspace-relative path must use relative slash-separated form")
			}
			cleaned := path.Clean(entry.Reference.Path)
			if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || len(strings.Split(cleaned, "/")) > MaximumComponents {
				return Selection{}, errors.New("workspace-relative path escapes its anchor")
			}
			entry.Reference.Path = cleaned
		case ReferenceLocalAbsolute:
			if !filepath.IsAbs(entry.Reference.Path) {
				return Selection{}, errors.New("local path must be absolute")
			}
			cleaned := filepath.Clean(entry.Reference.Path)
			if cleaned == string(filepath.Separator) || len(strings.Split(strings.TrimPrefix(cleaned, string(filepath.Separator)), string(filepath.Separator))) > MaximumComponents {
				return Selection{}, errors.New("local path root is unsupported")
			}
			entry.Reference.Path = cleaned
		default:
			return Selection{}, errors.New("unsupported path reference kind")
		}
		destination := entry.Reference.Kind + "\x00" + entry.Reference.Path
		if destinations[destination] {
			return Selection{}, errors.New("path semantic destination is duplicated")
		}
		destinations[destination] = true
	}
	sort.Slice(result.Entries, func(i, j int) bool { return result.Entries[i].ID < result.Entries[j].ID })
	return result, nil
}
