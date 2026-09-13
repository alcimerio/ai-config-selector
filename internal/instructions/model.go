// Package instructions owns bounded, target-neutral instruction references.
package instructions

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	SourceID          = "acs-instructions"
	MaxEntries        = 64
	MaxFileBytes      = 128 << 10
	MaxAggregateBytes = 1 << 20
	MaxPathBytes      = 1024
	MaxDepth          = 16
)

type Reference struct {
	Source       string `json:"source"`
	RelativePath string `json:"relativePath"`
}
type Bundle struct {
	Reference Reference
	Content   []byte
}

// ValidateSelection enforces the portable identity contract without touching the filesystem.
func ValidateSelection(refs []Reference) error {
	if len(refs) > MaxEntries {
		return fmt.Errorf("instructions selection exceeds %d entries", MaxEntries)
	}
	seen := map[Reference]bool{}
	keys := map[string]Reference{}
	paths := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.Source != SourceID {
			return errors.New("unsupported instruction source")
		}
		p, err := clean(r.RelativePath)
		if err != nil {
			return err
		}
		if p != r.RelativePath {
			return errors.New("instruction path is not canonical")
		}
		if seen[r] {
			return errors.New("duplicate instruction reference")
		}
		seen[r] = true
		key := norm.NFC.String(cases.Fold().String(p))
		if previous, exists := keys[key]; exists {
			return fmt.Errorf("instruction destination collision between %q and %q", previous.RelativePath, p)
		}
		keys[key] = r
		paths = append(paths, key)
	}
	for i, left := range paths {
		for j, right := range paths {
			if i != j && strings.HasPrefix(right, left+"/") {
				return errors.New("instruction destination has a file and directory collision")
			}
		}
	}
	return nil
}
func clean(value string) (string, error) {
	if value == "" || len(value) > MaxPathBytes || !utf8.ValidString(value) || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "\xef\xbb\xbf") {
		return "", errors.New("invalid instruction relative path")
	}
	parts := strings.Split(value, "/")
	if len(parts) > MaxDepth {
		return "", errors.New("instruction path exceeds depth limit")
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || strings.HasPrefix(p, ".") {
			return "", errors.New("invalid instruction path component")
		}
		for _, r := range p {
			if unicode.IsControl(r) {
				return "", errors.New("invalid instruction path text")
			}
		}
	}
	if !strings.HasSuffix(value, ".md") {
		return "", errors.New("instruction files must use the .md extension")
	}
	return filepath.ToSlash(filepath.Clean(filepath.FromSlash(value))), nil
}
func Encode(refs []Reference) (json.RawMessage, error) {
	if refs == nil {
		refs = []Reference{}
	}
	if err := ValidateSelection(refs); err != nil {
		return nil, err
	}
	ordered := make([]Reference, len(refs))
	copy(ordered, refs)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].RelativePath < ordered[j].RelativePath })
	return json.Marshal(ordered)
}
func Decode(raw json.RawMessage) ([]Reference, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("instruction selection is not valid UTF-8")
	}
	if !validJSONSurrogateEscapes(raw) {
		return nil, errors.New("instruction selection contains an unpaired Unicode surrogate")
	}
	var refs []Reference
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&refs); err != nil {
		return nil, err
	}
	if refs == nil {
		return nil, errors.New("expected an array, got null")
	}
	var extra any
	if !errors.Is(d.Decode(&extra), io.EOF) {
		return nil, errors.New("unexpected data after instruction selection")
	}
	if err := ValidateSelection(refs); err != nil {
		return nil, err
	}
	return refs, nil
}

// validJSONSurrogateEscapes prevents encoding/json's replacement of lone
// UTF-16 surrogates with U+FFFD from silently changing a selected identity.
func validJSONSurrogateEscapes(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		for i++; i < len(raw); i++ {
			switch raw[i] {
			case '"':
				goto nextString
			case '\\':
				i++
				if i >= len(raw) {
					return true
				} // JSON decoder reports malformed syntax.
				if raw[i] != 'u' {
					continue
				}
				if i+4 >= len(raw) {
					return true
				}
				value, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
				if err != nil {
					return true
				}
				i += 4
				if value >= 0xDC00 && value <= 0xDFFF {
					return false
				}
				if value >= 0xD800 && value <= 0xDBFF {
					if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
						return false
					}
					low, lowErr := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
					if lowErr != nil || low < 0xDC00 || low > 0xDFFF {
						return false
					}
					i += 6
				}
			}
		}
		return true // Unterminated strings are rejected by the JSON decoder.
	nextString:
	}
	return true
}

// Resolve opens every selected file beneath home/.acs/instructions, rejects links and unsafe ownership/modes, and captures immutable bounded bytes.
func Resolve(home string, refs []Reference) ([]Bundle, error) {
	if err := ValidateSelection(refs); err != nil {
		return nil, err
	}
	if len(refs) == 0 {
		return []Bundle{}, nil
	}
	homeFD, err := unix.Open(home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("selected instruction source is unavailable")
	}
	defer unix.Close(homeFD)
	uid := uint32(os.Geteuid())
	acsFD, err := unix.Openat(homeFD, ".acs", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("selected instruction source is unavailable")
	}
	defer unix.Close(acsFD)
	var acsStat unix.Stat_t
	err = unix.Fstat(acsFD, &acsStat)
	if err != nil || !ownedSafeStat(&acsStat, uid) {
		return nil, errors.New("selected instruction source ownership or permissions are unsafe")
	}
	rootFD, err := unix.Openat(acsFD, "instructions", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("selected instruction source is unavailable")
	}
	defer unix.Close(rootFD)
	var rootStat unix.Stat_t
	err = unix.Fstat(rootFD, &rootStat)
	if err != nil || !ownedSafeStat(&rootStat, uid) {
		return nil, errors.New("selected instruction source ownership or permissions are unsafe")
	}
	result := make([]Bundle, 0, len(refs))
	total := 0
	for _, ref := range refs {
		parts := strings.Split(ref.RelativePath, "/")
		dirFD, dupErr := unix.Dup(rootFD)
		if dupErr != nil {
			return nil, errors.New("selected instruction path cannot be opened")
		}
		for _, part := range parts[:len(parts)-1] {
			next, e := unix.Openat(dirFD, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			unix.Close(dirFD)
			if e != nil {
				return nil, errors.New("selected instruction path is unsafe")
			}
			dirFD = next
			var stat unix.Stat_t
			e = unix.Fstat(dirFD, &stat)
			if e != nil || !ownedSafeStat(&stat, uid) {
				unix.Close(dirFD)
				return nil, errors.New("selected instruction path ownership or permissions are unsafe")
			}
		}
		fd, e := unix.Openat(dirFD, parts[len(parts)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
		unix.Close(dirFD)
		if e != nil {
			return nil, errors.New("selected instruction file is unsafe or unavailable")
		}
		f := os.NewFile(uintptr(fd), "instruction-file")
		before, e := f.Stat()
		if e != nil || !before.Mode().IsRegular() || before.Size() > MaxFileBytes || !ownedSafe(before, uid) {
			f.Close()
			return nil, errors.New("selected instruction file is unsafe or exceeds limits")
		}
		data, e := captureVerified(f, func(file *os.File) ([]byte, error) { return io.ReadAll(io.LimitReader(file, MaxFileBytes+1)) })
		after, ae := f.Stat()
		ce := f.Close()
		if e != nil || ae != nil || ce != nil || len(data) > MaxFileBytes || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || before.Mode() != after.Mode() || !ownedSafe(after, uid) {
			return nil, errors.New("selected instruction file changed or exceeds limits")
		}
		if !validContent(data) {
			return nil, errors.New("selected instruction file is not valid UTF-8 text")
		}
		total += len(data)
		if total > MaxAggregateBytes {
			return nil, errors.New("instruction selection exceeds aggregate size limit")
		}
		result = append(result, Bundle{Reference: ref, Content: append([]byte(nil), data...)})
	}
	return result, nil
}

// captureVerified compares two bounded reads from the same open descriptor. It
// detects in-place changes during capture even when the pathname is unchanged.
func captureVerified(file *os.File, readPass func(*os.File) ([]byte, error)) ([]byte, error) {
	first, err := readPass(file)
	if err != nil {
		return nil, err
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	second, err := readPass(file)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(first, second) {
		return nil, errors.New("instruction changed during capture")
	}
	return first, nil
}
func ownedSafeStat(st *unix.Stat_t, uid uint32) bool {
	return st != nil && st.Uid == uid && st.Mode&0022 == 0
}
func ownedSafe(info os.FileInfo, uid uint32) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uid && info.Mode().Perm()&0022 == 0
}
func validContent(data []byte) bool {
	if len(data) == 0 || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 || bytes.HasPrefix(data, []byte("\xef\xbb\xbf")) {
		return false
	}
	for _, r := range string(data) {
		if unicode.IsControl(r) && r != '\n' && r != '\r' && r != '\t' {
			return false
		}
	}
	return true
}
func DestinationName(ref Reference) string {
	h := sha256.Sum256([]byte(ref.Source + "\x00" + ref.RelativePath))
	return "acs-instruction-" + hex.EncodeToString(h[:]) + ".md"
}

// Discover lists bounded relative .md identities without reading file bodies.
func Discover(home string) ([]Bundle, error) {
	uid := uint32(os.Geteuid())
	homeFD, err := unix.Open(home, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errors.New("instruction source cannot be inspected")
	}
	homeDir := os.NewFile(uintptr(homeFD), "trusted-home")
	defer homeDir.Close()
	acsDir, err := openOwnedDirectory(homeDir, ".acs", uid)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return []Bundle{}, nil
		}
		return nil, errors.New("instruction source is unsafe")
	}
	defer acsDir.Close()
	rootDir, err := openOwnedDirectory(acsDir, "instructions", uid)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return []Bundle{}, nil
		}
		return nil, errors.New("instruction source is unsafe")
	}
	defer rootDir.Close()
	var result []Bundle
	visited := 0
	var visit func(*os.File, string, int) error
	visit = func(dir *os.File, prefix string, depth int) error {
		for {
			remaining := 4097 - visited
			if remaining <= 0 {
				return errors.New("instruction catalog exceeds traversal limit")
			}
			batchSize := 128
			if remaining < batchSize {
				batchSize = remaining
			}
			entries, e := dir.ReadDir(batchSize)
			if e != nil && !errors.Is(e, io.EOF) {
				return errors.New("instruction catalog cannot be inspected")
			}
			if len(entries) == 0 {
				return nil
			}
			for _, entry := range entries {
				visited++
				if visited > 4096 {
					return errors.New("instruction catalog exceeds traversal limit")
				}
				relative := entry.Name()
				if prefix != "" {
					relative = prefix + "/" + entry.Name()
				}
				if entry.Type()&os.ModeSymlink != 0 {
					continue
				}
				if entry.IsDir() {
					if depth >= MaxDepth {
						continue
					}
					child, e := openOwnedDirectory(dir, entry.Name(), uid)
					if e != nil {
						return errors.New("instruction catalog directory is unsafe")
					}
					e = visit(child, relative, depth+1)
					child.Close()
					if e != nil {
						return e
					}
					continue
				}
				if !entry.Type().IsRegular() || !strings.HasSuffix(entry.Name(), ".md") {
					continue
				}
				if _, e := clean(relative); e == nil {
					result = append(result, Bundle{Reference: Reference{Source: SourceID, RelativePath: relative}})
				}
			}
			if e != nil {
				return nil
			}
		}
	}
	if err := visit(rootDir, "", 1); err != nil {
		return nil, err
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Reference.RelativePath < result[j].Reference.RelativePath })
	return result, nil
}

func openOwnedDirectory(parent *os.File, name string, uid uint32) (*os.File, error) {
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), "instruction-directory")
	info, err := directory.Stat()
	if err != nil || !ownedSafe(info, uid) {
		directory.Close()
		return nil, errors.New("unsafe directory")
	}
	return directory, nil
}
