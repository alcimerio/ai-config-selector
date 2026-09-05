package profileinspect

import (
	"errors"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Store has no codec or runtime collaborator. The user home is the trust root;
// .acs, profiles and direct entries are opened relative to pinned descriptors.
type Store struct{ Home string }

func (store Store) List() Result {
	result := newResult("list")
	directory, missing := store.open()
	if missing {
		result.Storage = "missing"
		return result
	}
	if directory == nil {
		return Unavailable("list")
	}
	defer directory.Close()
	result.Storage = "present"
	names, err := directory.Readdirnames(-1)
	if err != nil {
		return Unavailable("list")
	}
	sort.Strings(names)
	for _, name := range names {
		if strings.HasSuffix(name, ".json") {
			result.Entries = append(result.Entries, readEntry(directory, name))
		}
	}
	return result
}
func (store Store) Show(name string) Result {
	result := newResult("show")
	entry := newEntry(name)
	if entry.Name == nil {
		result.Entries = append(result.Entries, entry.failed("invalid_name"))
		return result
	}
	directory, missing := store.open()
	if missing {
		result.Storage = "missing"
		filename := name + ".json"
		entry.File = &filename
		result.Entries = append(result.Entries, entry.failed("missing"))
		return result
	}
	if directory == nil {
		return Unavailable("show")
	}
	defer directory.Close()
	result.Storage = "present"
	result.Entries = append(result.Entries, readEntry(directory, name+".json"))
	return result
}
func (store Store) open() (*os.File, bool) {
	home, err := os.Open(store.Home)
	if err != nil {
		return nil, false
	}
	defer home.Close()
	parent := home
	for _, component := range []string{".acs", "profiles"} {
		fd, err := unix.Openat(int(parent.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if parent != home {
			_ = parent.Close()
		}
		if err != nil {
			return nil, errors.Is(err, unix.ENOENT)
		}
		parent = os.NewFile(uintptr(fd), component)
	}
	return parent, false
}
func readEntry(directory *os.File, filename string) Entry {
	entry := newEntry(strings.TrimSuffix(filename, ".json"))
	escaped := strconv.QuoteToASCII(filename)
	escaped = escaped[1 : len(escaped)-1]
	entry.File = &escaped
	if entry.Name == nil {
		return entry.failed("invalid_name")
	}
	// A metadata check avoids opening known devices. NOFOLLOW and NONBLOCK plus
	// fstat protect the subsequent open against symlink/FIFO replacement races.
	var stat unix.Stat_t
	if err := unix.Fstatat(int(directory.Fd()), filename, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return entry.failed(readCode(err))
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return entry.failed("non_regular")
	}
	fd, err := unix.Openat(int(directory.Fd()), filename, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return entry.failed(readCode(err))
	}
	file := os.NewFile(uintptr(fd), filename)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return entry.failed("unreadable")
	}
	if !info.Mode().IsRegular() {
		return entry.failed("non_regular")
	}
	if info.Size() > maxProfileBytes {
		return entry.failed("too_large")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxProfileBytes+1))
	if err != nil {
		return entry.failed("unreadable")
	}
	if len(data) > maxProfileBytes {
		return entry.failed("too_large")
	}
	return decode(entry, data)
}
func readCode(err error) string {
	if errors.Is(err, unix.ENOENT) {
		return "missing"
	}
	if errors.Is(err, unix.ELOOP) {
		return "non_regular"
	}
	return "unreadable"
}
