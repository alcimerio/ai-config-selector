package codexauthresource

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const providerSelectionFilename = "credential-provider.json"
const maximumProviderSelectionSize = 256

type providerSelection struct {
	Version  int        `json:"version"`
	Provider ProviderID `json:"provider"`
}

func readProviderSelection(path string) (ProviderID, error) {
	directory, err := openProviderConfigDirectory(path, false)
	if err != nil {
		return "", err
	}
	defer directory.file.Close()
	return readProviderSelectionAt(directory)
}

func readProviderSelectionAt(directory *privateDirectory) (ProviderID, error) {
	file, err := directory.open(providerSelectionFilename, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrProviderNotSelected
	}
	if err != nil {
		return "", ErrProviderChoice
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() <= 0 || info.Size() > maximumProviderSelectionSize {
		return "", ErrProviderChoice
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) || native.Nlink != 1 || native.Mode&0o7777 != 0o600 {
		return "", ErrProviderChoice
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumProviderSelectionSize+1))
	if err != nil || len(contents) > maximumProviderSelectionSize || rejectDuplicateJSONKeys(contents) != nil {
		return "", ErrProviderChoice
	}
	// Require exact field names as well as uniqueness. A struct decoder alone
	// accepts case-folded aliases, including two spellings of "provider".
	var fields map[string]json.RawMessage
	if json.Unmarshal(contents, &fields) != nil || len(fields) != 2 {
		return "", ErrProviderChoice
	}
	var choice providerSelection
	if json.Unmarshal(fields["version"], &choice.Version) != nil || choice.Version != 1 ||
		json.Unmarshal(fields["provider"], &choice.Provider) != nil || (choice.Provider != ProviderFile && choice.Provider != ProviderSecretService) {
		return "", ErrProviderChoice
	}
	return choice.Provider, nil
}

func writeProviderSelection(path string, id ProviderID) error {
	if id != ProviderFile && id != ProviderSecretService {
		return ErrProviderChoice
	}
	directory, err := openProviderConfigDirectory(path, true)
	if err != nil {
		return err
	}
	defer directory.file.Close()
	if chosen, err := readProviderSelectionAt(directory); !errors.Is(err, ErrProviderNotSelected) {
		return matchProviderSelection(directory, chosen, id, err)
	}
	contents, err := json.Marshal(providerSelection{Version: 1, Provider: id})
	if err != nil {
		return ErrProviderChoice
	}
	file, name, err := directory.createTemporary(".provider-")
	if err != nil {
		return ErrProviderChoice
	}
	defer directory.unlink(name)
	defer file.Close()
	if err := file.Chmod(0o600); err != nil {
		return ErrProviderChoice
	}
	if _, err := file.Write(contents); err != nil {
		return ErrProviderChoice
	}
	if err := file.Sync(); err != nil {
		return ErrProviderChoice
	}
	if err := file.Close(); err != nil {
		return ErrProviderChoice
	}
	if err := directory.renameNoReplace(name, providerSelectionFilename); err != nil {
		if errors.Is(err, os.ErrExist) {
			chosen, readErr := readProviderSelectionAt(directory)
			return matchProviderSelection(directory, chosen, id, readErr)
		}
		return ErrProviderChoice
	}
	if err := directory.sync(); err != nil {
		return ErrProviderChoice
	}
	return nil
}

func matchProviderSelection(directory *privateDirectory, chosen, requested ProviderID, err error) error {
	if err != nil {
		return err
	}
	if chosen != requested {
		return ErrProviderConflict
	}
	// Also finish a previous selection whose rename succeeded but whose caller
	// did not observe a successful directory sync.
	if err := directory.sync(); err != nil {
		return ErrProviderChoice
	}
	return nil
}

// Walk from a trusted root using no-follow descriptors. Creation is explicit;
// provider-selection reads never provision storage. The final directory must
// be private; unsafe existing permissions are not repaired.
func openProviderConfigDirectory(path string, create bool) (*privateDirectory, error) {
	if !filepath.IsAbs(path) {
		return nil, ErrProviderChoice
	}
	path = filepath.Clean(path)
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrProviderChoice
	}
	defer func() { _ = unix.Close(fd) }()
	components := strings.Split(strings.TrimPrefix(path, "/"), "/")
	var native unix.Stat_t
	for index, part := range components {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && create {
			if err := unix.Mkdirat(fd, part, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
				return nil, ErrProviderChoice
			}
			if unix.Fsync(fd) != nil {
				return nil, ErrProviderChoice
			}
			next, err = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		}
		if errors.Is(err, unix.ENOENT) {
			return nil, ErrProviderNotSelected
		}
		if err != nil {
			return nil, ErrProviderChoice
		}
		_ = unix.Close(fd)
		fd = next
		if unix.Fstat(fd, &native) != nil {
			return nil, ErrProviderChoice
		}
		if index == len(components)-1 {
			if native.Uid != uint32(os.Geteuid()) || native.Mode&0o7777 != 0o700 {
				return nil, ErrProviderChoice
			}
		} else {
			// Root-owned sticky ancestors (e.g. /tmp) protect an owned child
			// from rename/removal by other users. Other writable parents fail.
			stickyRoot := native.Uid == 0 && native.Mode&unix.S_ISVTX != 0
			if (native.Uid != 0 && native.Uid != uint32(os.Geteuid())) || (native.Mode&0o022 != 0 && !stickyRoot) {
				return nil, ErrProviderChoice
			}
		}
	}
	file := os.NewFile(uintptr(fd), "credential provider configuration")
	fd = -1 // file now owns the descriptor.
	return &privateDirectory{file: file, physicalPath: path, device: uint64(native.Dev), inode: uint64(native.Ino)}, nil
}
