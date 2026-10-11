package codexauthresource

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const (
	maximumFileCredentialSize = maximumAuthJSONSize + 4096
	maximumFileCredentials    = 4096
	credentialTemporaryPrefix = ".credential-"
)

// fileCredentialProvider is plaintext at rest and requires a durable file
// selection, even when constructed directly. It uses no desktop service.
// Store retains the separate identity lock and quarantine across a Session;
// the directory flock below serializes individual storage transactions.
type fileCredentialProvider struct {
	configPath  string
	statePath   string
	initErr     error
	mu          sync.Mutex
	pinned      bool
	rootID      [2]uint64
	directoryID [2]uint64

	// Narrow filesystem seams permit deterministic I/O failure tests.
	syncFile      func(*os.File) error
	rename        func(*privateDirectory, string, string, bool) error
	syncDirectory func(*privateDirectory) error
}

func newFileCredentialProvider() *fileCredentialProvider {
	config, configErr := providerConfigDirectory()
	state, stateErr := credentialStateDirectory()
	return &fileCredentialProvider{
		configPath: config, statePath: state, initErr: errors.Join(configErr, stateErr),
		syncFile: (*os.File).Sync,
		rename: func(directory *privateDirectory, from, to string, create bool) error {
			if create {
				return directory.renameNoReplace(from, to)
			}
			return directory.rename(from, to)
		},
		syncDirectory: (*privateDirectory).sync,
	}
}

func credentialStateDirectory() (string, error) {
	base := os.Getenv("XDG_STATE_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil || !filepath.IsAbs(home) {
			return "", ErrProviderUnavailable
		}
		base = filepath.Join(home, ".local", "state")
	}
	if !filepath.IsAbs(base) {
		return "", ErrProviderUnavailable
	}
	return filepath.Join(base, "acs"), nil
}

func directoryIdentity(directory *privateDirectory) [2]uint64 {
	return [2]uint64{directory.device, directory.inode}
}

// open validates both private directories and every ancestor without following
// symlinks. Once used, this provider refuses removed or replaced directories.
// No descriptors are retained between transactions.
func (provider *fileCredentialProvider) open() (*privateDirectory, error) {
	if provider == nil || provider.initErr != nil {
		return nil, ErrProviderUnavailable
	}
	chosen, err := readProviderSelection(provider.configPath)
	if err != nil || chosen != ProviderFile {
		return nil, ErrProviderUnavailable
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	root, err := openProviderConfigDirectory(provider.statePath, !provider.pinned)
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	defer root.file.Close()
	directory, err := openProviderConfigDirectory(filepath.Join(provider.statePath, "credentials"), !provider.pinned)
	if err != nil {
		return nil, ErrProviderUnavailable
	}
	if provider.pinned && (provider.rootID != directoryIdentity(root) || provider.directoryID != directoryIdentity(directory)) {
		_ = directory.file.Close()
		return nil, ErrProviderUnavailable
	}
	provider.pinned = true
	provider.rootID, provider.directoryID = directoryIdentity(root), directoryIdentity(directory)
	return directory, nil
}

func (provider *fileCredentialProvider) withDirectory(ctx context.Context, operation func(*privateDirectory) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	directory, err := provider.open()
	if err != nil {
		return err
	}
	defer directory.file.Close()
	// Lock the directory inode itself: no replaceable lock file or lock-file
	// cleanup can split transaction ownership. Closing releases the flock.
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := unix.Flock(int(directory.file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			return ErrProviderUnavailable
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	// Rewalk after waiting: reject permission, selection and ancestor changes,
	// including replacement of the inode on which we acquired the lock.
	checked, err := provider.open()
	if err != nil {
		return err
	}
	_ = checked.file.Close()
	if directoryIdentity(checked) != directoryIdentity(directory) {
		return ErrProviderUnavailable
	}
	if err := operation(directory); err != nil {
		return err
	}
	checked, err = provider.open()
	if err != nil {
		return err
	}
	if checked.file.Close() != nil {
		return ErrProviderUnavailable
	}
	return nil
}

func (provider *fileCredentialProvider) Metadata(ctx context.Context, name CredentialRef) (IdentityMetadata, bool, error) {
	record, exists, err := provider.Load(ctx, name)
	defer clearBytes(record.Auth)
	return record.Metadata, exists, err
}

func (provider *fileCredentialProvider) Load(ctx context.Context, name CredentialRef) (credentialRecord, bool, error) {
	var record credentialRecord
	var exists bool
	err := provider.withDirectory(ctx, func(directory *privateDirectory) (err error) {
		record, exists, err = loadFileCredential(directory, name)
		return err
	})
	if err != nil {
		clearBytes(record.Auth)
		return credentialRecord{}, false, err
	}
	return record, exists, nil
}

func loadFileCredential(directory *privateDirectory, name CredentialRef) (credentialRecord, bool, error) {
	if _, err := ParseCredentialRef(string(name)); err != nil {
		return credentialRecord{}, false, ErrInvalidCredentialRef
	}
	leaf := string(name) + ".json"
	file, err := directory.open(leaf, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return credentialRecord{}, false, nil
	}
	if err != nil {
		return credentialRecord{}, false, ErrProviderUnavailable
	}
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(int(file.Fd()), &before) != nil || !validCredentialFile(before, false) {
		return credentialRecord{}, false, ErrProviderUnavailable
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximumFileCredentialSize+1))
	defer clearBytes(contents)
	if err != nil || len(contents) > maximumFileCredentialSize || int64(len(contents)) != before.Size ||
		unix.Fstatat(int(directory.file.Fd()), leaf, &after, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		!sameCredentialFile(before, after) {
		return credentialRecord{}, false, ErrProviderUnavailable
	}
	// Exact field names prevent encoding/json's case-folded aliases. Derive
	// metadata from the same payload instead of trusting a separate sidecar.
	var fields map[string]json.RawMessage
	if rejectDuplicateJSONKeys(contents) != nil || json.Unmarshal(contents, &fields) != nil || len(fields) != 2 || fields["version"] == nil || fields["auth"] == nil {
		return credentialRecord{}, false, ErrProviderUnavailable
	}
	auth, err := decodeEnvelope(contents)
	if err != nil {
		return credentialRecord{}, false, ErrProviderUnavailable
	}
	metadata, err := validateAuthJSON(name, auth)
	if err != nil || validateMetadata(metadata) != nil {
		clearBytes(auth)
		return credentialRecord{}, false, ErrProviderUnavailable
	}
	return credentialRecord{Metadata: metadata, Auth: auth}, true, nil
}

func validCredentialFile(stat unix.Stat_t, temporary bool) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && stat.Mode&0o7777 == 0o600 &&
		stat.Uid == uint32(os.Geteuid()) && stat.Nlink == 1 &&
		stat.Size >= 0 && (temporary || stat.Size > 0) && stat.Size <= maximumFileCredentialSize
}

func sameCredentialFile(before, after unix.Stat_t) bool {
	return before.Dev == after.Dev && before.Ino == after.Ino && before.Mode == after.Mode &&
		before.Uid == after.Uid && before.Nlink == after.Nlink && before.Size == after.Size &&
		before.Mtim == after.Mtim && before.Ctim == after.Ctim
}

func (provider *fileCredentialProvider) Create(ctx context.Context, record credentialRecord) error {
	return provider.write(ctx, record, true)
}

func (provider *fileCredentialProvider) Replace(ctx context.Context, record credentialRecord) error {
	return provider.write(ctx, record, false)
}

func (provider *fileCredentialProvider) write(ctx context.Context, record credentialRecord, create bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	metadata, err := validateAuthJSON(record.Metadata.Name, record.Auth)
	if err != nil || validateMetadata(record.Metadata) != nil || metadata != record.Metadata {
		return ErrUnsupportedAuth
	}
	contents, err := encodeEnvelope(record.Auth)
	if err != nil {
		return ErrUnsupportedAuth
	}
	defer clearBytes(contents)
	if len(contents) > maximumFileCredentialSize {
		return ErrUnsupportedAuth
	}
	return provider.withDirectory(ctx, func(directory *privateDirectory) error {
		previous, exists, err := loadFileCredential(directory, record.Metadata.Name)
		defer clearBytes(previous.Auth)
		if err != nil {
			return err
		}
		if create && exists {
			return ErrIdentityExists
		}
		if !create && !exists {
			return ErrProviderUnavailable
		}
		if !create && previous.Metadata != record.Metadata {
			return ErrUnsupportedAuth
		}
		file, temporary, err := directory.createTemporary(credentialTemporaryPrefix)
		if err != nil {
			return ErrProviderUnavailable
		}
		defer file.Close()
		defer directory.unlink(temporary)
		// Set exactly 0600 even under a restrictive umask. Existing files and
		// directories are only checked, never repaired.
		if file.Chmod(0o600) != nil {
			return ErrProviderUnavailable
		}
		if count, err := file.Write(contents); err != nil || count != len(contents) {
			return ErrProviderUnavailable
		}
		if provider.syncFile(file) != nil || file.Close() != nil {
			return ErrProviderUnavailable
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := provider.rename(directory, temporary, string(record.Metadata.Name)+".json", create); err != nil {
			if create && errors.Is(err, unix.EEXIST) {
				return ErrIdentityExists
			}
			return ErrProviderUnavailable
		}
		// Failure here is an uncertain commit, never success or an attempt to
		// roll back. Store's refresh lifecycle retains quarantine on this error.
		if provider.syncDirectory(directory) != nil {
			return ErrProviderUnavailable
		}
		return nil
	})
}

func (provider *fileCredentialProvider) List(ctx context.Context) ([]IdentityMetadata, error) {
	identities := []IdentityMetadata{}
	err := provider.withDirectory(ctx, func(directory *privateDirectory) error {
		entries, err := directory.file.ReadDir(maximumFileCredentials + 1)
		if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > maximumFileCredentials {
			return ErrProviderUnavailable
		}
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			leaf := entry.Name()
			if strings.HasPrefix(leaf, credentialTemporaryPrefix) {
				// A crash can leave a private partial temporary. It is never
				// promoted or interpreted as a committed identity.
				suffix, err := hex.DecodeString(strings.TrimPrefix(leaf, credentialTemporaryPrefix))
				var stat unix.Stat_t
				if err != nil || len(suffix) != 16 || unix.Fstatat(int(directory.file.Fd()), leaf, &stat, unix.AT_SYMLINK_NOFOLLOW) != nil || !validCredentialFile(stat, true) {
					return ErrProviderUnavailable
				}
				continue
			}
			if !strings.HasSuffix(leaf, ".json") {
				return ErrProviderUnavailable
			}
			record, exists, err := loadFileCredential(directory, CredentialRef(strings.TrimSuffix(leaf, ".json")))
			clearBytes(record.Auth)
			if err != nil || !exists {
				return ErrProviderUnavailable
			}
			identities = append(identities, record.Metadata)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(identities, func(i, j int) bool { return identities[i].Name < identities[j].Name })
	return identities, nil
}

func (provider *fileCredentialProvider) Delete(ctx context.Context, name CredentialRef) error {
	return provider.withDirectory(ctx, func(directory *privateDirectory) error {
		record, exists, err := loadFileCredential(directory, name)
		clearBytes(record.Auth)
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if exists && directory.unlink(string(name)+".json") != nil {
			return ErrProviderUnavailable
		}
		if provider.syncDirectory(directory) != nil {
			return ErrProviderUnavailable
		}
		return nil
	})
}
