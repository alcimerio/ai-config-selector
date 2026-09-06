// Package codexauthresource owns the durable, non-executing part of named
// Codex authentication. It deliberately imports neither launch nor session.
package codexauthresource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

type credentialRecord struct {
	Metadata IdentityMetadata
	Auth     []byte
}

type credentialProvider interface {
	Metadata(context.Context, CredentialRef) (IdentityMetadata, bool, error)
	Create(context.Context, credentialRecord) error
	Replace(context.Context, credentialRecord) error
	List(context.Context) ([]IdentityMetadata, error)
	Load(context.Context, CredentialRef) (credentialRecord, bool, error)
	Delete(context.Context, CredentialRef) error
}

type identityLocker interface {
	TryLock(CredentialRef) (identityLock, error)
}
type identityLock interface{ Release() error }

// Store is the concrete durable resource authority. Its dependencies and
// records are private so neither recipes nor process orchestration can obtain
// credential bytes, provider handles, locks, or marker writers.
type Store struct {
	provider credentialProvider
	locks    identityLocker
	markers  bindingQuarantine
}

// Binding retains one identity lock and, for Status, the validated durable
// record. It is opaque outside this package.
type Binding struct {
	store     *Store
	name      CredentialRef
	lock      identityLock
	record    credentialRecord
	hasRecord bool
}

// RecoveryBinding is deliberately separate from an active Binding. Recovery
// code may inspect marker state but cannot create an identity or acquire an
// authentication payload for a new login.
type RecoveryBinding struct {
	store  *Store
	name   CredentialRef
	lock   identityLock
	marker quarantineMarker
}

// New creates the production durable authority from already validated private
// directories. Session creation/removal stays above this layer.
func New(locksDirectory, quarantineDirectory string) (*Store, error) {
	locks := newFileIdentityLocker(locksDirectory)
	markers := newFileBindingQuarantine(quarantineDirectory)
	if locks.initErr != nil || markers.initErr != nil {
		return nil, ErrProviderUnavailable
	}
	return &Store{provider: newKeychainProvider(), locks: locks, markers: markers}, nil
}

func (store *Store) acquire(ctx context.Context, name CredentialRef, allowMarker bool) (*Binding, error) {
	if store == nil || store.provider == nil || store.locks == nil || store.markers == nil {
		return nil, ErrProviderUnavailable
	}
	locked, err := store.locks.TryLock(name)
	if err != nil {
		return nil, err
	}
	if !allowMarker {
		_, exists, inspectErr := store.markers.Inspect(ctx, name)
		if inspectErr != nil {
			_ = locked.Release()
			return nil, fmt.Errorf("inspect Codex authentication binding %q: %w", name, inspectErr)
		}
		if exists {
			_ = locked.Release()
			return nil, fmt.Errorf("%w: %q", ErrIdentityBusy, name)
		}
	}
	return &Binding{store: store, name: name, lock: locked}, nil
}

// AcquireLogin obtains identity authority and checks existence before an upper
// layer may prepare an executable or Session.
func (store *Store) AcquireLogin(ctx context.Context, value string) (*Binding, error) {
	name, err := ParseCredentialRef(value)
	if err != nil {
		return nil, err
	}
	binding, err := store.acquire(ctx, name, false)
	if err != nil {
		return nil, err
	}
	if _, exists, err := store.provider.Metadata(ctx, name); err != nil {
		_ = binding.Release()
		return nil, fmt.Errorf("inspect Codex authentication identity %q: %w", name, err)
	} else if exists {
		_ = binding.Release()
		return nil, fmt.Errorf("%w: %q", ErrIdentityExists, name)
	}
	return binding, nil
}

// AcquireStatus obtains the record before executable preparation and keeps its
// credential payload private for projection/finalization operations.
func (store *Store) AcquireStatus(ctx context.Context, value string) (*Binding, IdentityMetadata, error) {
	name, err := ParseCredentialRef(value)
	if err != nil {
		return nil, IdentityMetadata{}, err
	}
	binding, err := store.acquire(ctx, name, false)
	if err != nil {
		return nil, IdentityMetadata{}, err
	}
	record, exists, err := store.provider.Load(ctx, name)
	if err != nil {
		_ = binding.Release()
		return nil, IdentityMetadata{}, fmt.Errorf("load Codex authentication identity %q: %w", name, err)
	}
	if !exists {
		_ = binding.Release()
		return nil, IdentityMetadata{}, fmt.Errorf("%w: %q", ErrIdentityNotFound, name)
	}
	binding.record, binding.hasRecord = record, true
	return binding, record.Metadata, nil
}

// AcquireRecovery locks an existing durable marker. It intentionally exposes
// no provider record and therefore cannot be used to commit a new login.
func (store *Store) AcquireRecovery(ctx context.Context, value string) (*RecoveryBinding, error) {
	name, err := ParseCredentialRef(value)
	if err != nil {
		return nil, err
	}
	binding, err := store.acquire(ctx, name, true)
	if err != nil {
		return nil, err
	}
	marker, exists, err := store.markers.Inspect(ctx, name)
	if err != nil {
		_ = binding.Release()
		return nil, err
	}
	if !exists {
		_ = binding.Release()
		return nil, nil
	}
	return &RecoveryBinding{store: store, name: name, lock: binding.lock, marker: marker}, nil
}

func (binding *Binding) Name() CredentialRef {
	if binding == nil {
		return ""
	}
	return binding.name
}
func (binding *Binding) Release() error {
	if binding == nil || binding.lock == nil {
		return nil
	}
	locked := binding.lock
	ClearBytes(binding.record.Auth)
	binding.lock, binding.record.Auth = nil, nil
	return locked.Release()
}

func (binding *RecoveryBinding) Release() error {
	if binding == nil || binding.lock == nil {
		return nil
	}
	locked := binding.lock
	binding.lock = nil
	return locked.Release()
}

// Project writes only a validated durable record into the supplied private
// home. Credential bytes never leave the Store API.
func (binding *Binding) Project(home string) error {
	if binding == nil || !binding.hasRecord {
		return ErrProjectedAuthInvalid
	}
	if err := validateMetadata(binding.record.Metadata); err != nil {
		return ErrProjectedAuthInvalid
	}
	validated, err := ValidateAuthJSON(binding.name, binding.record.Auth)
	if err != nil || validated != binding.record.Metadata {
		return ErrProjectedAuthInvalid
	}
	codexHome := filepath.Join(home, ".codex")
	if err := os.Mkdir(codexHome, 0o700); err != nil {
		return ErrProjectedAuthInvalid
	}
	configuration := "cli_auth_credentials_store = \"file\"\nforced_login_method = \"chatgpt\"\n"
	if binding.record.Metadata.Workspace != "" {
		configuration += fmt.Sprintf("forced_chatgpt_workspace_id = %q\n", binding.record.Metadata.Workspace)
	}
	if err := writeExclusivePrivateFile(filepath.Join(codexHome, "config.toml"), []byte(configuration)); err != nil {
		return ErrProjectedAuthInvalid
	}
	if err := writeExclusivePrivateFile(filepath.Join(codexHome, "auth.json"), binding.record.Auth); err != nil {
		return ErrProjectedAuthInvalid
	}
	return nil
}

// CommitLogin validates and creates only. The input is a private projection
// read by the upper Session lifecycle and is not returned to it.
func (binding *Binding) CommitLogin(ctx context.Context, auth []byte) (IdentityMetadata, error) {
	if binding == nil || binding.hasRecord {
		return IdentityMetadata{}, ErrProviderUnavailable
	}
	metadata, err := ValidateAuthJSON(binding.name, auth)
	if err != nil {
		return IdentityMetadata{}, err
	}
	if err := binding.store.provider.Create(ctx, credentialRecord{Metadata: metadata, Auth: auth}); err != nil {
		return IdentityMetadata{}, fmt.Errorf("store Codex authentication identity %q: %w", binding.name, err)
	}
	return metadata, nil
}

// FinalizeStatus reads a projection and replaces only a changed, valid record
// with precisely the acquired identity metadata.
func (binding *Binding) FinalizeStatus(ctx context.Context, root string) (BindingDisposition, error) {
	if binding == nil || !binding.hasRecord {
		return QuarantinedUncertain, ErrProviderUnavailable
	}
	projected, err := readSessionAuthFile(root)
	if err != nil {
		return DiscardedProjection, ErrProjectedAuthInvalid
	}
	defer ClearBytes(projected)
	metadata, err := ValidateAuthJSON(binding.name, projected)
	if err != nil || metadata != binding.record.Metadata {
		return DiscardedProjection, ErrProjectedAuthInvalid
	}
	if bytes.Equal(projected, binding.record.Auth) {
		return DiscardedProjection, nil
	}
	if err := binding.store.provider.Replace(ctx, credentialRecord{Metadata: metadata, Auth: projected}); err != nil {
		return QuarantinedUncertain, ErrBindingQuarantined
	}
	return CommittedSameIdentityRefresh, nil
}

func writeExclusivePrivateFile(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	remove, closed := true, false
	defer func() {
		if !closed {
			_ = file.Close()
		}
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed, remove = true, false
	return nil
}

func readSessionAuthFile(root string) ([]byte, error) {
	directory, err := openPrivateDirectory(root)
	if err != nil {
		return nil, ErrUnsupportedAuth
	}
	defer directory.Close()
	home, err := openPrivateChildDirectory(directory, "home")
	if err != nil {
		return nil, ErrUnsupportedAuth
	}
	defer home.Close()
	codexHome, err := openPrivateChildDirectory(home, ".codex")
	if err != nil {
		return nil, ErrUnsupportedAuth
	}
	defer codexHome.Close()
	descriptor, err := unix.Openat(int(codexHome.Fd()), "auth.json", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnsupportedAuth
	}
	file := os.NewFile(uintptr(descriptor), "auth.json")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, ErrUnsupportedAuth
	}
	defer file.Close()
	return readPrivateRegularDescriptor(file, MaximumAuthJSONSize)
}

func openPrivateDirectory(path string) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	return privateDirectoryFile(descriptor, path)
}

func openPrivateChildDirectory(parent *os.File, name string) (*os.File, error) {
	descriptor, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	return privateDirectoryFile(descriptor, name)
}

func privateDirectoryFile(descriptor int, name string) (*os.File, error) {
	directory := os.NewFile(uintptr(descriptor), name)
	if directory == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("open private directory")
	}
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		_ = directory.Close()
		return nil, errors.New("invalid private directory")
	}
	if native, ok := info.Sys().(*syscall.Stat_t); !ok || native.Uid != uint32(os.Geteuid()) {
		_ = directory.Close()
		return nil, errors.New("invalid private directory")
	}
	return directory, nil
}

func readPrivateRegularDescriptor(file *os.File, maximumSize int64) ([]byte, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > maximumSize {
		return nil, ErrUnsupportedAuth
	}
	contents := make([]byte, info.Size())
	read, err := file.Read(contents)
	if err != nil || int64(read) != info.Size() {
		ClearBytes(contents)
		return nil, ErrUnsupportedAuth
	}
	return contents, nil
}
