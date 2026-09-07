package sessionops

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

type privateDirectory struct {
	file   *os.File
	path   string
	dev    uint64
	ino    uint64
	parent *privateDirectory
	leaf   string
}

func pinPrivateChild(parent *privateDirectory, name string, create bool) (*privateDirectory, error) {
	if parent == nil || !validLeaf(name) || parent.validate() != nil {
		return nil, errors.New("invalid private directory")
	}
	if create {
		if err := unix.Mkdirat(int(parent.file.Fd()), name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, err
		}
	}
	descriptor, err := unix.Openat(int(parent.file.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("open private directory")
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		file.Close()
		return nil, errors.New("invalid private directory")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) {
		file.Close()
		return nil, errors.New("invalid private directory")
	}
	return &privateDirectory{
		file: file, path: filepath.Join(parent.path, name), dev: uint64(native.Dev), ino: uint64(native.Ino),
		parent: parent, leaf: name,
	}, nil
}

type privateStorage struct {
	base, records, capabilities, locks *privateDirectory
}

func pinPrivateDirectory(path string, create bool) (*privateDirectory, error) {
	if create {
		if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return nil, err
	}
	physical := filepath.Join(parent, filepath.Base(absolute))
	descriptor, err := unix.Open(physical, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), physical)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("open private directory")
	}
	info, err := file.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		file.Close()
		return nil, errors.New("invalid private directory")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) {
		file.Close()
		return nil, errors.New("invalid private directory")
	}
	return &privateDirectory{file: file, path: physical, dev: uint64(native.Dev), ino: uint64(native.Ino)}, nil
}

func (directory *privateDirectory) validate() error {
	if directory == nil || directory.file == nil {
		return errors.New("private directory unavailable")
	}
	if directory.parent != nil {
		if directory.parent.validate() != nil {
			return errors.New("private directory changed")
		}
		var info unix.Stat_t
		if err := unix.Fstatat(int(directory.parent.file.Fd()), directory.leaf, &info, unix.AT_SYMLINK_NOFOLLOW); err != nil || info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Mode&0o777 != 0o700 || info.Uid != uint32(os.Geteuid()) || uint64(info.Dev) != directory.dev || uint64(info.Ino) != directory.ino {
			return errors.New("private directory changed")
		}
		return nil
	}
	info, err := os.Lstat(directory.path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return errors.New("private directory changed")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) || uint64(native.Dev) != directory.dev || uint64(native.Ino) != directory.ino {
		return errors.New("private directory changed")
	}
	return nil
}

func (directory *privateDirectory) open(name string, flags int, mode uint32) (*os.File, error) {
	if !validLeaf(name) || directory.validate() != nil {
		return nil, errors.New("invalid private file")
	}
	descriptor, err := unix.Openat(int(directory.file.Fd()), name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), name)
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("open private file")
	}
	return file, nil
}

func (directory *privateDirectory) entries(limit int) ([]os.DirEntry, error) {
	if limit <= 0 || directory.validate() != nil {
		return nil, errors.New("invalid private directory")
	}
	copy, err := directory.openScan()
	if err != nil {
		return nil, err
	}
	defer copy.Close()
	entries, err := copy.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > limit {
		return nil, errors.New("private directory limit")
	}
	return entries, nil
}

func (directory *privateDirectory) openScan() (*os.File, error) {
	if directory.validate() != nil {
		return nil, errors.New("invalid private directory")
	}
	descriptor, err := unix.Openat(int(directory.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	copy := os.NewFile(uintptr(descriptor), "private-directory-scan")
	if copy == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("scan private directory")
	}
	info, err := copy.Stat()
	if err != nil {
		copy.Close()
		return nil, errors.New("private directory changed")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(native.Dev) != directory.dev || uint64(native.Ino) != directory.ino {
		copy.Close()
		return nil, errors.New("private directory changed")
	}
	return copy, nil
}

func (directory *privateDirectory) write(name string, data []byte) error {
	var temporaryName string
	var temporary *os.File
	for attempt := 0; attempt < 16; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return err
		}
		temporaryName = ".session-write-" + hex.EncodeToString(random[:])
		file, err := directory.open(temporaryName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return err
		}
		temporary = file
		break
	}
	if temporary == nil {
		return errors.New("allocate private temporary file")
	}
	defer func() { _ = temporary.Close(); _ = unix.Unlinkat(int(directory.file.Fd()), temporaryName, 0) }()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if directory.validate() != nil {
		return errors.New("private directory changed")
	}
	if err := unix.Renameat(int(directory.file.Fd()), temporaryName, int(directory.file.Fd()), name); err != nil {
		return err
	}
	temporaryName = ""
	return directory.file.Sync()
}

func (directory *privateDirectory) unlink(name string) error {
	if !validLeaf(name) || directory.validate() != nil {
		return errors.New("private directory changed")
	}
	if err := unix.Unlinkat(int(directory.file.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return directory.file.Sync()
}

func (directory *privateDirectory) lock(name string, nonblocking bool) (*os.File, error) {
	file, err := directory.open(name, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR, 0o600)
	created := err == nil
	if errors.Is(err, unix.EEXIST) {
		file, err = directory.open(name, unix.O_RDWR, 0)
	}
	if err != nil {
		return nil, err
	}
	valid := false
	defer func() {
		if created && !valid {
			_ = unix.Unlinkat(int(directory.file.Fd()), name, 0)
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, errors.New("invalid lock")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) || native.Nlink != 1 {
		file.Close()
		return nil, errors.New("invalid lock")
	}
	if created {
		if err := file.Chmod(0o600); err != nil {
			file.Close()
			return nil, err
		}
	} else if info.Mode().Perm() != 0o600 {
		file.Close()
		return nil, errors.New("invalid lock")
	}
	operation := unix.LOCK_EX
	if nonblocking {
		operation |= unix.LOCK_NB
	}
	if err := unix.Flock(int(file.Fd()), operation); err != nil {
		file.Close()
		return nil, err
	}
	valid = true
	return file, nil
}

func (directory *privateDirectory) close() {
	if directory != nil && directory.file != nil {
		_ = directory.file.Close()
		directory.file = nil
	}
}
func (storage *privateStorage) close() {
	if storage == nil {
		return
	}
	storage.locks.close()
	storage.capabilities.close()
	storage.records.close()
	storage.base.close()
}

func validLeaf(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && len(name) <= 128
}
