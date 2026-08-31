package codexauth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

type privateDirectory struct {
	file         *os.File
	physicalPath string
	device       uint64
	inode        uint64
}

func pinPrivateDirectory(path string) (*privateDirectory, error) {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	physicalParent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return nil, err
	}
	physicalPath := filepath.Join(physicalParent, filepath.Base(absolute))
	directory, err := openPrivateDirectoryPath(physicalPath)
	if err != nil {
		return nil, err
	}
	info, err := directory.Stat()
	if err != nil || !info.IsDir() {
		_ = directory.Close()
		return nil, errors.New("invalid private directory")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) {
		_ = directory.Close()
		return nil, errors.New("invalid private directory owner")
	}
	if err := directory.Chmod(0o700); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return &privateDirectory{
		file: directory, physicalPath: physicalPath,
		device: uint64(native.Dev), inode: uint64(native.Ino),
	}, nil
}

func (directory *privateDirectory) open(name string, flags int, mode uint32) (*os.File, error) {
	if directory == nil || directory.file == nil || !validPrivateLeaf(name) {
		return nil, errors.New("invalid private file")
	}
	if err := directory.validateCanonicalIdentity(); err != nil {
		return nil, err
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

func (directory *privateDirectory) createTemporary(prefix string) (*os.File, string, error) {
	for attempts := 0; attempts < 32; attempts++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := prefix + hex.EncodeToString(random[:])
		file, err := directory.open(name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		return file, name, err
	}
	return nil, "", errors.New("create private temporary file")
}

func (directory *privateDirectory) rename(oldName, newName string) error {
	if !validPrivateLeaf(oldName) || !validPrivateLeaf(newName) {
		return errors.New("invalid private file")
	}
	if err := directory.validateCanonicalIdentity(); err != nil {
		return err
	}
	return unix.Renameat(int(directory.file.Fd()), oldName, int(directory.file.Fd()), newName)
}

func (directory *privateDirectory) renameNoReplace(oldName, newName string) error {
	if !validPrivateLeaf(oldName) || !validPrivateLeaf(newName) {
		return errors.New("invalid private file")
	}
	if err := directory.validateCanonicalIdentity(); err != nil {
		return err
	}
	return renameatNoReplace(int(directory.file.Fd()), oldName, newName)
}

func (directory *privateDirectory) unlink(name string) error {
	if directory == nil || directory.file == nil || !validPrivateLeaf(name) {
		return errors.New("invalid private file")
	}
	if err := directory.validateCanonicalIdentity(); err != nil {
		return err
	}
	return unix.Unlinkat(int(directory.file.Fd()), name, 0)
}

func (directory *privateDirectory) sync() error {
	if directory == nil || directory.file == nil {
		return errors.New("invalid private directory")
	}
	if err := directory.validateCanonicalIdentity(); err != nil {
		return err
	}
	return unix.Fsync(int(directory.file.Fd()))
}

func (directory *privateDirectory) validateCanonicalIdentity() error {
	if directory == nil || directory.file == nil || directory.physicalPath == "" {
		return errors.New("invalid private directory")
	}
	current, err := openPrivateDirectoryPath(directory.physicalPath)
	if err != nil {
		return err
	}
	defer current.Close()
	info, err := current.Stat()
	if err != nil {
		return err
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || uint64(native.Dev) != directory.device || uint64(native.Ino) != directory.inode {
		return errors.New("private directory identity changed")
	}
	return nil
}

func openPrivateDirectoryPath(path string) (*os.File, error) {
	path = filepath.Clean(path)
	if !filepath.IsAbs(path) {
		return nil, errors.New("private directory path must be absolute")
	}
	descriptor, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	current := descriptor
	components := strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		if component == "" {
			continue
		}
		next, openErr := unix.Openat(current, component, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
		_ = unix.Close(current)
		if openErr != nil {
			return nil, openErr
		}
		current = next
	}
	file := os.NewFile(uintptr(current), "private directory")
	if file == nil {
		_ = unix.Close(current)
		return nil, errors.New("open private directory")
	}
	return file, nil
}

func validPrivateLeaf(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsRune(name, filepath.Separator)
}

func securePrivateRoot(path string) (string, error) {
	path = filepath.Clean(path)
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return "", err
	}
	root := filepath.Join(parent, filepath.Base(path))
	if err := secureOwnedDirectory(root); err != nil {
		return "", err
	}
	return root, nil
}

func securePrivateChild(parent, name string) (string, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name || strings.ContainsRune(name, filepath.Separator) {
		return "", errors.New("invalid private directory name")
	}
	path := filepath.Join(parent, name)
	if err := secureOwnedDirectory(path); err != nil {
		return "", err
	}
	return path, nil
}

func secureOwnedDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	directory := os.NewFile(uintptr(descriptor), path)
	if directory == nil {
		_ = syscall.Close(descriptor)
		return errors.New("open private directory")
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil || !info.IsDir() {
		return errors.New("invalid private directory")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) {
		return errors.New("invalid private directory owner")
	}
	return directory.Chmod(0o700)
}
