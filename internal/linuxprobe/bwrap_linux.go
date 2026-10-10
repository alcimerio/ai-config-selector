package linuxprobe

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const bwrapPath = "/usr/bin/bwrap"

var errUntrustedBwrap = errors.New("system bubblewrap identity is untrusted")

// This is a metadata/content identity, not a package signature or a launch
// authorization. Any future launcher must acquire and validate its own handle.
type bwrapIdentity struct {
	Device, Inode uint64
	Size          int64
	Mode          uint32
	UID, GID      uint32
	Links         uint64
	Changed       unix.Timespec
	Modified      unix.Timespec
	SHA256        string
}

type bwrapOps struct {
	openat func(int, string, int, uint32) (int, error)
	stat   func(int, *unix.Stat_t) error
	access func(int, string, uint32, int) error
	close  func(int) error
	digest func(int) (string, error)
}

func inspectBwrap() (bwrapIdentity, error) {
	return inspectBwrapWith(bwrapOps{unix.Openat, unix.Fstat, unix.Faccessat2, unix.Close, digestBwrap})
}

func inspectBwrapWith(p bwrapOps) (bwrapIdentity, error) {
	// Walk every component relative to a pinned parent, never resolving a PATH
	// entry or a symlink (including /bin -> /usr/bin). ACL write access is also
	// checked with the caller's effective IDs, not inferred from mode bits.
	parent := unix.AT_FDCWD
	var opened []int
	defer func() {
		for _, fd := range opened {
			_ = p.close(fd)
		}
	}()
	var before unix.Stat_t
	for i, name := range []string{"/", "usr", "bin", "bwrap"} {
		directory := i < 3
		flags := unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC
		if directory {
			flags |= unix.O_DIRECTORY
		} else {
			flags = unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
		}
		fd, err := p.openat(parent, name, flags, 0)
		if err != nil {
			return bwrapIdentity{}, errUntrustedBwrap
		}
		opened = append(opened, fd)
		if p.stat(fd, &before) != nil || !trustedBwrapMode(before, directory) {
			return bwrapIdentity{}, errUntrustedBwrap
		}
		writeErr := p.access(fd, "", unix.W_OK, unix.AT_EMPTY_PATH|unix.AT_EACCESS)
		if !errors.Is(writeErr, unix.EACCES) && !errors.Is(writeErr, unix.EROFS) {
			return bwrapIdentity{}, errUntrustedBwrap
		}
		if p.access(fd, "", unix.R_OK|unix.X_OK, unix.AT_EMPTY_PATH|unix.AT_EACCESS) != nil {
			return bwrapIdentity{}, errUntrustedBwrap
		}
		parent = fd
	}
	id := bwrapStatIdentity(before)
	digest, err := p.digest(parent)
	var after unix.Stat_t
	if err != nil || p.stat(parent, &after) != nil || id != bwrapStatIdentity(after) {
		return bwrapIdentity{}, errUntrustedBwrap
	}
	id.SHA256 = digest
	return id, nil
}

func trustedBwrapMode(s unix.Stat_t, directory bool) bool {
	if s.Uid != 0 || s.Mode&0022 != 0 {
		return false
	}
	if directory {
		return s.Mode&unix.S_IFMT == unix.S_IFDIR
	}
	return s.Mode&unix.S_IFMT == unix.S_IFREG && s.Mode&0111 != 0 && s.Mode&06000 == 0 && s.Nlink == 1
}

func bwrapStatIdentity(s unix.Stat_t) bwrapIdentity {
	return bwrapIdentity{Device: s.Dev, Inode: s.Ino, Size: s.Size, Mode: s.Mode, UID: s.Uid, GID: s.Gid, Links: uint64(s.Nlink), Changed: s.Ctim, Modified: s.Mtim}
}

func digestBwrap(fd int) (string, error) {
	// A duplicate keeps ownership of the original validated descriptor here.
	duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(duplicate), bwrapPath)
	defer f.Close()
	var header [20]byte
	if _, err := io.ReadFull(f, header[:]); err != nil {
		return "", err
	}
	// Only the native amd64 ELF executable is eligible, never a wrapper script
	// whose interpreter would introduce another unchecked trust dependency.
	if string(header[:4]) != "\x7fELF" || header[4] != 2 || header[5] != 1 || (header[16] != 2 && header[16] != 3) || header[17] != 0 || header[18] != 62 || header[19] != 0 {
		return "", errUntrustedBwrap
	}
	h := sha256.New()
	_, _ = h.Write(header[:])
	n, err := io.Copy(h, io.LimitReader(f, 32*1024*1024+1))
	if err != nil || n > int64(32*1024*1024-len(header)) {
		return "", errUntrustedBwrap
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
