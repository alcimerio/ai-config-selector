package linuxprobe

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

type fakeBwrap struct {
	t                                               *testing.T
	stats                                           [4]unix.Stat_t
	openError, readError, writeAllowed, accessError int
	digestError                                     bool
	change                                          func(*unix.Stat_t)
	opened, closed                                  []int
	digested                                        bool
}

func newFakeBwrap(t *testing.T) *fakeBwrap {
	f := &fakeBwrap{t: t, openError: -1, readError: -1, writeAllowed: -1, accessError: -1}
	for i := range f.stats {
		f.stats[i] = unix.Stat_t{Mode: unix.S_IFDIR | 0755, Ino: uint64(i + 1), Nlink: 1}
	}
	f.stats[3].Mode = unix.S_IFREG | 0755
	f.stats[3].Size = 1024
	return f
}

func (f *fakeBwrap) ops() bwrapOps {
	return bwrapOps{
		openat: func(parent int, name string, flags int, mode uint32) (int, error) {
			i := len(f.opened)
			if i >= 4 {
				f.t.Fatal("too many path components")
			}
			wantParent := i - 1
			if i == 0 {
				wantParent = unix.AT_FDCWD
			}
			if parent != wantParent || name != []string{"/", "usr", "bin", "bwrap"}[i] || flags&unix.O_NOFOLLOW == 0 || flags&unix.O_CLOEXEC == 0 {
				f.t.Fatalf("untrusted lookup parent=%d name=%q flags=%d", parent, name, flags)
			}
			if i == f.openError {
				return -1, os.ErrNotExist
			}
			f.opened = append(f.opened, i)
			return i, nil
		},
		stat: func(fd int, s *unix.Stat_t) error {
			*s = f.stats[fd]
			if f.digested && f.change != nil {
				f.change(s)
			}
			return nil
		},
		access: func(fd int, name string, mode uint32, flags int) error {
			if name != "" || flags != unix.AT_EMPTY_PATH|unix.AT_EACCESS {
				f.t.Fatal("access did not use pinned descriptor and effective identity")
			}
			if fd == f.accessError {
				return unix.ENOSYS
			}
			if mode == unix.W_OK {
				if fd == f.writeAllowed {
					return nil
				}
				return unix.EACCES
			}
			if fd == f.readError {
				return unix.EACCES
			}
			return nil
		},
		close: func(fd int) error { f.closed = append(f.closed, fd); return nil },
		digest: func(fd int) (string, error) {
			if fd != 3 {
				f.t.Fatal("wrong binary descriptor")
			}
			f.digested = true
			if f.digestError {
				return "", errors.New("private path")
			}
			return strings.Repeat("a", 64), nil
		},
	}
}

func TestBwrapPinsFixedSystemPathAndRejectsUnsafeProvenance(t *testing.T) {
	// A PATH override never participates in backend lookup.
	t.Setenv("PATH", "/home/private/attacker-bin:.")
	for _, tc := range []struct {
		name   string
		change func(*fakeBwrap)
	}{
		{"trusted", func(*fakeBwrap) {}},
		{"missing", func(f *fakeBwrap) { f.openError = 3 }},
		{"unowned root", func(f *fakeBwrap) { f.stats[0].Uid = 1000 }},
		{"unowned usr", func(f *fakeBwrap) { f.stats[1].Uid = 1000 }},
		{"unowned bin", func(f *fakeBwrap) { f.stats[2].Uid = 1000 }},
		{"unowned executable", func(f *fakeBwrap) { f.stats[3].Uid = 1000 }},
		{"world writable parent", func(f *fakeBwrap) { f.stats[1].Mode |= 0002 }},
		{"group writable binary", func(f *fakeBwrap) { f.stats[3].Mode |= 0020 }},
		{"parent ACL write", func(f *fakeBwrap) { f.writeAllowed = 2 }},
		{"binary ACL write", func(f *fakeBwrap) { f.writeAllowed = 3 }},
		{"access unavailable", func(f *fakeBwrap) { f.accessError = 3 }},
		{"no read execute access", func(f *fakeBwrap) { f.readError = 3 }},
		{"symlink parent", func(f *fakeBwrap) { f.stats[2].Mode = unix.S_IFLNK | 0755 }},
		{"symlink binary", func(f *fakeBwrap) { f.stats[3].Mode = unix.S_IFLNK | 0755 }},
		{"directory binary", func(f *fakeBwrap) { f.stats[3].Mode = unix.S_IFDIR | 0755 }},
		{"not executable", func(f *fakeBwrap) { f.stats[3].Mode &^= 0111 }},
		{"setuid", func(f *fakeBwrap) { f.stats[3].Mode |= unix.S_ISUID }},
		{"setgid", func(f *fakeBwrap) { f.stats[3].Mode |= unix.S_ISGID }},
		{"hard links", func(f *fakeBwrap) { f.stats[3].Nlink = 2 }},
		{"digest failure", func(f *fakeBwrap) { f.digestError = true }},
		{"inode changed", func(f *fakeBwrap) { f.change = func(s *unix.Stat_t) { s.Ino++ } }},
		{"ownership changed", func(f *fakeBwrap) { f.change = func(s *unix.Stat_t) { s.Uid++ } }},
		{"content changed", func(f *fakeBwrap) { f.change = func(s *unix.Stat_t) { s.Ctim.Nsec++ } }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeBwrap(t)
			tc.change(f)
			id, err := inspectBwrapWith(f.ops())
			if tc.name == "trusted" {
				if err != nil || id.Inode != 4 || len(id.SHA256) != 64 {
					t.Fatalf("identity=%+v err=%v", id, err)
				}
			} else if !errors.Is(err, errUntrustedBwrap) || id != (bwrapIdentity{}) {
				t.Fatalf("unsafe binary accepted: %+v %v", id, err)
			}
			if !reflect.DeepEqual(f.opened, f.closed) {
				t.Fatalf("leaked descriptors: open=%v closed=%v", f.opened, f.closed)
			}
		})
	}
}

func TestBwrapDigestRequiresNativeELFAndPreservesDescriptor(t *testing.T) {
	header := make([]byte, 32)
	copy(header, "\x7fELF")
	header[4], header[5], header[16], header[18] = 2, 1, 3, 62
	for _, tc := range []struct {
		name  string
		bytes []byte
		ok    bool
	}{
		{"amd64 ELF", header, true},
		{"script", []byte("#!/bin/sh\necho test\n"), false},
		{"truncated", header[:10], false},
		{"foreign architecture", append(append([]byte{}, header[:18]...), make([]byte, 14)...), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := filepath.Join(t.TempDir(), "binary")
			if err := os.WriteFile(name, tc.bytes, 0700); err != nil {
				t.Fatal(err)
			}
			fd, err := unix.Open(name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			got, err := digestBwrap(fd)
			if (err == nil) != tc.ok {
				t.Fatalf("digest=%s err=%v", got, err)
			}
			if tc.ok {
				want := sha256.Sum256(tc.bytes)
				if got != hex.EncodeToString(want[:]) {
					t.Fatal(got)
				}
			}
			var stat unix.Stat_t
			if unix.Fstat(fd, &stat) != nil {
				t.Fatal("digest closed caller descriptor")
			}
		})
	}
}
