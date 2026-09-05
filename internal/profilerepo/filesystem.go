package profilerepo

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const artifactPrefix = ".profile-transaction-"
const maxEntries = 4096
const maxMetadataBytes = 8192

type identity struct {
	Device uint64
	Inode  uint64
	Size   int64
	Hash   string
}
type object struct {
	identity
	data  []byte
	links uint64
}

func (o *object) bytes() []byte {
	if o == nil {
		return nil
	}
	return o.data
}
func (o *object) matches(id identity) bool { return o != nil && o.identity == id }
func leaf(name string) string {
	if strings.HasSuffix(name, ".json") {
		return name
	}
	return artifactPrefix + name
}

type directory struct {
	r                         *Repository
	parent, home, file, guard *os.File
	parentPath, homeName      string
}

func (r *Repository) open(mutate bool) (*directory, error) {
	path, err := filepath.Abs(r.acsHome)
	if err != nil {
		return nil, err
	}
	if filepath.Base(path) == "/" {
		return nil, ErrUnsafe
	}
	parentPath, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	parent, err := os.Open(parentPath)
	if err != nil {
		return nil, err
	}
	d := &directory{r: r, parent: parent, parentPath: parentPath, homeName: filepath.Base(path)}
	fail := func(err error) (*directory, error) { return nil, errors.Join(err, d.close()) }
	d.home, err = d.child(parent, d.homeName, mutate, "home")
	if err != nil {
		return fail(err)
	}
	d.file, err = d.child(d.home, "profiles", mutate, "repository")
	if err != nil {
		return fail(err)
	}
	return d, nil
}
func (d *directory) child(parent *os.File, name string, mutate bool, label string) (*os.File, error) {
	if mutate {
		err := d.r.step(label+".mkdir", func() error {
			e := unix.Mkdirat(int(parent.Fd()), name, 0700)
			if errors.Is(e, unix.EEXIST) {
				return nil
			}
			return e
		})
		if err != nil {
			return nil, err
		}
		// Also sync an existing directory: a previous bootstrap can have been interrupted.
		if err := d.r.step(label+".parent-sync", parent.Sync); err != nil {
			return nil, err
		}
	}
	fd, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err == nil && (st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid())) {
		err = ErrUnsafe
	}
	if err == nil && mutate {
		err = d.r.step(label+".chmod", func() error { return f.Chmod(0700) })
	}
	if err == nil && mutate {
		err = d.r.step(label+".sync", f.Sync)
	}
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}
func (d *directory) close() error {
	var err error
	for _, f := range []*os.File{d.file, d.home, d.parent} {
		if f != nil {
			err = errors.Join(err, f.Close())
		}
	}
	return err
}
func sameStat(a, b *unix.Stat_t) bool { return a.Dev == b.Dev && a.Ino == b.Ino }
func (d *directory) validate() error {
	var parent, now unix.Stat_t
	if err := unix.Fstat(int(d.parent.Fd()), &parent); err != nil {
		return err
	}
	if err := unix.Stat(d.parentPath, &now); err != nil {
		return err
	}
	if !sameStat(&parent, &now) {
		return ErrUnsafe
	}
	for _, p := range []struct {
		parent, file *os.File
		name         string
	}{{d.parent, d.home, d.homeName}, {d.home, d.file, "profiles"}} {
		if err := unix.Fstat(int(p.file.Fd()), &parent); err != nil {
			return err
		}
		if err := unix.Fstatat(int(p.parent.Fd()), p.name, &now, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if !sameStat(&parent, &now) || now.Mode&unix.S_IFMT != unix.S_IFDIR {
			return ErrUnsafe
		}
	}
	if d.guard != nil {
		if err := unix.Fstat(int(d.guard.Fd()), &parent); err != nil {
			return err
		}
		if err := unix.Fstatat(int(d.file.Fd()), leaf("lock"), &now, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if !sameStat(&parent, &now) || !privateRegular(&now, 1) || now.Size != 0 {
			return ErrUnsafe
		}
	}
	return nil
}
func privateRegular(st *unix.Stat_t, maxLinks uint64) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFREG && st.Mode&07777 == 0600 && st.Uid == uint32(os.Geteuid()) && st.Nlink >= 1 && uint64(st.Nlink) <= maxLinks
}
func (d *directory) lock() error {
	if err := d.validate(); err != nil {
		return err
	}
	fd, err := unix.Openat(int(d.file.Fd()), leaf("lock"), unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), "Profile repository lock")
	fail := func(err error) error { return errors.Join(err, f.Close()) }
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return fail(err)
	}
	if !privateRegular(&st, 1) || st.Size != 0 {
		return fail(ErrUnsafe)
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			err = ErrBusy
		}
		return fail(err)
	}
	d.guard = f
	if err = d.validate(); err == nil {
		err = d.r.step("lock.sync", f.Sync)
	}
	if err == nil {
		err = d.sync("lock.directory-sync")
	}
	if err != nil {
		return errors.Join(err, d.release())
	}
	return nil
}
func (d *directory) release() error {
	if d.guard == nil {
		return nil
	}
	f := d.guard
	d.guard = nil
	// Always release even if the injected diagnostic reports failure.
	err := unix.Flock(int(f.Fd()), unix.LOCK_UN)
	err = errors.Join(err, f.Close())
	return errors.Join(err, d.r.step("lock.release", func() error { return nil }))
}
func (d *directory) read(name string, limit int, maxLinks uint64) (result *object, err error) {
	if err = d.validate(); err != nil {
		return
	}
	var before unix.Stat_t
	err = unix.Fstatat(int(d.file.Fd()), leaf(name), &before, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return
	}
	if !privateRegular(&before, maxLinks) || before.Size > int64(limit) {
		return nil, ErrUnsafe
	}
	fd, err := unix.Openat(int(d.file.Fd()), leaf(name), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { err = errors.Join(err, f.Close()) }()
	var st, after unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil {
		return
	}
	if !sameStat(&before, &st) || !privateRegular(&st, maxLinks) || st.Size > int64(limit) {
		return nil, ErrUnsafe
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if err = unix.Fstat(fd, &after); err != nil {
		return
	}
	if !sameStat(&st, &after) || st.Mode != after.Mode || st.Nlink != after.Nlink || st.Size != after.Size || st.Mtim != after.Mtim || st.Ctim != after.Ctim || int64(len(data)) != st.Size || len(data) > limit {
		return nil, ErrUnsafe
	}
	if err = unix.Fstatat(int(d.file.Fd()), leaf(name), &after, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return
	}
	if !sameStat(&st, &after) {
		return nil, ErrUnsafe
	}
	sum := sha256.Sum256(data)
	return &object{identity{uint64(st.Dev), uint64(st.Ino), st.Size, hex.EncodeToString(sum[:])}, data, uint64(st.Nlink)}, nil
}
func (d *directory) sync(point string) error {
	return d.r.step(point, func() error {
		if err := d.validate(); err != nil {
			return err
		}
		return d.file.Sync()
	})
}
func (d *directory) link(from, to, point string) error {
	return d.r.step(point, func() error {
		if err := d.validate(); err != nil {
			return err
		}
		return unix.Linkat(int(d.file.Fd()), leaf(from), int(d.file.Fd()), leaf(to), 0)
	})
}
func (d *directory) rename(from, to, point string) error {
	return d.r.step(point, func() error {
		if err := d.validate(); err != nil {
			return err
		}
		return unix.Renameat(int(d.file.Fd()), leaf(from), int(d.file.Fd()), leaf(to))
	})
}
func (d *directory) remove(name, point string) error {
	return d.r.step(point, func() error {
		if err := d.validate(); err != nil {
			return err
		}
		err := unix.Unlinkat(int(d.file.Fd()), leaf(name), 0)
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	})
}
func (d *directory) writeNew(name string, data []byte) (err error) {
	if err = d.validate(); err != nil {
		return
	}
	var f *os.File
	if err = d.r.step(name+".create", func() error {
		fd, e := unix.Openat(int(d.file.Fd()), leaf(name), unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if e == nil {
			f = os.NewFile(uintptr(fd), name)
		}
		return e
	}); err != nil {
		if f != nil {
			err = errors.Join(err, f.Close())
		}
		return
	}
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, f.Close())
		}
	}()
	if err = d.r.step(name+".write", func() error {
		var n int
		var e error
		if d.r.write != nil {
			n, e = d.r.write(f, data)
		} else {
			n, e = f.Write(data)
		}
		if e == nil && n != len(data) {
			e = io.ErrShortWrite
		}
		return e
	}); err != nil {
		return
	}
	if err = d.r.step(name+".sync", f.Sync); err != nil {
		return
	}
	// A before-close fault still closes the descriptor via the defer.
	err = d.r.step(name+".close", func() error { closed = true; return f.Close() })
	return
}
func (d *directory) artifacts() (map[string]*object, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(d.file.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "Profile artifact scan")
	names, readErr := f.Readdirnames(maxEntries + 1)
	closeErr := f.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, errors.Join(readErr, closeErr)
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(names) > maxEntries {
		return nil, ErrUnsafe
	}
	result := map[string]*object{}
	for _, name := range names {
		if len(name) > 255 {
			return nil, ErrUnsafe
		}
		if !strings.HasPrefix(name, artifactPrefix) {
			if strings.HasPrefix(strings.ToLower(name), artifactPrefix) {
				return nil, ErrUnsafe
			}
			continue
		}
		n := strings.TrimPrefix(name, artifactPrefix)
		limit := maxMetadataBytes
		links := uint64(3)
		switch n {
		case "lock":
			continue
		case "stage", "swap":
			limit = MaxDocumentBytes
		case "pending", "plan", "decision", "complete":
		default:
			return nil, ErrUnsafe
		}
		obj, e := d.read(n, limit, links)
		if e != nil {
			return nil, e
		}
		if obj == nil {
			return nil, ErrUnsafe
		}
		result[n] = obj
	}
	return result, nil
}
func identical(a, b *object) bool {
	return a != nil && b != nil && a.identity == b.identity && bytes.Equal(a.data, b.data)
}
