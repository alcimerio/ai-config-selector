// Package exchangefile publishes one complete exchange document as an
// exclusive new regular file without introducing a persistence journal.
package exchangefile

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var ErrUnsafeDestination = errors.New("unsafe exchange output destination")

// Outcome records whether the exclusive rename completed. Once Published is
// true, later cancellation, durability, reporting, or cleanup errors do not
// make the destination absent.
type Outcome struct{ Published bool }

type Publisher struct {
	Hook  func(string) error
	Write func(io.Writer, []byte) (int, error)
}

func (publisher Publisher) step(name string, action func() error) error {
	if publisher.Hook != nil {
		if err := publisher.Hook(name + ".before"); err != nil {
			return err
		}
	}
	if err := action(); err != nil {
		return err
	}
	if publisher.Hook != nil {
		return publisher.Hook(name + ".after")
	}
	return nil
}

func (publisher Publisher) Publish(ctx context.Context, destination string, data []byte) (out Outcome, err error) {
	if err = ctx.Err(); err != nil {
		return
	}
	absolute, err := filepath.Abs(destination)
	if err != nil {
		return out, ErrUnsafeDestination
	}
	leaf := filepath.Base(absolute)
	if leaf == "" || leaf == "." || leaf == ".." || strings.ContainsRune(leaf, 0) || strings.ContainsRune(leaf, filepath.Separator) {
		return out, ErrUnsafeDestination
	}
	parentPath, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return out, ErrUnsafeDestination
	}
	parent, err := os.Open(parentPath)
	if err != nil {
		return out, ErrUnsafeDestination
	}
	defer func() { err = errors.Join(err, parent.Close()) }()
	var parentStat unix.Stat_t
	if unix.Fstat(int(parent.Fd()), &parentStat) != nil || parentStat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return out, ErrUnsafeDestination
	}
	validateParent := func() error {
		var current unix.Stat_t
		if unix.Stat(parentPath, &current) != nil || current.Dev != parentStat.Dev || current.Ino != parentStat.Ino || current.Mode&unix.S_IFMT != unix.S_IFDIR {
			return ErrUnsafeDestination
		}
		return nil
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return
	}
	temporary := ".acs-profile-exchange-" + hex.EncodeToString(random[:])
	fd, err := unix.Openat(int(parent.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return out, err
	}
	file := os.NewFile(uintptr(fd), "exchange output temporary")
	temporaryExists := true
	defer func() {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
		if temporaryExists {
			err = errors.Join(err, unix.Unlinkat(int(parent.Fd()), temporary, 0))
		}
	}()
	write := publisher.Write
	if write == nil {
		write = func(output io.Writer, value []byte) (int, error) { return output.Write(value) }
	}
	if err = publisher.step("write", func() error {
		written, writeErr := write(file, data)
		if writeErr != nil {
			return writeErr
		}
		if written != len(data) {
			return io.ErrShortWrite
		}
		return nil
	}); err != nil {
		return
	}
	if err = publisher.step("file-sync", file.Sync); err != nil {
		return
	}
	if err = publisher.step("close", file.Close); err != nil {
		file = nil
		return
	}
	file = nil
	if err = ctx.Err(); err != nil {
		return
	}
	if err = validateParent(); err != nil {
		return
	}
	publishErr := publisher.step("publish", func() error {
		// This is the final cancellation observation before the commit syscall.
		// Cancellation can still race with that syscall; a successful rename is
		// therefore always reported as published.
		if cancelErr := ctx.Err(); cancelErr != nil {
			return cancelErr
		}
		if renameErr := renameAtNoReplace(int(parent.Fd()), temporary, leaf); renameErr != nil {
			return renameErr
		}
		temporaryExists = false
		out.Published = true
		return nil
	})
	if publishErr != nil && !out.Published {
		err = publishErr
		return
	}
	// A successful rename is already publication, so attempt directory
	// durability even if a post-publication hook fails or cancellation arrives.
	syncErr := publisher.step("directory-sync", parent.Sync)
	err = errors.Join(publishErr, syncErr, ctx.Err())
	return
}
