package sessionops

import (
	"errors"
	"io"
	"os"
)

// walkEntries visits the entire pinned directory without retaining more than
// one bounded batch. Each traversal has its own file description, so repeated
// scans never share or inherit a partially consumed directory offset.
func (directory *privateDirectory) walkEntries(visit func(os.DirEntry) error) error {
	scan, err := directory.openScan()
	if err != nil {
		return err
	}
	defer scan.Close()
	return walkDirectoryEntries(scan.ReadDir, directory.validate, visit)
}

func walkDirectoryEntries(read func(int) ([]os.DirEntry, error), validate func() error, visit func(os.DirEntry) error) error {
	if visit == nil {
		return errors.New("invalid private directory visitor")
	}
	for {
		if err := validate(); err != nil {
			return err
		}
		entries, readErr := read(scanBatchSize)
		if err := validate(); err != nil {
			return err
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		for _, entry := range entries {
			if err := visit(entry); err != nil {
				return err
			}
		}
		if err := validate(); err != nil {
			return err
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		if len(entries) == 0 {
			return io.ErrNoProgress
		}
	}
}
