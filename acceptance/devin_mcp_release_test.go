package acceptance_test

import (
	"io"
	"os"
	"path/filepath"
)

// Both start and inspection acknowledgements become visible only when complete.
// Link preserves exclusive publication: existing files, links and directories
// are refused rather than replaced. Temporary siblings are always removed.
func devinRelease(path string) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".devin-release-")
	if e != nil {
		return e
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	n, e := f.WriteString("release\n")
	if e == nil && n != 8 {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Link(temporary, path)
}
