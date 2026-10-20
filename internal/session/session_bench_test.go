package session

import (
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkSessionCreateRemove(b *testing.B) {
	root := b.TempDir()
	sessions := filepath.Join(root, "sessions")
	work := filepath.Join(root, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for index := 0; index < b.N; index++ {
		created, err := CreateTracked(sessions, work, nil, "command")
		if err != nil {
			b.Fatal(err)
		}
		if err := created.Remove(); err != nil {
			b.Fatal(err)
		}
	}
}
