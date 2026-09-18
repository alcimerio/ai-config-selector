package acceptance_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestDevinProtocolAtomicRelease(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 128; i++ {
		p := filepath.Join(root, fmt.Sprint(i))
		ready := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			deadline := time.Now().Add(time.Second)
			close(ready)
			for {
				b, e := os.ReadFile(p)
				if e == nil {
					if string(b) != "release\n" {
						done <- fmt.Errorf("partial acknowledgement: %d bytes", len(b))
					} else {
						done <- nil
					}
					return
				}
				if !os.IsNotExist(e) {
					done <- e
					return
				}
				if time.Now().After(deadline) {
					done <- fmt.Errorf("publication deadline")
					return
				}
				runtime.Gosched()
			}
		}()
		<-ready
		if e := devinRelease(p); e != nil {
			t.Fatal(e)
		}
		if e := <-done; e != nil {
			t.Fatal(e)
		}
		info, e := os.Stat(p)
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatal("release permissions")
		}
	}
	entries, e := os.ReadDir(root)
	if e != nil || len(entries) != 128 {
		t.Fatal("temporary publication file leaked")
	}
}
func TestDevinProtocolReleaseRefusesExisting(t *testing.T) {
	for _, kind := range []string{"file", "symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			p := filepath.Join(root, "ack")
			target := filepath.Join(root, "target")
			if e := os.WriteFile(target, []byte("untouched"), 0600); e != nil {
				t.Fatal(e)
			}
			var e error
			switch kind {
			case "file":
				e = os.WriteFile(p, []byte("original"), 0600)
			case "symlink":
				e = os.Symlink(target, p)
			case "directory":
				e = os.Mkdir(p, 0700)
			}
			if e != nil {
				t.Fatal(e)
			}
			before, e := os.Lstat(p)
			if e != nil {
				t.Fatal(e)
			}
			if devinRelease(p) == nil {
				t.Fatal("existing acknowledgement replaced")
			}
			after, e := os.Lstat(p)
			if e != nil || !os.SameFile(before, after) {
				t.Fatal("existing identity changed")
			}
			b, e := os.ReadFile(target)
			if e != nil || string(b) != "untouched" {
				t.Fatal("symlink target changed")
			}
			if kind == "file" {
				b, e = os.ReadFile(p)
				if e != nil || string(b) != "original" {
					t.Fatal("existing bytes changed")
				}
			}
			entries, e := os.ReadDir(root)
			if e != nil || len(entries) != 2 {
				t.Fatal("temporary file leaked on refusal")
			}
		})
	}
}
