package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestInspectionAcknowledgement(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ack")
	if awaitInspection(p, time.Millisecond) == nil {
		t.Fatal("missing acknowledgement passed")
	}
	if e := os.WriteFile(p, []byte("wrong\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if awaitInspection(p, time.Millisecond) == nil {
		t.Fatal("malformed acknowledgement passed")
	}
	if e := os.WriteFile(p, []byte("release\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := awaitInspection(p, time.Millisecond); e != nil {
		t.Fatal(e)
	}
}

func TestInspectionRefusesUnsafeEntries(t *testing.T) {
	for _, kind := range []string{"fifo", "oversize", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "ack")
			var e error
			switch kind {
			case "fifo":
				e = syscall.Mkfifo(p, 0600)
			case "oversize":
				e = os.WriteFile(p, make([]byte, 1024), 0600)
			case "symlink":
				target := filepath.Join(t.TempDir(), "target")
				if e = os.WriteFile(target, []byte("release\n"), 0600); e == nil {
					e = os.Symlink(target, p)
				}
			}
			if e != nil {
				t.Fatal(e)
			}
			if e = awaitInspection(p, time.Millisecond); e == nil {
				t.Fatal("unsafe entry accepted")
			}
		})
	}
}
