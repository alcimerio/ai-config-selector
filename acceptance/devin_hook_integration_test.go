package acceptance_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Called in the actual phase-done paths, after natural child exit is validated.
// Existing MCP cleanup effects must remain AFTER public ACS settles; only the
// hook receipt observation belongs before the inspection acknowledgement.
func acknowledgeDevinPhase(phase string, beforeAttachedAck, ack func() error) error {
	if phase == "attached" && beforeAttachedAck != nil {
		if e := beforeAttachedAck(); e != nil {
			return e
		}
	}
	return ack()
}

// Freeze independent build/input expectations before any target phase starts.
func devinHookFileDigest(path string, limit int64) (string, error) {
	f, e := openDevinHookReceipt(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	a, e := f.Stat()
	if e != nil || !a.Mode().IsRegular() || a.Size() < 1 || a.Size() > limit {
		return "", errors.New("hook expectation file type or size")
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, limit+1))
	if e != nil || n > limit {
		return "", errors.New("hook expectation read bound")
	}
	z, e := f.Stat()
	if e != nil || !os.SameFile(a, z) || a.Mode() != z.Mode() || a.Size() != z.Size() || n != z.Size() || !a.ModTime().Equal(z.ModTime()) {
		return "", errors.New("hook expectation changed")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func TestDevinHookInspectionOrdering(t *testing.T) {
	for _, phase := range []string{"skills", "auth", "attached"} {
		t.Run(phase, func(t *testing.T) {
			var calls []string
			e := acknowledgeDevinPhase(phase, func() error { calls = append(calls, "hook"); return nil }, func() error { calls = append(calls, "ack"); return nil })
			if e != nil {
				t.Fatal(e)
			}
			want := []string{"ack"}
			if phase == "attached" {
				want = append([]string{"hook"}, want...)
			}
			if !reflect.DeepEqual(calls, want) {
				t.Fatal("phase callbacks out of order", calls)
			}
		})
	}
	stop := errors.New("hook changed")
	acked := false
	if e := acknowledgeDevinPhase("attached", func() error { return stop }, func() error { acked = true; return nil }); !errors.Is(e, stop) || acked {
		t.Fatal("verification failure acknowledged")
	}
	if e := acknowledgeDevinPhase("attached", nil, func() error { return stop }); !errors.Is(e, stop) {
		t.Fatal("acknowledgement failure swallowed")
	}
}
func TestDevinHookIndependentBuildDigest(t *testing.T) {
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	p := filepath.Join(root, "witness")
	if _, e = devinHookFileDigest(p, 1024); e == nil {
		t.Fatal("missing executable ignored")
	}
	b := []byte("fixed independently built helper")
	if e = os.WriteFile(p, b, 0500); e != nil {
		t.Fatal(e)
	}
	got, e := devinHookFileDigest(p, 1024)
	expected := sha256.Sum256(b)
	if e != nil || got != hex.EncodeToString(expected[:]) {
		t.Fatal("wrong build digest", e)
	}
	if _, e = devinHookFileDigest(p, 1); e == nil {
		t.Fatal("digest size cap ignored")
	}
	alias := p + "-alias"
	if e = os.Symlink(p, alias); e != nil {
		t.Fatal(e)
	}
	if _, e = devinHookFileDigest(alias, 1024); e == nil {
		t.Fatal("aliased helper accepted")
	}
}
