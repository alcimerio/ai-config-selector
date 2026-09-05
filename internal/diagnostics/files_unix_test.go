//go:build darwin || linux

package diagnostics

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

type metadata struct {
	mode os.FileMode
	uid  uint32
}

func (m metadata) Name() string       { return "sandbox-exec" }
func (m metadata) Size() int64        { return 0 }
func (m metadata) Mode() os.FileMode  { return m.mode }
func (m metadata) ModTime() time.Time { return time.Time{} }
func (m metadata) IsDir() bool        { return m.mode.IsDir() }
func (m metadata) Sys() any           { return &syscall.Stat_t{Uid: m.uid} }
func TestBackendTrustMetadataAndReadDenial(t *testing.T) {
	for _, tc := range []struct {
		name           string
		mode           os.FileMode
		uid            uint32
		accessible, ok bool
	}{
		{"trusted", 0755, 0, true, true}, {"group writable", 0775, 0, true, false}, {"world writable", 0757, 0, true, false}, {"nonroot", 0755, 501, true, false}, {"symlink", os.ModeSymlink | 0755, 0, true, false}, {"directory", os.ModeDir | 0755, 0, true, false}, {"fifo", os.ModeNamedPipe | 0755, 0, true, false}, {"not executable", 0644, 0, true, false}, {"access denied", 0755, 0, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := trustedBackendFile("/usr/bin/sandbox-exec", func(string) (os.FileInfo, error) { return metadata{tc.mode, tc.uid}, nil }, func(string) bool { return tc.accessible }); got != tc.ok {
				t.Fatal(got)
			}
		})
	}
	if trustedBackendFile("/private/backend", func(string) (os.FileInfo, error) { t.Fatal("non-system backend inspected"); return nil, nil }, nil) {
		t.Fatal("wrong path")
	}
	if trustedBackendFile("/usr/bin/sandbox-exec", func(string) (os.FileInfo, error) { return nil, errors.New("denied") }, func(string) bool { t.Fatal("access after stat failure"); return true }) {
		t.Fatal("stat failure")
	}
}

func TestActualPermissionDenial(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses discretionary read permissions; native non-root CI exercises actual access denial")
	}
	home := t.TempDir()
	file := home + "/devin"
	if err := os.WriteFile(file, []byte("#!/bin/sh\nexit 97\n"), 0100); err != nil {
		t.Fatal(err)
	}
	if executableAvailable(file) {
		t.Fatal("unreadable executable accepted")
	}
	source := home + "/.agents/skills"
	if err := os.MkdirAll(source, 0700); err != nil {
		t.Fatal(err)
	}
	writeProfile(t, home, `{"version":1,"name":"example","target":"devin","skillReferences":[{"source":"shared-agents","relativePath":"selected"}]}`)
	if err := os.Chmod(source, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(source, 0700)
	check(t, Validate("example", func() (string, error) { return home, nil }), "profile.sources", "fail", "sources_unavailable")
}
