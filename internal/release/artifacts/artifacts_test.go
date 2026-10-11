package artifacts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxCandidateExactSet(t *testing.T) {
	binaryPath := filepath.Join(t.TempDir(), "acs")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", binaryPath, "./cmd/acs")
	build.Dir = "../../.."
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		mutate func(string)
		want   string
	}{
		{name: "valid"},
		{name: "missing archive", mutate: func(dir string) { mustRemove(t, filepath.Join(dir, "acs_0.2.0_linux_amd64.tar.gz")) }, want: "artifact names"},
		{name: "missing installer", mutate: func(dir string) { mustRemove(t, filepath.Join(dir, "install.sh")) }, want: "artifact names"},
		{name: "missing manifest", mutate: func(dir string) { mustRemove(t, filepath.Join(dir, "SHA256SUMS")) }, want: "artifact names"},
		{name: "extra arm64", mutate: func(dir string) { mustWrite(t, filepath.Join(dir, "acs_0.2.0_linux_arm64.tar.gz"), []byte("extra")) }, want: "artifact names"},
		{name: "mixed release", mutate: func(dir string) { mustWrite(t, filepath.Join(dir, "acs_0.2.0_darwin_arm64.tar.gz"), []byte("extra")) }, want: "artifact names"},
		{name: "hidden file", mutate: func(dir string) { mustWrite(t, filepath.Join(dir, ".extra"), nil) }, want: "artifact names"},
		{name: "altered manifest", mutate: func(dir string) {
			mustWrite(t, filepath.Join(dir, "SHA256SUMS"), []byte(strings.Repeat("0", 64)+"  acs_0.2.0_linux_amd64.tar.gz\n"))
		}, want: "checksum mismatch"},
		{name: "duplicate checksum", mutate: func(dir string) {
			p := filepath.Join(dir, "SHA256SUMS")
			b, e := os.ReadFile(p)
			if e != nil {
				t.Fatal(e)
			}
			mustWrite(t, p, append(b, b...))
		}, want: "duplicate"},
		{name: "wrong manifest arch", mutate: func(dir string) {
			mustWrite(t, filepath.Join(dir, "SHA256SUMS"), []byte(strings.Repeat("0", 64)+"  acs_0.2.0_linux_arm64.tar.gz\n"))
		}, want: "unexpected entry"},
		{name: "altered archive", mutate: func(dir string) { mustWrite(t, filepath.Join(dir, "acs_0.2.0_linux_amd64.tar.gz"), []byte("altered")) }, want: "checksum mismatch"},
		{name: "wrong binary arch with matching checksum", mutate: func(dir string) {
			b := append([]byte(nil), binary...)
			b[18] = 183
			b[19] = 0
			writeLinuxArchive(t, dir, b, nil)
		}, want: "not linux/amd64 ELF"},
		{name: "script with matching checksum", mutate: func(dir string) { writeLinuxArchive(t, dir, []byte("#!/bin/sh\nexit 0\n"), nil) }, want: "not ELF"},
		{name: "gzip corruption with matching checksum", mutate: func(dir string) {
			writeLinuxArchive(t, dir, binary, func(b []byte) []byte { b[len(b)-8] ^= 0xff; return b })
		}, want: "gzip"},
		{name: "extra gzip member with matching checksum", mutate: func(dir string) { writeLinuxArchive(t, dir, binary, func(b []byte) []byte { return append(b, b...) }) }, want: "trailing"},
		{name: "installer symlink", mutate: func(dir string) {
			p := filepath.Join(dir, "install.sh")
			mustRemove(t, p)
			if e := os.Symlink(binaryPath, p); e != nil {
				t.Fatal(e)
			}
		}, want: "not a regular file"},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			writeLinuxArchive(t, dir, binary, nil)
			mustWrite(t, filepath.Join(dir, "install.sh"), []byte("#!/bin/sh\nreadonly release_version=\"v0.2.0\"\n"))
			if test.mutate != nil {
				test.mutate(dir)
			}
			got, err := Read(dir, "v0.2.0", true)
			if test.want != "" {
				if err == nil || !strings.Contains(err.Error(), test.want) {
					t.Fatalf("error=%v, want %q", err, test.want)
				}
				return
			}
			if err != nil || !bytes.Equal(got, binary) {
				t.Fatalf("candidate bytes changed or rejected: %v", err)
			}
			if _, err := Read(dir, "v0.2.0", false); err == nil {
				t.Fatal("Linux candidate accepted as publishable release")
			}
		})
	}
}

func writeLinuxArchive(t *testing.T, dir string, binary []byte, alter func([]byte) []byte) {
	t.Helper()
	var compressed bytes.Buffer
	z := gzip.NewWriter(&compressed)
	w := tar.NewWriter(z)
	for _, entry := range []struct {
		name     string
		contents []byte
		mode     int64
	}{
		{"acs", binary, 0755}, {"README.md", []byte("fixture"), 0644}, {"LICENSE", []byte("fixture"), 0644},
	} {
		if err := w.WriteHeader(&tar.Header{Name: entry.name, Mode: entry.mode, Size: int64(len(entry.contents)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(entry.contents); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	b := compressed.Bytes()
	if alter != nil {
		b = alter(b)
	}
	name := "acs_0.2.0_linux_amd64.tar.gz"
	mustWrite(t, filepath.Join(dir, name), b)
	mustWrite(t, filepath.Join(dir, "SHA256SUMS"), []byte(fmt.Sprintf("%x  %s\n", sha256.Sum256(b), name)))
}

func mustWrite(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0755); err != nil {
		t.Fatal(err)
	}
}
func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}
