package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReleaseCandidateAcceptsExactlyFourSupportedArchives(t *testing.T) {
	version := "v0.2.0"
	dist := writeCandidate(t, version)

	output, err := verifyCandidate(dist, version)
	if err != nil {
		t.Fatalf("release candidate rejected: %v\n%s", err, output)
	}
}

func TestReleaseCandidateRejectsInvalidArtifactSets(t *testing.T) {
	version := "v0.2.0"
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{name: "missing archive", mutate: func(t *testing.T, dist string) {
			mustRemove(t, filepath.Join(dist, "acs_0.2.0_linux_arm64.tar.gz"))
		}},
		{name: "extra archive", mutate: func(t *testing.T, dist string) {
			mustWriteFile(t, filepath.Join(dist, "acs_0.2.0_windows_amd64.tar.gz"), []byte("unexpected"))
		}},
		{name: "malformed archive name", mutate: func(t *testing.T, dist string) {
			mustRename(t, filepath.Join(dist, "acs_0.2.0_linux_arm64.tar.gz"), filepath.Join(dist, "acs-v0.2.0-linux-arm64.tar.gz"))
		}},
		{name: "zip artifact", mutate: func(t *testing.T, dist string) {
			mustWriteFile(t, filepath.Join(dist, "acs_0.2.0_linux_arm64.zip"), []byte("unexpected"))
		}},
		{name: "missing checksum manifest", mutate: func(t *testing.T, dist string) {
			mustRemove(t, filepath.Join(dist, "SHA256SUMS"))
		}},
		{name: "extra checksum entry", mutate: func(t *testing.T, dist string) {
			manifest := filepath.Join(dist, "SHA256SUMS")
			contents, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			mustWriteFile(t, manifest, append(contents, []byte(strings.Repeat("0", 64)+"  unrelated\n")...))
		}},
		{name: "malformed checksum entry", mutate: func(t *testing.T, dist string) {
			mustWriteFile(t, filepath.Join(dist, "SHA256SUMS"), []byte("not a checksum\n"))
		}},
		{name: "checksum mismatch", mutate: func(t *testing.T, dist string) {
			path := filepath.Join(dist, "acs_0.2.0_linux_arm64.tar.gz")
			file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write([]byte("corruption")); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "nested archive content", mutate: func(t *testing.T, dist string) {
			rewriteArchive(t, dist, "acs_0.2.0_linux_arm64.tar.gz", []archiveEntry{
				{name: "bin/acs", mode: 0o755, body: []byte("fixture")},
				{name: "README.md", mode: 0o644, body: []byte("fixture")},
				{name: "LICENSE", mode: 0o644, body: []byte("fixture")},
			})
		}},
		{name: "extra archive content", mutate: func(t *testing.T, dist string) {
			rewriteArchive(t, dist, "acs_0.2.0_linux_arm64.tar.gz", []archiveEntry{
				{name: "acs", mode: 0o755, body: []byte("fixture")},
				{name: "README.md", mode: 0o644, body: []byte("fixture")},
				{name: "LICENSE", mode: 0o644, body: []byte("fixture")},
				{name: "CHANGELOG.md", mode: 0o644, body: []byte("fixture")},
			})
		}},
		{name: "non-executable acs", mutate: func(t *testing.T, dist string) {
			rewriteArchive(t, dist, "acs_0.2.0_linux_arm64.tar.gz", []archiveEntry{
				{name: "acs", mode: 0o644, body: []byte("fixture")},
				{name: "README.md", mode: 0o644, body: []byte("fixture")},
				{name: "LICENSE", mode: 0o644, body: []byte("fixture")},
			})
		}},
		{name: "host ownership metadata", mutate: func(t *testing.T, dist string) {
			rewriteArchive(t, dist, "acs_0.2.0_linux_arm64.tar.gz", []archiveEntry{
				{name: "acs", mode: 0o755, body: []byte("fixture"), uid: 501, gid: 20, uname: "maintainer", gname: "staff"},
				{name: "README.md", mode: 0o644, body: []byte("fixture")},
				{name: "LICENSE", mode: 0o644, body: []byte("fixture")},
			})
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dist := writeCandidate(t, version)
			test.mutate(t, dist)
			if output, err := verifyCandidate(dist, version); err == nil {
				t.Fatalf("invalid release candidate accepted:\n%s", output)
			}
		})
	}
}

func writeCandidate(t *testing.T, version string) string {
	t.Helper()
	dist := t.TempDir()
	archiveVersion := strings.TrimPrefix(version, "v")
	for _, target := range []struct {
		goos   string
		goarch string
	}{
		{goos: "darwin", goarch: "arm64"},
		{goos: "darwin", goarch: "amd64"},
		{goos: "linux", goarch: "amd64"},
		{goos: "linux", goarch: "arm64"},
	} {
		name := fmt.Sprintf("acs_%s_%s_%s.tar.gz", archiveVersion, target.goos, target.goarch)
		binary := []byte("fixture executable")
		if target.goos == runtime.GOOS && target.goarch == runtime.GOARCH {
			binary = []byte("#!/bin/sh\nprintf 'acs v0.2.0\\n'\n")
		}
		writeArchive(t, filepath.Join(dist, name), binary)
	}
	writeChecksums(t, dist, archiveVersion)
	return dist
}

func verifyCandidate(dist, version string) ([]byte, error) {
	command := exec.Command("go", "run", ".", "--dist", dist, "--version", version)
	command.Dir = "."
	return command.CombinedOutput()
}

func writeArchive(t *testing.T, path string, binary []byte) {
	t.Helper()
	writeArchiveEntries(t, path, []archiveEntry{
		{name: "acs", mode: 0o755, body: binary},
		{name: "README.md", mode: 0o644, body: []byte("fixture readme\n")},
		{name: "LICENSE", mode: 0o644, body: []byte("fixture license\n")},
	})
}

type archiveEntry struct {
	name  string
	mode  int64
	body  []byte
	uid   int
	gid   int
	uname string
	gname string
}

func writeArchiveEntries(t *testing.T, path string, entries []archiveEntry) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		if err := tarWriter.WriteHeader(&tar.Header{
			Name: entry.name, Mode: entry.mode, Size: int64(len(entry.body)), Typeflag: tar.TypeReg,
			Uid: entry.uid, Gid: entry.gid, Uname: entry.uname, Gname: entry.gname,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(entry.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func rewriteArchive(t *testing.T, dist, name string, entries []archiveEntry) {
	t.Helper()
	writeArchiveEntries(t, filepath.Join(dist, name), entries)
	writeChecksums(t, dist, "0.2.0")
}

func writeChecksums(t *testing.T, dist, archiveVersion string) {
	t.Helper()
	var checksums strings.Builder
	for _, target := range []string{"darwin_arm64", "darwin_amd64", "linux_amd64", "linux_arm64"} {
		name := fmt.Sprintf("acs_%s_%s.tar.gz", archiveVersion, target)
		contents, err := os.ReadFile(filepath.Join(dist, name))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&checksums, "%x  %s\n", sha256.Sum256(contents), name)
	}
	mustWriteFile(t, filepath.Join(dist, "SHA256SUMS"), []byte(checksums.String()))
}

func mustWriteFile(t *testing.T, path string, contents []byte) {
	t.Helper()
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustRemove(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func mustRename(t *testing.T, oldPath, newPath string) {
	t.Helper()
	if err := os.Rename(oldPath, newPath); err != nil {
		t.Fatal(err)
	}
}
