package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

var canonicalVersionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var checksumLinePattern = regexp.MustCompile(`^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$`)

func main() {
	flags := flag.NewFlagSet("releaseverify", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	dist := flags.String("dist", "", "directory containing the release candidate")
	version := flags.String("version", "", "canonical release tag")
	if err := flags.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	if *dist == "" || *version == "" || flags.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: releaseverify --dist <directory> --version <vMAJOR.MINOR.PATCH>")
		os.Exit(2)
	}
	if err := verify(*dist, *version); err != nil {
		fmt.Fprintf(os.Stderr, "release candidate is invalid: %v\n", err)
		os.Exit(1)
	}
}

func verify(dist, version string) error {
	if !canonicalVersionPattern.MatchString(version) {
		return fmt.Errorf("version must be a canonical SemVer tag")
	}
	archiveVersion := strings.TrimPrefix(version, "v")
	expectedArchives := []string{
		fmt.Sprintf("acs_%s_darwin_arm64.tar.gz", archiveVersion),
		fmt.Sprintf("acs_%s_darwin_amd64.tar.gz", archiveVersion),
		fmt.Sprintf("acs_%s_linux_amd64.tar.gz", archiveVersion),
		fmt.Sprintf("acs_%s_linux_arm64.tar.gz", archiveVersion),
	}
	expectedFiles := append(append([]string(nil), expectedArchives...), "SHA256SUMS")
	sort.Strings(expectedFiles)

	entries, err := os.ReadDir(dist)
	if err != nil {
		return fmt.Errorf("read candidate directory: %w", err)
	}
	actualFiles := make([]string, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect candidate entry %q: %w", entry.Name(), err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("candidate entry %q is not a regular file", entry.Name())
		}
		actualFiles = append(actualFiles, entry.Name())
	}
	sort.Strings(actualFiles)
	if strings.Join(actualFiles, "\n") != strings.Join(expectedFiles, "\n") {
		return fmt.Errorf("artifact names are %q, want %q", actualFiles, expectedFiles)
	}

	checksums, err := readChecksums(filepath.Join(dist, "SHA256SUMS"), expectedArchives)
	if err != nil {
		return err
	}
	for _, archive := range expectedArchives {
		path := filepath.Join(dist, archive)
		contents, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read archive %q: %w", archive, err)
		}
		actual := fmt.Sprintf("%x", sha256.Sum256(contents))
		if actual != checksums[archive] {
			return fmt.Errorf("checksum mismatch for %q", archive)
		}
		parts := strings.Split(strings.TrimSuffix(archive, ".tar.gz"), "_")
		if len(parts) != 4 {
			return fmt.Errorf("archive name %q is malformed", archive)
		}
		if err := verifyArchive(path, parts[2], parts[3], version); err != nil {
			return fmt.Errorf("archive %q: %w", archive, err)
		}
	}
	return nil
}

func readChecksums(path string, expectedArchives []string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open SHA256SUMS: %w", err)
	}
	defer file.Close()
	expected := make(map[string]bool, len(expectedArchives))
	for _, name := range expectedArchives {
		expected[name] = true
	}
	checksums := make(map[string]string, len(expectedArchives))
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		matches := checksumLinePattern.FindStringSubmatch(scanner.Text())
		if matches == nil {
			return nil, fmt.Errorf("SHA256SUMS contains a malformed entry")
		}
		name := matches[2]
		if !expected[name] {
			return nil, fmt.Errorf("SHA256SUMS contains unexpected entry %q", name)
		}
		if _, duplicate := checksums[name]; duplicate {
			return nil, fmt.Errorf("SHA256SUMS contains duplicate entry %q", name)
		}
		checksums[name] = matches[1]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read SHA256SUMS: %w", err)
	}
	if len(checksums) != len(expectedArchives) {
		return nil, fmt.Errorf("SHA256SUMS contains %d entries, want %d", len(checksums), len(expectedArchives))
	}
	return checksums, nil
}

func verifyArchive(path, goos, goarch, version string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("open gzip stream: %w", err)
	}
	defer gzipReader.Close()
	tarReader := tar.NewReader(gzipReader)
	want := map[string]bool{"acs": true, "README.md": true, "LICENSE": true}
	seen := make(map[string]bool, len(want))
	var executable []byte
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar stream: %w", err)
		}
		if !want[header.Name] {
			return fmt.Errorf("unexpected entry %q", header.Name)
		}
		if seen[header.Name] {
			return fmt.Errorf("duplicate entry %q", header.Name)
		}
		seen[header.Name] = true
		if header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return fmt.Errorf("entry %q is not a regular file", header.Name)
		}
		if header.Uid != 0 || header.Gid != 0 || (header.Uname != "" && header.Uname != "root") || (header.Gname != "" && header.Gname != "root") {
			return fmt.Errorf("entry %q contains host ownership metadata", header.Name)
		}
		if header.Size < 0 || header.Size > 128<<20 {
			return fmt.Errorf("entry %q has an invalid size", header.Name)
		}
		contents, err := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if err != nil {
			return fmt.Errorf("read entry %q: %w", header.Name, err)
		}
		if int64(len(contents)) != header.Size {
			return fmt.Errorf("entry %q is truncated", header.Name)
		}
		if header.Name == "acs" {
			if header.Mode&0o111 == 0 {
				return fmt.Errorf("acs is not executable")
			}
			executable = contents
		}
	}
	if len(seen) != len(want) {
		return fmt.Errorf("archive entries are incomplete")
	}
	if goos == runtime.GOOS && goarch == runtime.GOARCH {
		if err := verifyExecutable(executable, version); err != nil {
			return err
		}
	}
	return nil
}

func verifyExecutable(contents []byte, version string) error {
	temporaryDirectory, err := os.MkdirTemp("", "acs-releaseverify-")
	if err != nil {
		return fmt.Errorf("create executable workspace: %w", err)
	}
	defer os.RemoveAll(temporaryDirectory)
	path := filepath.Join(temporaryDirectory, "acs")
	if err := os.WriteFile(path, contents, 0o700); err != nil {
		return fmt.Errorf("write executable: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, path, "version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("execute acs version: %w", err)
	}
	want := fmt.Sprintf("acs %s\n", version)
	if string(output) != want {
		return fmt.Errorf("acs version output is %q, want %q", output, want)
	}
	return nil
}
