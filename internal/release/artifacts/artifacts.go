// Package artifacts validates staged release artifact sets without publishing them.
package artifacts

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var canonicalVersionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var checksumLinePattern = regexp.MustCompile(`^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$`)

// Read validates one exact artifact set and returns the packaged executable bytes.
// Linux candidates are deliberately separate from the publishable macOS set.
func Read(dist, version string, linuxCandidate bool) ([]byte, error) {
	if !canonicalVersionPattern.MatchString(version) {
		return nil, fmt.Errorf("version must be a canonical SemVer tag")
	}
	target := "darwin_arm64"
	if linuxCandidate {
		target = "linux_amd64"
	}
	archiveVersion := strings.TrimPrefix(version, "v")
	expectedArchives := []string{
		fmt.Sprintf("acs_%s_%s.tar.gz", archiveVersion, target),
	}
	expectedFiles := append(append([]string(nil), expectedArchives...), "SHA256SUMS", "install.sh")
	sort.Strings(expectedFiles)

	entries, err := os.ReadDir(dist)
	if err != nil {
		return nil, fmt.Errorf("read candidate directory: %w", err)
	}
	actualFiles := make([]string, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("inspect candidate entry %q: %w", entry.Name(), err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("candidate entry %q is not a regular file", entry.Name())
		}
		actualFiles = append(actualFiles, entry.Name())
	}
	sort.Strings(actualFiles)
	if strings.Join(actualFiles, "\n") != strings.Join(expectedFiles, "\n") {
		return nil, fmt.Errorf("artifact names are %q, want %q", actualFiles, expectedFiles)
	}
	if err := verifyInstaller(filepath.Join(dist, "install.sh"), version); err != nil {
		return nil, err
	}

	checksums, err := readChecksums(filepath.Join(dist, "SHA256SUMS"), expectedArchives)
	if err != nil {
		return nil, err
	}
	var executable []byte
	for _, archive := range expectedArchives {
		path := filepath.Join(dist, archive)
		contents, err := readBounded(path, 128<<20)
		if err != nil {
			return nil, fmt.Errorf("read archive %q: %w", archive, err)
		}
		actual := fmt.Sprintf("%x", sha256.Sum256(contents))
		if actual != checksums[archive] {
			return nil, fmt.Errorf("checksum mismatch for %q", archive)
		}
		parts := strings.Split(strings.TrimSuffix(archive, ".tar.gz"), "_")
		if len(parts) != 4 {
			return nil, fmt.Errorf("archive name %q is malformed", archive)
		}
		executable, err = readArchive(contents)
		if err != nil {
			return nil, fmt.Errorf("archive %q: %w", archive, err)
		}
		if linuxCandidate {
			if err := verifyLinuxBinary(executable); err != nil {
				return nil, err
			}
		}
	}
	return executable, nil
}

func verifyInstaller(path, version string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect install.sh: %w", err)
	}
	if info.Mode()&0o111 == 0 {
		return fmt.Errorf("install.sh is not executable")
	}
	if info.Size() <= 0 || info.Size() > 1<<20 {
		return fmt.Errorf("install.sh has an invalid size")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read install.sh: %w", err)
	}
	text := string(contents)
	if !strings.HasPrefix(text, "#!/bin/sh\n") {
		return fmt.Errorf("install.sh does not use the portable Unix shell")
	}
	wantVersion := fmt.Sprintf("readonly release_version=\"%s\"", version)
	if strings.Count(text, wantVersion) != 1 || strings.Contains(text, "__ACS_RELEASE_VERSION__") {
		return fmt.Errorf("install.sh is not pinned to %s", version)
	}
	if strings.Contains(text, "/latest/") || strings.Contains(text, "releases/latest") {
		return fmt.Errorf("install.sh contains a mutable Release URL")
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

func readArchive(contents []byte) ([]byte, error) {
	source := bytes.NewReader(contents)
	gzipReader, err := gzip.NewReader(source)
	if err != nil {
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	defer gzipReader.Close()
	gzipReader.Multistream(false)
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
			return nil, fmt.Errorf("read tar stream: %w", err)
		}
		if !want[header.Name] {
			return nil, fmt.Errorf("unexpected entry %q", header.Name)
		}
		if seen[header.Name] {
			return nil, fmt.Errorf("duplicate entry %q", header.Name)
		}
		seen[header.Name] = true
		// tar.Reader normalizes legacy regular-file headers to TypeReg.
		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("entry %q is not a regular file", header.Name)
		}
		if header.Uid != 0 || header.Gid != 0 || (header.Uname != "" && header.Uname != "root") || (header.Gname != "" && header.Gname != "root") {
			return nil, fmt.Errorf("entry %q contains host ownership metadata", header.Name)
		}
		if header.Size < 0 || header.Size > 128<<20 {
			return nil, fmt.Errorf("entry %q has an invalid size", header.Name)
		}
		contents, err := io.ReadAll(io.LimitReader(tarReader, header.Size+1))
		if err != nil {
			return nil, fmt.Errorf("read entry %q: %w", header.Name, err)
		}
		if int64(len(contents)) != header.Size {
			return nil, fmt.Errorf("entry %q is truncated", header.Name)
		}
		if header.Name == "acs" {
			if header.Mode&0o111 == 0 {
				return nil, fmt.Errorf("acs is not executable")
			}
			executable = contents
		}
	}
	if len(seen) != len(want) {
		return nil, fmt.Errorf("archive entries are incomplete")
	}
	tail, err := io.ReadAll(io.LimitReader(gzipReader, 64<<10+1))
	if err != nil || len(tail) > 64<<10 || len(bytes.Trim(tail, "\x00")) != 0 || source.Len() != 0 {
		return nil, fmt.Errorf("archive has invalid trailing data or gzip checksum")
	}
	return executable, nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > limit {
		return nil, fmt.Errorf("artifact exceeds size limit")
	}
	return contents, nil
}

func verifyLinuxBinary(binary []byte) error {
	executable, err := elf.NewFile(bytes.NewReader(binary))
	if err != nil {
		return fmt.Errorf("candidate executable is not ELF")
	}
	defer executable.Close()
	if executable.Class != elf.ELFCLASS64 || executable.Data != elf.ELFDATA2LSB || executable.Machine != elf.EM_X86_64 || (executable.Type != elf.ET_EXEC && executable.Type != elf.ET_DYN) {
		return fmt.Errorf("candidate executable is not linux/amd64 ELF")
	}
	for _, program := range executable.Progs {
		if program.Type == elf.PT_INTERP {
			return fmt.Errorf("candidate executable requires a dynamic interpreter")
		}
	}
	info, err := buildinfo.Read(bytes.NewReader(binary))
	if err != nil || info.Path != "github.com/alcimerio/ai-config-selector/cmd/acs" {
		return fmt.Errorf("candidate executable has unexpected Go build identity")
	}
	settings := make(map[string]string)
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != "linux" || settings["GOARCH"] != "amd64" || settings["CGO_ENABLED"] != "0" {
		return fmt.Errorf("candidate executable has unexpected platform or CGO settings")
	}
	return nil
}
