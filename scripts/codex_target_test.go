package scripts

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

func TestCodexTargetInstallerAcceptsOnlyTheLockedNativeRegularFile(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("native target installation is macOS-only")
	}
	arch, member := nativeCodexTestTarget(t)
	bundle := t.TempDir()
	archive := filepath.Join(bundle, "codex_0.149.1_darwin_"+arch+".tar.gz")
	writeCodexTargetArchive(t, archive, member, "#!/bin/sh\nprintf 'codex-cli 0.149.1\\n'\n", tar.TypeReg)
	lock := writeCodexTargetLock(t, arch, archive)
	outputDirectory := t.TempDir()
	output := filepath.Join(outputDirectory, "codex")

	command := exec.Command("sh", "install-codex-test-target.sh", lock, bundle, arch, output)
	if result, err := command.CombinedOutput(); err != nil {
		t.Fatalf("install target: %v; output=%q", err, result)
	}
	if result, err := exec.Command(output, "--version").CombinedOutput(); err != nil || string(result) != "codex-cli 0.149.1\n" {
		t.Fatalf("installed target = (%q, %v)", result, err)
	}
}

func TestCodexTargetInstallerRejectsUnsafeArchiveContents(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("native target installation is macOS-only")
	}
	arch, _ := nativeCodexTestTarget(t)
	bundle := t.TempDir()
	archive := filepath.Join(bundle, "codex_0.149.1_darwin_"+arch+".tar.gz")
	writeCodexTargetArchive(t, archive, "../escape", "unsafe\n", tar.TypeReg)
	lock := writeCodexTargetLock(t, arch, archive)
	output := filepath.Join(t.TempDir(), "codex")

	result, err := exec.Command("sh", "install-codex-test-target.sh", lock, bundle, arch, output).CombinedOutput()
	if err == nil || !strings.Contains(string(result), "unexpected path") {
		t.Fatalf("unsafe archive result = (%q, %v)", result, err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("unsafe archive created output: %v", err)
	}
}

func TestCodexTargetLockPinsBothOfficialAppleArchives(t *testing.T) {
	contents, err := os.ReadFile("codex-test-targets.lock")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"0.149.1|darwin|arm64|ed60f475c6dda6044c2c00fd7f33273cc3f3f98900ccd1204bfdf2fe935f3405|https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-aarch64-apple-darwin.tar.gz",
		"0.149.1|darwin|amd64|85fe7a837eb739dd5e1cc59a9c95b7b682048e5aacdc261505bae768fb1288ef|https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-x86_64-apple-darwin.tar.gz",
	} {
		if !strings.Contains(string(contents), want) {
			t.Errorf("target lock omits %q", want)
		}
	}
}

func TestCodexTargetFetcherAcceptsCommittedLockWithoutNetwork(t *testing.T) {
	output, calls := runCodexTargetFetcher(t, readCodexTargetLock(t))
	for _, archive := range []string{
		"codex_0.149.1_darwin_arm64.tar.gz",
		"codex_0.149.1_darwin_amd64.tar.gz",
	} {
		contents, err := os.ReadFile(filepath.Join(output, archive))
		if err != nil {
			t.Fatalf("read fetched %s: %v", archive, err)
		}
		if string(contents) != archive+"\n" {
			t.Fatalf("fetched %s contents = %q", archive, contents)
		}
	}
	if got := strings.Count(string(calls), "https://github.com/openai/codex/releases/download/rust-v0.149.1/"); got != 2 {
		t.Fatalf("approved download calls = %d, want 2; calls=%q", got, calls)
	}
}

func TestCodexTargetFetcherRejectsMalformedDigests(t *testing.T) {
	valid := readCodexTargetLock(t)
	for name, digest := range map[string]string{
		"62 characters": strings.Repeat("a", 62),
		"63 characters": strings.Repeat("a", 63),
		"65 characters": strings.Repeat("a", 65),
		"nonhex":        strings.Repeat("a", 63) + "g",
	} {
		t.Run(name, func(t *testing.T) {
			lock := strings.Replace(valid, "ed60f475c6dda6044c2c00fd7f33273cc3f3f98900ccd1204bfdf2fe935f3405", digest, 1)
			output, calls, result, err := runCodexTargetFetcherFailure(t, lock)
			if err == nil || !strings.Contains(string(result), "invalid SHA-256 digest") {
				t.Fatalf("fetch malformed digest result = (%q, %v)", result, err)
			}
			if len(calls) != 0 {
				t.Fatalf("malformed digest invoked download: %q", calls)
			}
			entries, readErr := os.ReadDir(output)
			if readErr != nil && !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("malformed digest left output entries: %#v", entries)
			}
		})
	}
}

func TestCodexTargetFetcherValidatesEveryLockRowBeforeDownloading(t *testing.T) {
	valid := readCodexTargetLock(t)
	for name, digest := range map[string]string{
		"short":  strings.Repeat("b", 63),
		"nonhex": strings.Repeat("b", 63) + "g",
	} {
		t.Run(name, func(t *testing.T) {
			lock := strings.Replace(
				valid,
				"85fe7a837eb739dd5e1cc59a9c95b7b682048e5aacdc261505bae768fb1288ef",
				digest,
				1,
			)
			output, calls, result, err := runCodexTargetFetcherFailure(t, lock)
			if err == nil || !strings.Contains(string(result), "invalid SHA-256 digest") {
				t.Fatalf("fetch later malformed digest result = (%q, %v)", result, err)
			}
			if len(calls) != 0 {
				t.Fatalf("later malformed digest invoked download: %q", calls)
			}
			entries, readErr := os.ReadDir(output)
			if readErr != nil && !os.IsNotExist(readErr) {
				t.Fatal(readErr)
			}
			if len(entries) != 0 {
				t.Fatalf("later malformed digest left partial outputs: %#v", entries)
			}
			staging, globErr := filepath.Glob(output + ".fetch.*")
			if globErr != nil || len(staging) != 0 {
				t.Fatalf("later malformed digest left staging outputs = (%q, %v)", staging, globErr)
			}
		})
	}
}

func readCodexTargetLock(t *testing.T) string {
	t.Helper()
	contents, err := os.ReadFile("codex-test-targets.lock")
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func runCodexTargetFetcher(t *testing.T, lock string) (string, []byte) {
	t.Helper()
	output, calls, result, err := runCodexTargetFetcherFailure(t, lock)
	if err != nil {
		t.Fatalf("fetch targets: %v; output=%q", err, result)
	}
	return output, calls
}

func runCodexTargetFetcherFailure(t *testing.T, lock string) (string, []byte, []byte, error) {
	t.Helper()
	root := t.TempDir()
	lockPath := filepath.Join(root, "targets.lock")
	if err := os.WriteFile(lockPath, []byte(lock), 0o600); err != nil {
		t.Fatal(err)
	}
	fakeBin := filepath.Join(root, "bin")
	if err := os.Mkdir(fakeBin, 0o700); err != nil {
		t.Fatal(err)
	}
	callsPath := filepath.Join(root, "curl.calls")
	writeFakeExecutable(t, filepath.Join(fakeBin, "curl"), `#!/bin/sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
archive="codex_0.149.1_darwin_arm64.tar.gz"
case "$url" in
  *codex-x86_64-apple-darwin.tar.gz) archive="codex_0.149.1_darwin_amd64.tar.gz" ;;
esac
printf '%s\n' "$url" >>"$ACS_FETCH_CALLS"
printf '%s\n' "$archive" >"$output"
`)
	writeFakeExecutable(t, filepath.Join(fakeBin, "shasum"), `#!/bin/sh
set -eu
file=
for argument do file="$argument"; done
case "$file" in
  *arm64.tar.gz) digest=ed60f475c6dda6044c2c00fd7f33273cc3f3f98900ccd1204bfdf2fe935f3405 ;;
  *amd64.tar.gz) digest=85fe7a837eb739dd5e1cc59a9c95b7b682048e5aacdc261505bae768fb1288ef ;;
  *) exit 1 ;;
esac
printf '%s  %s\n' "$digest" "$file"
`)
	output := filepath.Join(root, "output")
	command := exec.Command("sh", "fetch-codex-test-targets.sh", lockPath, output)
	command.Env = append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH"), "ACS_FETCH_CALLS="+callsPath)
	result, err := command.CombinedOutput()
	calls, readErr := os.ReadFile(callsPath)
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	return output, calls, result, err
}

func writeFakeExecutable(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
}

func nativeCodexTestTarget(t *testing.T) (string, string) {
	t.Helper()
	switch runtime.GOARCH {
	case "arm64":
		return "arm64", "codex-aarch64-apple-darwin"
	case "amd64":
		return "amd64", "codex-x86_64-apple-darwin"
	default:
		t.Fatalf("unsupported test architecture %q", runtime.GOARCH)
		return "", ""
	}
}

func writeCodexTargetLock(t *testing.T, arch, archive string) string {
	t.Helper()
	contents, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(contents))
	url := "https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-aarch64-apple-darwin.tar.gz"
	if arch == "amd64" {
		url = "https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-x86_64-apple-darwin.tar.gz"
	}
	path := filepath.Join(t.TempDir(), "targets.lock")
	if err := os.WriteFile(path, []byte("0.149.1|darwin|"+arch+"|"+digest+"|"+url+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeCodexTargetArchive(t *testing.T, path, name, contents string, kind byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o700, Size: int64(len(contents)), Typeflag: kind}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write([]byte(contents)); err != nil {
		t.Fatal(err)
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
