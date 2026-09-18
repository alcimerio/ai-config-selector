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

func TestCodexTargetLockPinsTheOfficialAppleSiliconArchive(t *testing.T) {
	contents, err := os.ReadFile("codex-test-targets.lock")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"0.149.1|darwin|arm64|aae1c0c9459700a2e897adadd647351140ae7933ad73bd8d3af6505c69a4f3fd|https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-code-mode-host-aarch64-apple-darwin.tar.gz",
		"0.149.1|darwin|arm64|ed60f475c6dda6044c2c00fd7f33273cc3f3f98900ccd1204bfdf2fe935f3405|https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-aarch64-apple-darwin.tar.gz",
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
		"codex_code_mode_host_0.149.1_darwin_arm64.tar.gz",
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

func TestCodexTargetFetcherRejectsAnExtraIntelLockEntryBeforeDownloading(t *testing.T) {
	lock := readCodexTargetLock(t) + "0.149.1|darwin|amd64|" + strings.Repeat("a", 64) + "|https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-x86_64-apple-darwin.tar.gz\n"
	_, calls, result, err := runCodexTargetFetcherFailure(t, lock)
	if err == nil || !strings.Contains(string(result), "approved release asset") {
		t.Fatalf("extra Intel target result = (%q, %v)", result, err)
	}
	if len(calls) != 0 {
		t.Fatalf("extra Intel target invoked download: %q", calls)
	}
}

func TestCodexTargetFetcherRejectsMalformedPhysicalRowsBeforeDownloading(t *testing.T) {
	valid := readCodexTargetLock(t)
	for name, lock := range map[string]string{
		"empty version field":    valid + "|darwin|arm64|" + strings.Repeat("a", 64) + "|https://example.invalid/ignored.tar.gz\n",
		"unterminated final row": valid + "malformed",
		"blank row":              strings.Replace(valid, "\n", "\n\n", 1),
		"incomplete row":         valid + "0.149.1|darwin|arm64\n",
		"trailing empty field":   strings.Replace(valid, ".tar.gz\n", ".tar.gz|\n", 1),
	} {
		t.Run(name, func(t *testing.T) {
			output, calls, result, err := runCodexTargetFetcherFailure(t, lock)
			if err == nil {
				t.Fatalf("malformed physical row succeeded: output=%q", result)
			}
			if len(calls) != 0 {
				t.Fatalf("malformed physical row invoked download: %q", calls)
			}
			if _, statErr := os.Lstat(output); !os.IsNotExist(statErr) {
				t.Fatalf("malformed physical row published output: %v", statErr)
			}
			staging, globErr := filepath.Glob(output + ".fetch.*")
			if globErr != nil || len(staging) != 0 {
				t.Fatalf("malformed physical row left staging outputs = (%q, %v)", staging, globErr)
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
case "$url" in
  *codex-code-mode-host-aarch64-apple-darwin.tar.gz) archive="codex_code_mode_host_0.149.1_darwin_arm64.tar.gz" ;;
  *) archive="codex_0.149.1_darwin_arm64.tar.gz" ;;
esac
printf '%s\n' "$url" >>"$ACS_FETCH_CALLS"
printf '%s\n' "$archive" >"$output"
`)
	writeFakeExecutable(t, filepath.Join(fakeBin, "shasum"), `#!/bin/sh
set -eu
file=
for argument do file="$argument"; done
case "$file" in
  *codex_code_mode_host_0.149.1_darwin_arm64.tar.gz) digest=aae1c0c9459700a2e897adadd647351140ae7933ad73bd8d3af6505c69a4f3fd ;;
  *arm64.tar.gz) digest=ed60f475c6dda6044c2c00fd7f33273cc3f3f98900ccd1204bfdf2fe935f3405 ;;
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
	hostArchive := filepath.Join(filepath.Dir(archive), "codex_code_mode_host_0.149.1_darwin_arm64.tar.gz")
	if _, err := os.Stat(hostArchive); os.IsNotExist(err) {
		writeCodexTargetArchive(t, hostArchive, "codex-code-mode-host-aarch64-apple-darwin", "synthetic companion bytes", tar.TypeReg)
	}
	hostBytes, err := os.ReadFile(hostArchive)
	if err != nil {
		t.Fatal(err)
	}
	hostRow := fmt.Sprintf("0.149.1|darwin|arm64|%x|https://github.com/openai/codex/releases/download/rust-v0.149.1/codex-code-mode-host-aarch64-apple-darwin.tar.gz\n", sha256.Sum256(hostBytes))
	path := filepath.Join(t.TempDir(), "targets.lock")
	if err := os.WriteFile(path, []byte("0.149.1|darwin|"+arch+"|"+digest+"|"+url+"\n"+hostRow), 0o600); err != nil {
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

// Shell contract tests use synthetic scripts and a synthetic uname, never a
// foreign target binary. They validate archive staging on any host.
func TestCodexCompanionInstallerContract(t *testing.T) {
	for _, tc := range []struct {
		name, member     string
		kind             byte
		corrupt, missing bool
	}{
		{name: "valid", member: "codex-code-mode-host-aarch64-apple-darwin", kind: tar.TypeReg},
		{name: "second-move-failure", member: "codex-code-mode-host-aarch64-apple-darwin", kind: tar.TypeReg},
		{name: "publication-signal", member: "codex-code-mode-host-aarch64-apple-darwin", kind: tar.TypeReg},
		{name: "traversal", member: "../escape", kind: tar.TypeReg},
		{name: "symlink", member: "codex-code-mode-host-aarch64-apple-darwin", kind: tar.TypeSymlink},
		{name: "checksum", member: "codex-code-mode-host-aarch64-apple-darwin", kind: tar.TypeReg, corrupt: true},
		{name: "missing", member: "codex-code-mode-host-aarch64-apple-darwin", kind: tar.TypeReg, missing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			archive := filepath.Join(root, "codex_0.149.1_darwin_arm64.tar.gz")
			writeCodexTargetArchive(t, archive, "codex-aarch64-apple-darwin", "#!/bin/sh\nprintf 'codex-cli 0.149.1\\n'\n", tar.TypeReg)
			hostArchive := filepath.Join(root, "codex_code_mode_host_0.149.1_darwin_arm64.tar.gz")
			content := "synthetic companion bytes"
			if tc.kind != tar.TypeReg {
				content = ""
			}
			writeCodexTargetArchive(t, hostArchive, tc.member, content, tc.kind)
			lock := writeCodexTargetLock(t, "arm64", archive)
			if tc.corrupt {
				if err := os.WriteFile(hostArchive, []byte("corrupt"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.missing {
				if err := os.Remove(hostArchive); err != nil {
					t.Fatal(err)
				}
			}
			fakeBin := t.TempDir()
			writeFakeExecutable(t, filepath.Join(fakeBin, "uname"), "#!/bin/sh\ncase \"$1\" in -s) echo Darwin;; -m) echo arm64;; *) exit 1;; esac\n")
			if tc.name == "second-move-failure" || tc.name == "publication-signal" {
				realMV, err := exec.LookPath("mv")
				if err != nil {
					t.Fatal(err)
				}
				t.Setenv("ACS_REAL_MV", realMV)
				t.Setenv("ACS_INSTALL_FAILURE", tc.name)
				writeFakeExecutable(t, filepath.Join(fakeBin, "mv"), `#!/bin/sh
set -eu
case "$1:$ACS_INSTALL_FAILURE" in
  */codex-aarch64-apple-darwin:second-move-failure) exit 1 ;;
esac
"$ACS_REAL_MV" "$@"
case "$1:$ACS_INSTALL_FAILURE" in
  */codex-code-mode-host-aarch64-apple-darwin:publication-signal) kill -TERM "$PPID" ;;
esac
`)
			}
			output := filepath.Join(t.TempDir(), "codex")
			command := exec.Command("sh", "install-codex-test-target.sh", lock, root, "arm64", output)
			command.Env = append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH"))
			result, err := command.CombinedOutput()
			if tc.name == "valid" {
				if err != nil {
					t.Fatalf("install failed: %v %s", err, result)
				}
				host := filepath.Join(filepath.Dir(output), "codex-code-mode-host")
				got, err := os.ReadFile(host)
				if err != nil || string(got) != content {
					t.Fatalf("installed host changed: %q %v", got, err)
				}
				info, err := os.Stat(host)
				if err != nil || info.Mode().Perm() != 0500 {
					t.Fatal("host permissions differ")
				}
			} else {
				if err == nil {
					t.Fatal("unsafe companion accepted")
				}
				for _, path := range []string{output, filepath.Join(filepath.Dir(output), "codex-code-mode-host"), filepath.Join(filepath.Dir(output), "escape")} {
					if _, err := os.Lstat(path); !os.IsNotExist(err) {
						t.Fatalf("failed install published %s: %v", path, err)
					}
				}
			}
		})
	}
}

func TestCodexFetcherRequiresOneOfEachAsset(t *testing.T) {
	lock := readCodexTargetLock(t)
	lines := strings.Split(strings.TrimSpace(lock), "\n")
	for _, bad := range []string{strings.Join(lines[:len(lines)-1], "\n") + "\n", lock + lines[len(lines)-1] + "\n"} {
		_, calls, _, err := runCodexTargetFetcherFailure(t, bad)
		if err == nil || len(calls) != 0 {
			t.Fatal("missing/duplicate host lock downloaded assets")
		}
	}
}
