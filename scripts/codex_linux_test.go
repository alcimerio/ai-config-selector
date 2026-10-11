package scripts

import (
	"archive/tar"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/codexcompat"
)

func linuxCodexBundle(t *testing.T, version, companionMember string, companionKind byte) (string, string) {
	t.Helper()
	root := t.TempDir()
	var rows []string
	for _, role := range []string{"codex", "codex-code-mode-host"} {
		stem := strings.ReplaceAll(role, "-", "_")
		archive := filepath.Join(root, stem+"_"+version+"_linux_amd64.tar.gz")
		member, kind := role+"-x86_64-unknown-linux-musl", byte(tar.TypeReg)
		if role != "codex" {
			member, kind = companionMember, companionKind
		}
		// Invalid executable bytes are deliberate: Linux installation must not
		// run a target outside the contained native qualification harness.
		content := "synthetic " + version + " " + role
		if kind != tar.TypeReg {
			content = ""
		}
		writeCodexTargetArchive(t, archive, member, content, kind)
		data, err := os.ReadFile(archive)
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, fmt.Sprintf("%s|linux|amd64|%x|https://github.com/openai/codex/releases/download/rust-v%s/%s-x86_64-unknown-linux-musl.tar.gz\n", version, sha256.Sum256(data), version, role))
	}
	lock := filepath.Join(root, "targets.lock")
	if err := os.WriteFile(lock, []byte(strings.Join(rows, "")), 0600); err != nil {
		t.Fatal(err)
	}
	return root, lock
}

func TestLinuxCodexInstallerPairContract(t *testing.T) {
	for _, pair := range codexcompat.LinuxAMD64Pairs() {
		for _, mode := range []string{"valid", "corrupt-companion", "missing-companion", "duplicate", "cross-version", "traversal", "symlink", "arm64", "wrong-host"} {
			t.Run(pair.Version+"/"+mode, func(t *testing.T) {
				member, kind := "codex-code-mode-host-x86_64-unknown-linux-musl", byte(tar.TypeReg)
				if mode == "traversal" {
					member = "../escape"
				}
				if mode == "symlink" {
					kind = tar.TypeSymlink
				}
				bundle, lock := linuxCodexBundle(t, pair.Version, member, kind)
				data, _ := os.ReadFile(lock)
				switch mode {
				case "duplicate":
					data = append(data, data...)
				case "cross-version":
					other := codexcompat.CurrentVersion
					if pair.Version == other {
						other = codexcompat.LegacyVersion
					}
					data = []byte(strings.Replace(string(data), "/rust-v"+pair.Version+"/codex-code-mode-host-", "/rust-v"+other+"/codex-code-mode-host-", 1))
				case "arm64":
					data = []byte(strings.ReplaceAll(string(data), "|amd64|", "|arm64|"))
				}
				if err := os.WriteFile(lock, data, 0600); err != nil {
					t.Fatal(err)
				}
				hostArchive := filepath.Join(bundle, "codex_code_mode_host_"+pair.Version+"_linux_amd64.tar.gz")
				if mode == "corrupt-companion" {
					if err := os.WriteFile(hostArchive, []byte("corrupt"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "missing-companion" {
					if err := os.Remove(hostArchive); err != nil {
						t.Fatal(err)
					}
				}
				fakeBin := t.TempDir()
				host := "Linux"
				if mode == "wrong-host" {
					host = "Darwin"
				}
				writeFakeExecutable(t, filepath.Join(fakeBin, "uname"), "#!/bin/sh\ncase \"$1\" in -s) echo "+host+";; -m) echo x86_64;; esac\n")
				output := filepath.Join(t.TempDir(), "codex")
				cmd := exec.Command("sh", "install-codex-test-target.sh", lock, bundle, "amd64", output, pair.Version)
				cmd.Env = append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH"))
				result, err := cmd.CombinedOutput()
				if mode == "valid" {
					if err != nil {
						t.Fatalf("install: %v %s", err, result)
					}
					for _, role := range []string{"codex", "codex-code-mode-host"} {
						path := filepath.Join(filepath.Dir(output), role)
						got, readErr := os.ReadFile(path)
						info, statErr := os.Stat(path)
						if readErr != nil || statErr != nil || info.Mode().Perm() != 0500 || string(got) != "synthetic "+pair.Version+" "+role {
							t.Fatal("installed pair bytes or permissions changed")
						}
					}
				} else {
					if err == nil {
						t.Fatal("unsafe pair installed")
					}
					entries, readErr := os.ReadDir(filepath.Dir(output))
					if readErr != nil || len(entries) != 0 {
						t.Fatal("failed pair installation left partial output")
					}
				}
			})
		}
	}
}

func TestLinuxCodexLockAndFetcher(t *testing.T) {
	data, err := os.ReadFile("codex-linux-test-targets.lock")
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Split(strings.TrimSpace(string(data)), "\n")) != 5 {
		t.Fatal("Linux lock must contain exactly the two reviewed amd64 pairs")
	}
	// Validate the committed lock without performing network I/O. The Darwin
	// fetch tests exercise the shared download and SHA-256 failure path.
	for _, contents := range []string{string(data), string(data) + readCodexTargetLock(t)} {
		lock := filepath.Join(t.TempDir(), "targets.lock")
		if err := os.WriteFile(lock, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", "-c", `set -eu; fail() { echo "$1" >&2; exit 1; }; lock_file="$1"; . ./codex-target-lock.sh; validate_codex_lock; test "$old_cli:$old_host:$new_cli:$new_host" = 1:1:1:1`, "validate", lock)
		if out, err := cmd.CombinedOutput(); (err == nil) != (contents == string(data)) {
			t.Fatalf("Linux lock validation: %v %s", err, out)
		}
	}
}

func TestLinuxCodexFetcherVerifiesBothPairs(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		t.Run(fmt.Sprint(corrupt), func(t *testing.T) {
			bundle := t.TempDir()
			var lock []byte
			for _, pair := range codexcompat.LinuxAMD64Pairs() {
				source, path := linuxCodexBundle(t, pair.Version, "codex-code-mode-host-x86_64-unknown-linux-musl", tar.TypeReg)
				rows, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				lock = append(lock, rows...)
				for _, stem := range []string{"codex", "codex_code_mode_host"} {
					name := stem + "_" + pair.Version + "_linux_amd64.tar.gz"
					data, err := os.ReadFile(filepath.Join(source, name))
					if err != nil {
						t.Fatal(err)
					}
					if corrupt && pair.Version == codexcompat.CurrentVersion && stem != "codex" {
						data = []byte("corrupt companion")
					}
					if err := os.WriteFile(filepath.Join(bundle, name), data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			lockPath := filepath.Join(t.TempDir(), "targets.lock")
			if err := os.WriteFile(lockPath, lock, 0600); err != nil {
				t.Fatal(err)
			}
			fakeBin := t.TempDir()
			writeFakeExecutable(t, filepath.Join(fakeBin, "curl"), `#!/bin/sh
set -eu
while [ "$#" -gt 0 ]; do
  case "$1" in --output) output="$2"; shift 2;; https://*) url="$1"; shift;; *) shift;; esac
done
case "$url" in */rust-v0.149.1/*) version=0.149.1;; */rust-v0.156.0/*) version=0.156.0;; *) exit 1;; esac
case "$url" in */codex-code-mode-host-*) stem=codex_code_mode_host;; *) stem=codex;; esac
cp "$ACS_CODEX_FIXTURE_BUNDLE/${stem}_${version}_linux_amd64.tar.gz" "$output"
`)
			output := filepath.Join(t.TempDir(), "download")
			cmd := exec.Command("sh", "fetch-codex-test-targets.sh", lockPath, output)
			cmd.Env = append(os.Environ(), "PATH="+fakeBin+":"+os.Getenv("PATH"), "ACS_CODEX_FIXTURE_BUNDLE="+bundle)
			data, err := cmd.CombinedOutput()
			if corrupt {
				if err == nil || !strings.Contains(string(data), "digest did not match") {
					t.Fatalf("corrupt fetch: %v %s", err, data)
				}
				if _, err := os.Stat(output); !os.IsNotExist(err) {
					t.Fatal("failed fetch published a partial pair")
				}
			} else {
				entries, readErr := os.ReadDir(output)
				if err != nil || readErr != nil || len(entries) != 4 {
					t.Fatalf("fetch failed: %v %s", err, data)
				}
			}
		})
	}
}
