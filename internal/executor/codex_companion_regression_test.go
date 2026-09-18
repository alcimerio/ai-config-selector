package executor

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func companionRegressionFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0700); err != nil {
		t.Fatal(err)
	}
}

func companionRegressionEmpty(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("operation snapshots remain: entries=%d err=%v", len(entries), err)
	}
}

func TestCodexCompanionSnapshotBytesPermissionsAndCleanup(t *testing.T) {
	for _, withHost := range []bool{false, true} {
		name := "absent"
		if withHost {
			name = "present"
		}
		t.Run(name, func(t *testing.T) {
			source := t.TempDir()
			cli := filepath.Join(source, "codex")
			host := filepath.Join(source, "codex-code-mode-host")
			companionRegressionFile(t, cli, "synthetic-cli")
			if withHost {
				companionRegressionFile(t, host, "synthetic-host")
			}
			root := t.TempDir()
			snapshot, cleanup, err := newPinnedExecutable(cli).Snapshot(root)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			if snapshot == cli || filepath.Base(snapshot) != "codex" || filepath.Dir(filepath.Dir(snapshot)) != root {
				t.Fatalf("snapshot is not operation-local: %s", snapshot)
			}
			want := map[string]string{"codex": "synthetic-cli"}
			if withHost {
				want["codex-code-mode-host"] = "synthetic-host"
			}
			entries, err := os.ReadDir(filepath.Dir(snapshot))
			if err != nil || len(entries) != len(want) {
				t.Fatalf("snapshot entries=%d err=%v", len(entries), err)
			}
			for name, body := range want {
				path := filepath.Join(filepath.Dir(snapshot), name)
				got, err := os.ReadFile(path)
				if err != nil || string(got) != body {
					t.Fatalf("copied %s bytes differ: %v", name, err)
				}
				info, err := os.Lstat(path)
				if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0500 {
					t.Fatalf("copied %s mode/type differs: %v", name, err)
				}
				original, err := os.Stat(filepath.Join(source, name))
				if err != nil || os.SameFile(original, info) {
					t.Fatalf("snapshot %s aliases source: %v", name, err)
				}
			}
			cleanup()
			companionRegressionEmpty(t, root)
			if got, err := os.ReadFile(cli); err != nil || string(got) != "synthetic-cli" {
				t.Fatal("cleanup changed source CLI")
			}
			if withHost {
				if got, err := os.ReadFile(host); err != nil || string(got) != "synthetic-host" {
					t.Fatal("cleanup changed source companion")
				}
			}
		})
	}
}

func TestCodexCompanionSourceChangesAfterPinRefuseSnapshot(t *testing.T) {
	for _, change := range []string{"appearance", "preferred-resource", "content", "mode", "inode", "removed"} {
		t.Run(change, func(t *testing.T) {
			source := t.TempDir()
			cli := filepath.Join(source, "codex")
			host := filepath.Join(source, "codex-code-mode-host")
			if change == "preferred-resource" {
				cli = filepath.Join(source, "bin", "codex")
				host = filepath.Join(source, "bin", "codex-code-mode-host")
				companionRegressionFile(t, filepath.Join(source, "codex-package.json"), `{"version":"0.149.1"}`)
			}
			companionRegressionFile(t, cli, "synthetic-cli")
			if change != "appearance" {
				companionRegressionFile(t, host, "synthetic-host")
			}
			pinned := newPinnedExecutable(cli)
			if _, err := pinned.Resolve(); err != nil {
				t.Fatal(err)
			}
			original, statErr := os.Stat(host)
			if change != "appearance" && statErr != nil {
				t.Fatal(statErr)
			}
			switch change {
			case "appearance":
				companionRegressionFile(t, host, "synthetic-host")
			case "preferred-resource":
				companionRegressionFile(t, filepath.Join(source, "codex-resources", "codex-code-mode-host"), "synthetic-host")
			case "content":
				companionRegressionFile(t, host, "synthetic-HOST")
			case "mode":
				if err := os.Chmod(host, 0500); err != nil {
					t.Fatal(err)
				}
			case "inode":
				replacement := host + ".replacement"
				companionRegressionFile(t, replacement, "synthetic-host")
				if err := os.Rename(replacement, host); err != nil {
					t.Fatal(err)
				}
			case "removed":
				if err := os.Remove(host); err != nil {
					t.Fatal(err)
				}
			}
			// Preserve size/mode/mtime for these cases so digest and inode checks,
			// rather than only incidental timestamp changes, must catch mutation.
			if change == "content" || change == "inode" {
				if err := os.Chtimes(host, original.ModTime(), original.ModTime()); err != nil {
					t.Fatal(err)
				}
			}
			root := t.TempDir()
			snapshot, cleanup, err := pinned.Snapshot(root)
			if cleanup != nil {
				defer cleanup()
			}
			if err == nil || snapshot != "" {
				t.Fatalf("changed source reached snapshot: path=%q err=%v", snapshot, err)
			}
			companionRegressionEmpty(t, root)
		})
	}
}

// Limit only a child test process. Real CLI/host bytes are never executed.
// The file-size limit permits the CLI copy but forces a partial companion copy.
func TestCodexCompanionPartialCopyFailureCleansOperation(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^TestCodexCompanionCopyLimitHelper$", "-test.count=1", "-test.v")
	command.Env = append(os.Environ(), "ACS_TEST_COMPANION_COPY_LIMIT=1")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil || err != nil {
		t.Fatalf("bounded copy failure child: %v context=%v output=%s", err, ctx.Err(), output)
	}
	if !bytes.Contains(output, []byte("partial companion copy refused and operation removed")) {
		t.Fatal("child omitted copy failure receipt")
	}
}

func TestCodexCompanionCopyLimitHelper(t *testing.T) {
	if os.Getenv("ACS_TEST_COMPANION_COPY_LIMIT") != "1" {
		t.Skip("private file-size limit child")
	}
	source := t.TempDir()
	cli := filepath.Join(source, "codex")
	host := filepath.Join(source, "codex-code-mode-host")
	companionRegressionFile(t, cli, "synthetic-cli")
	companionRegressionFile(t, host, strings.Repeat("H", 4096))
	pinned := newPinnedExecutable(cli)
	if _, err := pinned.Resolve(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	signal.Ignore(syscall.SIGXFSZ)
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		t.Fatal(err)
	}
	limit.Cur = 128
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limit); err != nil {
		t.Fatal(err)
	}
	snapshot, cleanup, err := pinned.Snapshot(root)
	if cleanup != nil {
		defer cleanup()
	}
	if err == nil || snapshot != "" || !strings.Contains(err.Error(), "code-mode host changed while copying") {
		t.Fatalf("did not reach partial companion-copy failure: %q %v", snapshot, err)
	}
	companionRegressionEmpty(t, root)
	if info, err := os.Stat(host); err != nil || info.Size() != 4096 {
		t.Fatal("failed snapshot damaged source")
	}
	t.Log("partial companion copy refused and operation removed")
}

func TestCodexCompanionPreparedAuthorityUsesOnlyPrivateSibling(t *testing.T) {
	for _, withHost := range []bool{false, true} {
		name := "absent"
		if withHost {
			name = "present"
		}
		t.Run(name, func(t *testing.T) {
			auth := testChatGPTAuthJSON(t, "user", "workspace")
			registry, _, _, sessions := newBindingTestRegistry(t, "work", auth)
			source := filepath.Join(filepath.Dir(sessions), "source-bin")
			cli := filepath.Join(source, "codex")
			host := filepath.Join(source, "codex-code-mode-host")
			companionRegressionFile(t, cli, "synthetic-cli")
			if withHost {
				companionRegressionFile(t, host, "synthetic-host")
			}
			supplied := filepath.Join(filepath.Dir(sessions), "supplied-runtime")
			companionRegressionFile(t, supplied, "supplied")
			var seenCompanions []string
			sandbox := &fakeLoginSandbox{version: SupportedCodexVersion, prepareHook: func(request launch.ProcessRequest) {
				got, err := os.ReadFile(request.Executable)
				if err != nil || string(got) != "synthetic-cli" {
					t.Fatal("process did not receive copied CLI")
				}
				companion := filepath.Join(filepath.Dir(request.Executable), "codex-code-mode-host")
				expected := []string{supplied}
				if withHost {
					expected = append(expected, companion)
					got, err := os.ReadFile(companion)
					if err != nil || string(got) != "synthetic-host" {
						t.Fatal("process did not receive copied companion")
					}
					info, err := os.Lstat(companion)
					if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0500 {
						t.Fatal("process companion permissions/type differ")
					}
					seenCompanions = append(seenCompanions, companion)
				} else if _, err := os.Lstat(companion); !os.IsNotExist(err) {
					t.Fatal("absent host manufactured")
				}
				if !reflect.DeepEqual(request.RuntimeInputs, expected) {
					t.Fatalf("process runtime authority=%q want=%q", request.RuntimeInputs, expected)
				}
			}}
			registry.execution = newCodexExecutionRunner(codexLoginConfig{BinaryPath: cli, SupportedVersion: SupportedCodexVersion, SessionsDirectory: sessions, WorkingDirectory: registry.workingDirectory}, sandbox)
			inputs := []string{supplied}
			plan := authority.New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", authority.TargetRequirements{Recipe: authority.RecipeCodex, Executable: cli, RuntimeInputs: inputs}).WithAuthRef("work")
			code, err := registry.ExecuteCodex(context.Background(), CodexRequest{ResolvedPlan: &plan})
			if code != 0 || err != nil {
				t.Fatalf("fake contained execution=(%d,%v)", code, err)
			}
			if len(sandbox.requests) != 2 {
				t.Fatalf("requests=%d want version and interactive", len(sandbox.requests))
			}
			expected := []string{supplied}
			if withHost {
				expected = append(expected, filepath.Join(filepath.Dir(sandbox.check.Executable), "codex-code-mode-host"))
			}
			if !reflect.DeepEqual(sandbox.check.RuntimeInputs, expected) {
				t.Fatalf("Check authority=%q want=%q", sandbox.check.RuntimeInputs, expected)
			}
			if !reflect.DeepEqual(inputs, []string{supplied}) {
				t.Fatal("source runtime input slice mutated")
			}
			for _, request := range sandbox.requests {
				if request.Executable != sandbox.check.Executable || request.Executable == cli {
					t.Fatal("Check and run do not share private executable")
				}
			}
			for _, path := range append(seenCompanions, sandbox.check.Executable) {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatalf("successful settlement retained copied file %s: %v", path, err)
				}
			}
		})
	}
}
