package launch

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/codexcompat"
	"golang.org/x/sys/unix"
)

func TestLinuxCodexPairRejectsSubstitution(t *testing.T) {
	linuxCleanupPrerequisites(t)
	for _, mode := range []string{"valid", "missing", "wrong-version", "symlink", "hardlink", "writable", "changed-cli", "dynamic"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			fixture := linuxTestELF(t, elf.EM_X86_64, "", nil)
			data, err := os.ReadFile(fixture.Name())
			if err != nil {
				t.Fatal(err)
			}
			cli, host := filepath.Join(root, "codex"), filepath.Join(root, "codex-code-mode-host")
			for _, path := range []string{cli, host} {
				if err := os.WriteFile(path, data, 0500); err != nil {
					t.Fatal(err)
				}
			}
			pair := codexcompat.LinuxPair{Version: codexcompat.LegacyVersion, CLIBytes: int64(len(data)), CompanionBytes: int64(len(data)),
				CLISHA256: fmt.Sprintf("%x", sha256.Sum256(data)), CompanionSHA256: fmt.Sprintf("%x", sha256.Sum256(data))}
			rewrite := func(path string, data []byte) error {
				if err := os.Remove(path); err != nil {
					return err
				}
				return os.WriteFile(path, data, 0500)
			}
			switch mode {
			case "missing":
				err = os.Remove(host)
			case "wrong-version":
				err = rewrite(host, append(data, '2'))
			case "symlink", "hardlink":
				other := filepath.Join(root, "other-host")
				if err = os.Rename(host, other); err == nil {
					if mode == "symlink" {
						err = os.Symlink(other, host)
					} else {
						err = os.Link(other, host)
					}
				}
			case "writable":
				err = os.Chmod(host, 0777)
			case "changed-cli":
				data[len(data)-1] ^= 1
				err = rewrite(cli, data)
			case "dynamic":
				dynamic := linuxTestELF(t, elf.EM_X86_64, "/lib64/ld-linux-x86-64.so.2", nil)
				data, err = os.ReadFile(dynamic.Name())
				if err == nil {
					err = rewrite(cli, data)
				}
				pair.CLIBytes, pair.CLISHA256 = int64(len(data)), fmt.Sprintf("%x", sha256.Sum256(data))
			}
			if err != nil {
				t.Fatal(err)
			}
			files, err := linuxCodexRuntimePairs(cli, []codexcompat.LinuxPair{pair})
			if (err == nil) != (mode == "valid") {
				t.Fatalf("pair verification: %v", err)
			}
			if mode == "valid" && (len(files) != 2 || files[0].path != cli || files[1].path != host) {
				t.Fatal("runtime broadened beyond the exact pair")
			}
			if _, err := linuxCodexRuntime(cli); err == nil {
				t.Fatal("synthetic bytes reached the real locked recipe")
			}
		})
	}
}

func TestLinuxCodexProductionAdmissionRemainsClosed(t *testing.T) {
	_, err := linuxCompileRecipe(linuxRecipeAdmission{}, linuxCodexRecipe, validatedProcessRequest{}, nil, false)
	assertLinuxUnsupported(t, err)
	t.Setenv("ACS_LINUX_EXPERIMENTAL", "1")
	assertLinuxUnsupported(t, NewProcessSandbox().Check(context.Background(), SandboxCheck{Executable: "codex"}))
	for _, args := range [][]string{nil, {"--version"}, {"login"}, {"exec", "prompt"}, {"mcp", "add", "evil"}} {
		_, err := linuxCompileRecipe(linuxRecipeAdmission{true}, linuxCodexRecipe,
			validatedProcessRequest{executable: "/usr/bin/codex", workspace: "/work", arguments: args}, nil, false)
		if err == nil {
			t.Fatal("unreviewed Codex invocation accepted")
		}
	}
}

func TestLinuxCodexMCPProtectionFailsBeforeLaunch(t *testing.T) {
	f := newLinuxPlanFixture()
	for _, directory := range []string{"/.codex", "/.acs", "/.acs/mcp"} {
		f.directory(f.request.sessionHome + directory)
	}
	for _, path := range []string{f.request.sessionHome + "/.codex/config.toml", f.request.sessionHome + "/.acs/mcp/recipes.json"} {
		f.file(path)
	}
	f.compile(t) // Positive control: this otherwise-valid writable HOME launches.
	for _, path := range []string{f.request.sessionHome + "/.codex/config.toml", f.request.sessionHome + "/.acs/mcp/recipes.json"} {
		f.request.sessionProtections = append(f.request.sessionProtections, validatedSessionProtection{path: path, identity: f.tree[path].identity})
	}
	// The current compiler cannot subtract immutable MCP inputs from writable
	// HOME. Preserve its closed gate; never discard these protections to launch.
	if _, err := compileLinuxFilesystemPlan(f.request, f.tree, linuxFilesystemFeatures{6, linuxUnixSocketsDenyCreation}, nil); err == nil {
		t.Fatal("Codex MCP protection was silently dropped")
	}
}

func TestLinuxCodexRejectsSelectedEnvironment(t *testing.T) {
	cleanup := linuxCleanupFixture(t)
	helper, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer helper.Close()
	result, err := linuxRunRecipe(context.Background(), linuxRecipeAdmission{true}, linuxRecipe{
		wire: linuxTestWire(), session: cleanup.lease.RootDir, codex: true,
	}, helper, helper, nil, [3]*os.File{}, linuxTestLease(t, map[string]string{"OPENAI_API_KEY": "unselected"}), cleanup)
	if !errors.Is(err, errLinuxRecipe) || !result.Settled || result.Exited {
		t.Fatalf("Codex environment override did not abort before launch: %+v %v", result, err)
	}
}

func TestLinuxCodexTransportHidesHostAuthentication(t *testing.T) {
	for _, key := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "CODEX_HOME", "OPENAI_API_KEY", "CODEX_API_KEY", "DBUS_SESSION_BUS_ADDRESS"} {
		t.Setenv(key, "host-auth-sentinel")
	}
	wire := linuxTestWire()
	wire.CodexHome = wire.Home + "/.codex"
	transport, err := linuxWriteTransport(wire, linuxTestLease(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	_, env, err := linuxReadTransport(transport)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(env, "\n"), "host-auth-sentinel") {
		t.Fatal("host authentication entered the sealed environment")
	}
	got := map[string]string{}
	for _, entry := range env {
		name, value, _ := strings.Cut(entry, "=")
		got[name] = value
	}
	for name, want := range map[string]string{"HOME": wire.Home, "CODEX_HOME": wire.Home + "/.codex",
		"XDG_CONFIG_HOME": wire.Home + "/.config", "XDG_DATA_HOME": wire.Home + "/.local/share",
		"XDG_CACHE_HOME": wire.Home + "/.cache", "XDG_STATE_HOME": wire.Home + "/.local/state"} {
		if got[name] != want {
			t.Fatalf("Codex lost its private %s: %q", name, got[name])
		}
	}
}

func TestLinuxCodexConfigurationProjection(t *testing.T) {
	for _, state := range []string{"absent-directory", "absent-file", "present"} {
		t.Run(state, func(t *testing.T) {
			f := newLinuxPlanFixture()
			project := f.request.workspace
			f.directory(project + "/nested")
			f.file(project + "/README")
			f.grant(project, PathAccessReadOnly)
			f.request.workspace = project + "/nested"
			if state != "absent-directory" {
				f.directory(project + "/.codex")
				f.directory(project + "/.codex/skills")
			}
			if state == "present" {
				f.file(project + "/.codex/config.toml")
				f.directory(project + "/nested/.codex")
				f.file(project + "/nested/.codex/config.toml")
			}
			f.directory(f.request.sessionHome + "/.codex")
			f.file(f.request.sessionHome + "/.codex/config.toml")
			f.file(f.request.sessionHome + "/.codex/auth.json")
			original := append([]FilesystemExclusion(nil), f.request.filesystemExclusions...)
			request, err := linuxCodexConfigurationRequest(f.request, f.tree)
			if err != nil || !reflect.DeepEqual(original, f.request.filesystemExclusions) {
				t.Fatalf("configuration request: %v", err)
			}
			plan, err := compileLinuxFilesystemPlan(request, f.tree, f.features, nil)
			if err != nil {
				t.Fatal(err)
			}
			linuxAddCodexConfiguration(&plan, request.sessionHome)
			if planMount(t, plan, request.sessionHome).kind != linuxMountReadWrite ||
				planMount(t, plan, request.sessionHome+"/.codex/config.toml").kind != linuxMountEmptyCodexConfig {
				t.Fatal("Codex config did not use the empty selection while preserving writable authentication")
			}
			for _, config := range []string{project + "/.codex/config.toml", project + "/nested/.codex/config.toml"} {
				for _, mount := range plan.mounts {
					if mount.source != "" && withinOrEqual(mount.source, config) {
						t.Fatalf("project configuration remains reachable through %+v", mount)
					}
				}
			}
			if planMount(t, plan, project+"/README").kind != linuxMountReadOnly {
				t.Fatal("project data disappeared with the unselected configuration")
			}
			if state != "absent-directory" && planMount(t, plan, project+"/.codex/skills").kind != linuxMountReadOnly {
				t.Fatal("non-config project content disappeared")
			}
			request.workspaceAccess = WorkspaceAccessReadWrite
			if _, err := compileLinuxFilesystemPlan(request, f.tree, f.features, nil); err == nil {
				t.Fatal("writable project could recreate an unselected configuration")
			}
		})
	}
}

func TestLinuxCodexConfigurationUsesSealedMount(t *testing.T) {
	wire := linuxTestWire()
	wire.CodexHome = wire.Home + "/.codex"
	plan := linuxFilesystemPlan{handledAccess: linuxHandledFilesystem, scoped: 3, unixSockets: linuxUnixSocketsDenyCreation,
		mounts: []linuxMount{{kind: linuxMountDirectory, destination: "/"}, {kind: linuxMountSealRoot, destination: "/"}},
		rules:  []linuxLandlockRule{{wire.Rules[0].Path, wire.Rules[0].Access}}}
	linuxAddCodexConfiguration(&plan, wire.Home)
	file, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	prepare := func(plan linuxFilesystemPlan, wire linuxLaunchWire) (*linuxBwrapLaunch, error) {
		return linuxPrepareBwrapWith(context.Background(), plan, wire, linuxTestLease(t, nil), file, file, file,
			[3]*os.File{file, file, file}, nil, func() (*os.File, error) { return os.Open("/proc/self/exe") })
	}
	prepared, err := prepare(plan, wire)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.close()
	found := false
	args := prepared.command.Args
	for i, arg := range args {
		if arg != "--ro-bind-data" || i+2 >= len(args) || args[i+2] != wire.CodexHome+"/config.toml" {
			continue
		}
		fd, err := strconv.Atoi(args[i+1])
		if err != nil || fd < 3 || fd-3 >= len(prepared.command.ExtraFiles) {
			t.Fatal("configuration did not use a private descriptor")
		}
		config := prepared.command.ExtraFiles[fd-3]
		data, err := io.ReadAll(config)
		if err != nil || string(data) != linuxCodexEmptyConfig {
			t.Fatalf("selected configuration bytes: %q %v", data, err)
		}
		if seals, err := unix.FcntlInt(config.Fd(), unix.F_GET_SEALS, 0); err != nil || seals != linuxTransportSeals {
			t.Fatal("selected configuration is mutable")
		}
		found = true
	}
	if !found {
		t.Fatal("unselected Session config was not replaced by a read-only sealed mount")
	}
	for _, failure := range []string{"missing", "duplicate", "wrong-path", "source", "no-codex-home"} {
		t.Run(failure, func(t *testing.T) {
			bad := plan
			bad.mounts = append([]linuxMount(nil), plan.mounts...)
			badWire := wire
			for i, mount := range bad.mounts {
				if mount.kind != linuxMountEmptyCodexConfig {
					continue
				}
				switch failure {
				case "missing":
					bad.mounts = append(bad.mounts[:i], bad.mounts[i+1:]...)
				case "duplicate":
					bad.mounts = append(bad.mounts[:i], append([]linuxMount{mount}, bad.mounts[i:]...)...)
				case "wrong-path":
					bad.mounts[i].destination = "/host/config.toml"
				case "source":
					bad.mounts[i].source = "/host/config.toml"
				case "no-codex-home":
					badWire.CodexHome = ""
				}
				break
			}
			if prepared, err := prepare(bad, badWire); err == nil || prepared != nil {
				if prepared != nil {
					prepared.close()
				}
				t.Fatal("invalid selected configuration mount accepted")
			}
		})
	}
}
