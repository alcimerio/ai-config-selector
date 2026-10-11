package launch

import (
	"context"
	"crypto/sha256"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/codexcompat"
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
	for _, key := range []string{"CODEX_HOME", "OPENAI_API_KEY", "CODEX_API_KEY", "DBUS_SESSION_BUS_ADDRESS"} {
		t.Setenv(key, "host-auth-sentinel")
	}
	wire := linuxTestWire()
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
	found := false
	for _, entry := range env {
		found = found || entry == "HOME="+wire.Home
	}
	if !found {
		t.Fatal("Codex lost its private HOME")
	}
}
