package launch

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/alcimerio/ai-config-selector/internal/codexcompat"
	"github.com/alcimerio/ai-config-selector/internal/linuxprobe"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func linuxCodexTestRoot(t *testing.T) string {
	t.Helper()
	root := os.Getenv("ACS_TEST_CODEX_LINUX_ROOT")
	if root == "" {
		linuxNativeUnavailable(t, "ACS_TEST_CODEX_LINUX_ROOT must contain both locked version directories with codex and codex-code-mode-host")
	}
	if !filepath.IsAbs(root) {
		t.Fatal("ACS_TEST_CODEX_LINUX_ROOT must be absolute")
	}
	return root
}

// Actual archive members and ELF metadata, without executing either binary.
func TestLinuxCodexPublishedPairs(t *testing.T) {
	root := linuxCodexTestRoot(t)
	linuxCleanupPrerequisites(t)
	for _, pair := range codexcompat.LinuxAMD64Pairs() {
		t.Run(pair.Version, func(t *testing.T) {
			path := filepath.Join(root, pair.Version, "codex")
			files, err := linuxCodexRuntime(path)
			if err != nil || len(files) != 2 || files[0].node.identity.size != pair.CLIBytes || files[1].node.identity.size != pair.CompanionBytes {
				t.Fatal("installed pair differs from locked static amd64 bytes")
			}
			if _, err := linuxDiscoverRuntime(path, false); err == nil {
				t.Fatal("Codex bypassed the generic runtime size bound")
			}
		})
	}
}

func TestLinuxNativeCodexPairs(t *testing.T) {
	linuxNativePrerequisites(t)
	report := linuxprobe.Probe(context.Background())
	if !report.PrerequisitesPassed() {
		var missing []string
		for _, check := range report.Checks {
			if check.Status != "pass" {
				missing = append(missing, check.ID+":"+check.Code)
			}
		}
		linuxNativeUnavailable(t, strings.Join(missing, ", "))
	}
	installed := linuxCodexTestRoot(t)
	for _, pair := range codexcompat.LinuxAMD64Pairs() {
		for _, mode := range []string{"version", "status-absent", "status-selected", "mcp", "interactive"} {
			t.Run(pair.Version+"/"+mode, func(t *testing.T) {
				// Never automatically erase a failed/uncertain Session.
				root, err := os.MkdirTemp("", "acs-linux-codex-")
				if err != nil {
					t.Fatal(err)
				}
				t.Logf("qualification state retained on failure: %s", root)
				owner, client := linuxTestSocketpair(t)
				ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestLinuxCodexSupervisorHelper$")
				cmd.Env = []string{"LANG=C", "LC_ALL=C", "ACS_TEST_CODEX_MODE=" + mode, "ACS_TEST_ROOT=" + root,
					"ACS_TEST_CODEX_VERSION=" + pair.Version, "ACS_TEST_CODEX_LINUX_ROOT=" + installed}
				cmd.ExtraFiles = []*os.File{client}
				var diagnostics bytes.Buffer
				cmd.Stdout, cmd.Stderr = &diagnostics, &diagnostics
				var master, slave *os.File
				if mode == "interactive" {
					master, slave, err = pty.Open()
					if err != nil {
						t.Fatal(err)
					}
					defer master.Close()
					defer slave.Close()
					if pty.Setsize(master, &pty.Winsize{Rows: 24, Cols: 80}) != nil {
						t.Fatal("set Codex terminal size")
					}
					cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
					cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
				}
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
				_ = client.Close()
				linuxTestByte(t, owner, 'R')
				linuxTestWrite(t, owner, 'S')
				linuxTestByte(t, owner, 'E')
				if master != nil {
					ready := []unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}
					if n, err := unix.Poll(ready, 10000); err != nil || n != 1 || ready[0].Revents&unix.POLLIN == 0 {
						t.Fatal("Codex did not start on the private terminal")
					}
					var data [4096]byte
					if n, err := master.Read(data[:]); err != nil || n == 0 {
						t.Fatal("Codex did not start on the private terminal")
					}
					if pty.Setsize(master, &pty.Winsize{Rows: 40, Cols: 120}) != nil {
						t.Fatal("resize Codex terminal")
					}
					linuxTestWrite(t, owner, byte(unix.SIGWINCH))
					_, _ = master.Write([]byte{3})
					// Bound this credential-free startup smoke test without an API
					// request. Full model interaction is a later native gate.
					linuxTestWrite(t, owner, byte(unix.SIGTERM))
				}
				linuxTestByte(t, owner, 'X')
				if err := cmd.Wait(); err != nil {
					t.Fatal("contained Codex qualification failed; inspect retained state")
				}
				if err := os.RemoveAll(root); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestLinuxCodexSupervisorHelper(t *testing.T) {
	mode, root := os.Getenv("ACS_TEST_CODEX_MODE"), os.Getenv("ACS_TEST_ROOT")
	if mode == "" {
		return
	}
	ctx := context.Background()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	write := func(path string, data []byte) {
		t.Helper()
		must(os.MkdirAll(filepath.Dir(path), 0700))
		must(os.WriteFile(path, data, 0600))
	}
	// Only ACS sees this isolated, explicitly selected durable provider.
	t.Setenv("HOME", filepath.Join(root, "host"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "host", "config"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "host", "data"))
	t.Setenv("XDG_STATE_HOME", filepath.Join(root, "host", "state"))
	must(codexauthresource.SelectProvider(codexauthresource.ProviderFile))
	store, err := codexauthresource.New(filepath.Join(root, "locks"), filepath.Join(root, "markers"))
	must(err)
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"synthetic-user","https://api.openai.com/auth":{"chatgpt_user_id":"synthetic-user","chatgpt_account_id":"synthetic-workspace"}}`))
	auth := []byte(`{"auth_mode":"chatgpt","tokens":{"id_token":"header.` + claims + `.signature","access_token":"synthetic-access","refresh_token":"synthetic-refresh","account_id":"synthetic-workspace"},"last_refresh":"2026-10-10T12:00:00Z"}`)
	write(filepath.Join(root, "host", ".codex", "auth.json"), auth)
	seed, err := CreateProtectedSession(filepath.Join(root, "seed"))
	must(err)
	write(filepath.Join(seed.RootDir, "home", ".codex", "auth.json"), auth)
	login, err := store.AcquireLogin(ctx, "selected")
	must(err)
	challenge := bytes.Repeat([]byte{0x5c}, RecoveryProofChallengeSize)
	must(login.PublishPrepared(ctx, seed.RootDir, hex.EncodeToString(challenge)))
	// Synthetic login seed has never executed a child. Actual CLI probes below
	// must instead obtain authenticated cgroup settlement before finalization.
	must(login.MarkCleanupPending(ctx))
	must(login.MarkRecoverable(ctx))
	_, err = login.CommitLogin(ctx, seed.RootDir)
	must(err)
	must(seed.Remove())
	must(login.DeleteMarkerAfterProjectionRemoval(ctx))
	must(login.Release())

	lease, err := CreateProtectedSession(filepath.Join(root, "sessions"))
	must(err)
	home, tmp, work := filepath.Join(lease.RootDir, "home"), filepath.Join(lease.RootDir, "tmp"), filepath.Join(root, "work")
	for _, path := range []string{home, tmp, work} {
		must(os.Mkdir(path, 0700))
	}
	var binding *codexauthresource.Binding
	if mode == "status-selected" || mode == "mcp" {
		binding, _, err = store.AcquireStatus(ctx, "selected")
		must(err)
		must(binding.PublishPrepared(ctx, lease.RootDir, hex.EncodeToString(challenge)))
		must(binding.Project(home))
		must(binding.MarkCleanupPending(ctx))
	}
	operation := mode
	if strings.HasPrefix(mode, "status-") {
		operation = "status"
	}
	if mode == "mcp" {
		write(filepath.Join(work, ".codex", "config.toml"), []byte("[mcp_servers.project]\ncommand = \"/unselected-project-server\"\n"))
		write(filepath.Join(home, ".codex", "config.toml"), []byte("[mcp_servers.session]\ncommand = \"/unselected-session-server\"\n"))
	}
	binary := filepath.Join(linuxCodexTestRoot(t), os.Getenv("ACS_TEST_CODEX_VERSION"), "codex")
	f := linuxNativeFixture{base: root, wire: linuxLaunchWire{Home: home, Temporary: tmp, Directory: work, Executable: binary}}
	request, tree := linuxRecipeFixtureRequest(t, f, false)
	workspace := ""
	if binding != nil {
		workspace = "synthetic-workspace"
	}
	request.arguments = codexcompat.LinuxArguments(workspace, work, operation)
	recipe, err := linuxCompileRecipe(linuxRecipeAdmission{true}, linuxCodexRecipe, request, tree, mode == "interactive")
	must(err)
	must(PrepareSessionCleanupProof(lease.RootDir, challenge))
	var terminal *os.File
	if mode == "interactive" {
		terminal = os.Stdin
	}
	cleanup, err := linuxPrepareCleanup(lease, challenge, terminal)
	must(err)
	input, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	must(err)
	defer input.Close()
	output, err := os.Create(filepath.Join(root, "output"))
	must(err)
	defer output.Close()
	stdio := [3]*os.File{input, output, output}
	if mode == "interactive" {
		stdio = [3]*os.File{os.Stdin, os.Stdout, os.Stderr}
	}
	helper, err := os.Open("/proc/self/exe")
	must(err)
	defer helper.Close()
	result, err := linuxRunRecipe(ctx, linuxRecipeAdmission{true}, recipe, os.NewFile(3, "owner"), helper,
		[]string{"-test.run=^TestLinuxRecipeInitHelper$", "--", "acs-recipe-init"}, stdio, linuxTestLease(t, nil), cleanup)
	must(err)
	proof, err := VerifySessionCleanupProof(lease.RootDir, challenge)
	must(err)
	if !result.Settled || !result.Exited || !proof {
		t.Fatal("Codex did not prove complete cgroup settlement")
	}
	data, err := os.ReadFile(output.Name())
	must(err)
	if mode != "interactive" {
		if !result.Status.Exited() || mode != "status-absent" && result.Status.ExitStatus() != 0 {
			t.Fatal("Codex probe failed")
		}
		switch mode {
		case "version":
			if strings.TrimSpace(string(data)) != "codex-cli "+os.Getenv("ACS_TEST_CODEX_VERSION") {
				t.Fatal("Codex version differs from locked pair")
			}
		case "status-absent", "status-selected":
			if binding == nil && (!bytes.Contains(data, []byte("Not logged in")) || result.Status.ExitStatus() != 1) ||
				binding != nil && !bytes.Contains(data, []byte("Logged in using ChatGPT")) {
				t.Fatal("Codex used ambient credentials or ignored selected projection")
			}
		case "mcp":
			var servers []json.RawMessage
			if json.Unmarshal(data, &servers) != nil || len(servers) != 0 {
				t.Fatal("unselected MCP configuration was discovered")
			}
		}
	}
	if bytes.Contains(data, []byte("synthetic-access")) || bytes.Contains(data, []byte("synthetic-refresh")) {
		t.Fatal("Codex printed credential bytes")
	}
	global, err := os.ReadFile(filepath.Join(root, "host", ".codex", "auth.json"))
	must(err)
	if !bytes.Equal(global, auth) {
		t.Fatal("Codex changed host authentication")
	}
	if binding != nil {
		must(binding.MarkRefreshAllowed(ctx))
		must(binding.MarkRecoverable(ctx))
		_, err = binding.FinalizeStatus(ctx, lease.RootDir)
		must(err)
	}
	must(lease.Remove())
	if binding != nil {
		must(binding.DeleteMarkerAfterProjectionRemoval(ctx))
		must(binding.Release())
	}
	os.Exit(0)
}
