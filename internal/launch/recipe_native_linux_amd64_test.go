package launch

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/linuxprobe"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func linuxRecipeFixtureRequest(t *testing.T, f linuxNativeFixture, synthetic bool) (validatedProcessRequest, linuxFilesystemSnapshot) {
	t.Helper()
	tree := linuxFilesystemSnapshot{}
	err := filepath.WalkDir(f.base, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		var x unix.Statx_t
		var fs unix.Statfs_t
		if unix.Statx(unix.AT_FDCWD, path, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_MNT_ID, &x) != nil || unix.Statfs(path, &fs) != nil {
			return errLinuxRecipe
		}
		node := linuxFilesystemNode{identity: identityFromFileInfo(info, info.Sys().(*syscall.Stat_t)), mountID: x.Mnt_id, filesystemType: fs.Type}
		if entry.IsDir() {
			children, err := os.ReadDir(path)
			if err != nil {
				return err
			}
			for _, child := range children {
				node.children = append(node.children, child.Name())
			}
		}
		tree[path] = node
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if synthetic {
		// Unit and restriction-only tests do not bind this snapshot. Model one
		// data filesystem even on virtual test hosts with split file/dir st_dev.
		// The full native composition must use unmodified kernel observations.
		device := tree[f.wire.Executable].identity.device
		for path, node := range tree {
			if node.identity.mode.IsDir() {
				node.identity.device = device
				tree[path] = node
			}
		}
	}
	request := validatedProcessRequest{workspace: f.wire.Directory,
		sessionsDirectory: filepath.Dir(filepath.Dir(f.wire.Home)), sessionDirectory: filepath.Dir(f.wire.Home),
		sessionHome: f.wire.Home, temporaryDirectory: f.wire.Temporary, executable: f.wire.Executable,
		runtimeAuthority: linuxFilesystemRuntimeAuthority()}
	return request, tree // zero workspaceAccess exercises the read-only default
}

func TestLinuxNativeRecipeStartupAndLiteralArguments(t *testing.T) {
	linuxNativePrerequisites(t)
	for _, kind := range []linuxRecipeKind{linuxShellRecipe, linuxCommandRecipe} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			f := linuxNewNativeFixture(t, false)
			if err := os.WriteFile(filepath.Join(f.wire.Home, ".bashrc"), []byte("printf RC-LEAK\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(f.wire.Home, ".bash_profile"), []byte("printf PROFILE-LEAK\n"), 0600); err != nil {
				t.Fatal(err)
			}
			request, tree := linuxRecipeFixtureRequest(t, f, true)
			input := ""
			var want []string
			if kind == linuxShellRecipe {
				request.executable = ""
				input = "[[ -z ${HOST_LEAK+x} && -z ${BASH_ENV+x} && $PATH == /usr/bin:/bin ]] || exit 91\n" +
					"printf home-ok > \"$HOME/allowed\" || exit 92\n" +
					"if { printf forbidden > allowed; } 2>/dev/null; then exit 93; fi\nprintf CLEAN-START\nexit 23\n"
			} else {
				want = []string{"a b", "$(touch injected)", "; exit 90", "*.txt", "", "--help"}
				request.arguments = append([]string{"-test.run=^TestLinuxRecipeLiteralTarget$", "--"}, want...)
			}
			recipe, err := linuxCompileRecipe(linuxRecipeAdmission{true}, kind, request, tree, false)
			if err != nil {
				t.Fatal(err)
			}
			status, output := linuxRunPrimitiveRecipe(t, recipe, input)
			if kind == linuxShellRecipe {
				if !status.Exited() || status.ExitStatus() != 23 || output != "CLEAN-START" {
					t.Fatalf("shell startup/status: %v %q", status, output)
				}
				if got, err := os.ReadFile(filepath.Join(f.wire.Home, "allowed")); err != nil || string(got) != "home-ok" {
					t.Fatal("private HOME write failed")
				}
			} else {
				var got []string
				if !status.Exited() || status.ExitStatus() != 0 || json.Unmarshal([]byte(output), &got) != nil || !reflect.DeepEqual(got, want) {
					t.Fatalf("literal argv/status: %v %q", status, output)
				}
			}
			if got, err := os.ReadFile(filepath.Join(f.wire.Directory, "allowed")); err != nil || string(got) != "allowed" {
				t.Fatal("read-only workspace changed")
			}
			if _, err := os.Stat(filepath.Join(f.wire.Directory, "injected")); !os.IsNotExist(err) {
				t.Fatal("argument was evaluated")
			}
		})
	}
}

func TestLinuxRecipeLiteralTarget(t *testing.T) {
	for i, arg := range os.Args {
		if arg == "--" {
			_ = json.NewEncoder(os.Stdout).Encode(os.Args[i+1:])
			os.Exit(0)
		}
	}
}

// Primitive evidence only: real ELF execution, Landlock and seccomp, without a
// mount namespace or Session/cgroup claim. Alias rules refer to the same host
// inodes here; the composition suite below tests the actual private mounts.
func linuxRunPrimitiveRecipe(t *testing.T, recipe linuxRecipe, input string) (unix.WaitStatus, string) {
	t.Helper()
	var master, slave *os.File
	if recipe.interactive {
		var err error
		master, slave, err = pty.Open()
		if err != nil {
			linuxNativeUnavailable(t, "private PTY allocation")
		}
		defer master.Close()
		defer slave.Close()
		attrs, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
		if err != nil {
			t.Fatal(err)
		}
		if unix.IoctlSetWinsize(int(slave.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80}) != nil {
			t.Fatal("set PTY size")
		}
		config, err := linuxRecipeTerminal([3]*os.File{slave, slave, slave}, &linuxTerminalState{file: slave, attrs: *attrs})
		if err != nil {
			t.Fatal(err)
		}
		recipe.wire.Terminal = config
	}
	aliases := map[string]bool{}
	for _, m := range recipe.plan.mounts {
		if m.kind == linuxMountRuntimeAlias {
			aliases[m.destination] = true
		}
	}
	wire := recipe.wire
	wire.Rules = nil
	for _, rule := range recipe.plan.rules {
		if !aliases[rule.path] {
			wire.Rules = append(wire.Rules, linuxWireRule{rule.path, rule.access})
		}
	}
	wire.Rules = append(wire.Rules, linuxWireRule{"/dev/null", linuxReadFile | linuxWriteFile})
	transport, err := linuxWriteTransport(wire, linuxTestLease(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close()
	status, report := linuxTestSocketpair(t)
	control, gate := linuxTestSocketpair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestLinuxRecipeInitHelper$", "--", "acs-recipe-init")
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "HOST_LEAK=secret", "BASH_ENV=/invalid"}
	cmd.ExtraFiles = []*os.File{transport, report, control}
	cmd.Stdin = strings.NewReader(input)
	var output linuxRecipeOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	var outputDone chan struct{}
	if recipe.interactive {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		outputDone = make(chan struct{})
		go func() { _, _ = io.Copy(&output, master); close(outputDone) }()
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	if slave != nil {
		_ = slave.Close()
	}
	_ = report.Close()
	_ = control.Close()
	linuxTestByte(t, status, 'R')
	linuxTestWrite(t, gate, 'S')
	linuxTestByte(t, status, 'E')
	if master != nil {
		if _, err := io.WriteString(master, input); err != nil {
			t.Fatal(err)
		}
	}
	var frame [5]byte
	if _, err := io.ReadFull(status, frame[:]); err != nil || frame[0] != 'X' {
		t.Fatalf("target status: %v %x output=%q", err, frame, output.String())
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("primitive recipe: %v", err)
	}
	if outputDone != nil {
		<-outputDone
	}
	return unix.WaitStatus(binary.LittleEndian.Uint32(frame[1:])), output.String()
}

type linuxRecipeOutput struct {
	sync.Mutex
	buffer bytes.Buffer
}

func (b *linuxRecipeOutput) Write(data []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.buffer.Write(data)
}

func (b *linuxRecipeOutput) String() string {
	b.Lock()
	defer b.Unlock()
	return b.buffer.String()
}

func TestLinuxNativeRecipeInteractiveShell(t *testing.T) {
	linuxNativePrerequisites(t)
	f := linuxNewNativeFixture(t, false)
	request, tree := linuxRecipeFixtureRequest(t, f, true)
	request.executable = ""
	recipe, err := linuxCompileRecipe(linuxRecipeAdmission{true}, linuxShellRecipe, request, tree, true)
	if err != nil {
		t.Fatal(err)
	}
	status, output := linuxRunPrimitiveRecipe(t, recipe, "[[ $- == *i* && $- == *m* ]] || exit 91; printf 'PTY-%s-%s\\n' \"$LINES\" \"$COLUMNS\"; exit 23\n")
	if !status.Exited() || status.ExitStatus() != 23 || !strings.Contains(output, "PTY-24-80\r\n") || strings.Contains(output, "no job control") {
		t.Fatalf("interactive shell failed: %v %q", status, output)
	}
}

type linuxRecipeReceipt struct {
	Result  linuxSessionResult
	Proof   bool
	Removed bool
}

func TestLinuxRecipeInitHelper(t *testing.T) {
	if os.Args[len(os.Args)-1] != "acs-recipe-init" {
		return
	}
	transport := os.NewFile(3, "transport")
	wire, env, err := linuxReadTransport(transport)
	_ = transport.Close()
	if err != nil || linuxRunContainedInit(wire, env, os.NewFile(4, "report"), os.NewFile(5, "control")) != nil {
		os.Exit(125)
	}
	os.Exit(0)
}

// No equivalent entry point is compiled into cmd/acs.
func TestLinuxRecipeSupervisorHelper(t *testing.T) {
	if os.Getenv("ACS_TEST_RECIPE") == "" {
		return
	}
	mode, root := os.Getenv("ACS_TEST_RECIPE"), os.Getenv("ACS_TEST_ROOT")
	f := linuxNewNativeFixture(t, false)
	session, err := CreateProtectedSession(filepath.Join(f.base, "sessions"))
	if err != nil {
		t.Fatal(err)
	}
	f.wire.Home, f.wire.Temporary = filepath.Join(session.RootDir, "home"), filepath.Join(session.RootDir, "tmp")
	for _, p := range []string{f.wire.Home, f.wire.Temporary} {
		if os.Mkdir(p, 0700) != nil {
			t.Fatal("create Session projection")
		}
	}
	if os.WriteFile(filepath.Join(f.wire.Home, ".bashrc"), []byte("printf RC-LEAK\n"), 0600) != nil {
		t.Fatal("write startup sentinel")
	}
	request, tree := linuxRecipeFixtureRequest(t, f, false)
	kind := linuxShellRecipe
	request.executable = ""
	if mode == "command" {
		kind, request.executable = linuxCommandRecipe, f.wire.Executable
		request.arguments = []string{"-test.run=^TestLinuxRecipeLiteralTarget$", "--", "a b", "$(touch injected)", ""}
	}
	recipe, err := linuxCompileRecipe(linuxRecipeAdmission{true}, kind, request, tree, mode == "interactive")
	if err != nil {
		t.Fatal(err)
	}
	challenge := bytes.Repeat([]byte{0x3a}, RecoveryProofChallengeSize)
	if PrepareSessionCleanupProof(session.RootDir, challenge) != nil {
		t.Fatal("prepare proof")
	}
	var terminal *os.File
	if mode == "interactive" {
		terminal = os.Stdin
	}
	cleanup, err := linuxPrepareCleanup(session, challenge, terminal)
	if err != nil {
		t.Fatal(err)
	}
	helper, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer helper.Close()
	result, err := linuxRunRecipe(context.Background(), linuxRecipeAdmission{true}, recipe, os.NewFile(3, "owner"), helper,
		[]string{"-test.run=^TestLinuxRecipeInitHelper$", "--", "acs-recipe-init"},
		[3]*os.File{os.Stdin, os.Stdout, os.Stderr}, linuxTestLease(t, nil), cleanup)
	if err != nil || !result.Settled {
		t.Fatalf("recipe: %+v %v", result, err)
	}
	proof, err := VerifySessionCleanupProof(session.RootDir, challenge)
	if err != nil || !proof {
		t.Fatal("missing authenticated settlement")
	}
	if err := session.Remove(); err != nil {
		t.Fatal(err)
	}
	_, statErr := os.Stat(session.RootDir)
	data, _ := json.Marshal(linuxRecipeReceipt{result, proof, os.IsNotExist(statErr)})
	if err := os.WriteFile(filepath.Join(root, "receipt"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(f.base); err != nil {
		t.Fatal(err)
	}
	os.Exit(0) // Do not add the testing package's PASS marker to target stdout.
}

func TestLinuxNativeRecipeComposition(t *testing.T) {
	linuxNativePrerequisites(t)
	report := linuxprobe.Probe(context.Background())
	if !report.PrerequisitesPassed() {
		var missing []string
		for _, c := range report.Checks {
			if c.Status != "pass" {
				missing = append(missing, c.ID+":"+c.Code)
			}
		}
		linuxNativeUnavailable(t, strings.Join(missing, ", "))
	}
	for _, mode := range []string{"redirected", "command", "interactive"} {
		t.Run(mode, func(t *testing.T) { linuxNativeRecipeScenario(t, mode) })
	}
}

func linuxNativeRecipeScenario(t *testing.T, mode string) {
	root := t.TempDir()
	owner, client := linuxTestSocketpair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestLinuxRecipeSupervisorHelper$")
	cmd.Env = []string{"LANG=C", "LC_ALL=C", "ACS_TEST_RECIPE=" + mode, "ACS_TEST_ROOT=" + root, "HOST_LEAK=private"}
	cmd.ExtraFiles = []*os.File{client}
	var output bytes.Buffer
	var master, slave *os.File
	if mode == "interactive" {
		var err error
		master, slave, err = pty.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer master.Close()
		defer slave.Close()
		if unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 80}) != nil {
			t.Fatal("set window size")
		}
		cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	} else {
		cmd.Stdin = strings.NewReader("[[ -z ${HOST_LEAK+x} ]] || exit 90\nprintf REDIRECTED\nexit 23\n")
		cmd.Stdout, cmd.Stderr = &output, &output
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	_ = client.Close()
	linuxTestByte(t, owner, 'R')
	linuxTestWrite(t, owner, 'S')
	linuxTestByte(t, owner, 'E')
	if mode == "interactive" {
		if _, err := master.Write([]byte("[[ $- == *i* && $- == *m* ]] || exit 91; printf 'INTERACTIVE-READY\\n'\n")); err != nil {
			t.Fatal(err)
		}
		// Read until a distinct completed output line, not the echoed command.
		_ = master.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 4096)
		for !strings.Contains(output.String(), "INTERACTIVE-READY\r\n") {
			n, err := master.Read(buffer)
			if err != nil {
				t.Fatalf("interactive startup: %v %q", err, output.String())
			}
			output.Write(buffer[:n])
		}
		if unix.IoctlSetWinsize(int(master.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Row: 40, Col: 120}) != nil {
			t.Fatal("resize PTY")
		}
		linuxTestWrite(t, owner, byte(unix.SIGWINCH))
		if _, err := master.Write([]byte("until [[ $LINES == 40 && $COLUMNS == 120 ]]; do :; done; exit 23\n")); err != nil {
			t.Fatal(err)
		}
	}
	linuxTestByte(t, owner, 'X')
	if err := cmd.Wait(); err != nil {
		t.Fatalf("native recipe failed: %v %q", err, output.String())
	}
	data, err := os.ReadFile(filepath.Join(root, "receipt"))
	var receipt linuxRecipeReceipt
	if err != nil || json.Unmarshal(data, &receipt) != nil || !receipt.Result.Settled || !receipt.Proof || !receipt.Removed {
		t.Fatalf("unproven recipe cleanup: %s %v", data, err)
	}
	wantStatus := 23
	if mode == "command" {
		wantStatus = 0
		var args []string
		if json.Unmarshal(output.Bytes(), &args) != nil || !reflect.DeepEqual(args, []string{"a b", "$(touch injected)", ""}) {
			t.Fatalf("argv: %q", output.String())
		}
	} else if mode == "redirected" && output.String() != "REDIRECTED" {
		t.Fatalf("redirected output changed: %q", output.String())
	}
	if !receipt.Result.Exited || !receipt.Result.Status.Exited() || receipt.Result.Status.ExitStatus() != wantStatus {
		t.Fatalf("exit status changed: %+v", receipt.Result)
	}
}
