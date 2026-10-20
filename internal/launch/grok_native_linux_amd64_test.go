package launch

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/grokcompat"
	"github.com/alcimerio/ai-config-selector/internal/linuxprobe"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func linuxGrokTestBinary(t *testing.T) string {
	t.Helper()
	path := os.Getenv("ACS_TEST_GROK_BINARY")
	if path == "" {
		linuxNativeUnavailable(t, "ACS_TEST_GROK_BINARY must name the checksum-locked Linux amd64 target")
	}
	if !filepath.IsAbs(path) {
		t.Fatal("ACS_TEST_GROK_BINARY must be absolute")
	}
	return path
}

func TestLinuxGrokPublishedBytes(t *testing.T) {
	path := linuxGrokTestBinary(t)
	files, err := linuxGrokRuntime(path)
	if err != nil || len(files) != 1 || files[0].node.identity.size != grokcompat.LinuxAMD64BinarySize {
		t.Fatal("installed Grok does not match the locked static Linux binary")
	}
	if _, err := linuxDiscoverRuntime(path, false); err == nil {
		t.Fatal("large target bypassed the generic runtime bound")
	}
}

func TestLinuxNativeGrokProbes(t *testing.T) {
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
	binary := linuxGrokTestBinary(t)
	for _, mode := range []string{"version", "interactive"} {
		t.Run(mode, func(t *testing.T) {
			root, err := os.MkdirTemp("", "acs-linux-grok-")
			if err != nil {
				t.Fatal(err)
			}
			owner, client := linuxTestSocketpair(t)
			if mode == "interactive" {
				if err := owner.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestLinuxGrokSupervisorHelper$")
			cmd.Env = []string{"LANG=C", "LC_ALL=C", "ACS_TEST_GROK_MODE=" + mode,
				"ACS_TEST_ROOT=" + root, "ACS_TEST_GROK_BINARY=" + binary, "HOME=" + filepath.Join(root, "host")}
			cmd.ExtraFiles = []*os.File{client}
			var diagnostics linuxRecipeOutput
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
					t.Fatal("set Grok terminal size")
				}
				cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
				cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			}
			process := linuxNativeStartCommand(t, cmd, diagnostics.String, func() string {
				return linuxNativeReadLogs(filepath.Join(root, "output")) + linuxNativePTYDiagnostics(master)
			})
			_ = client.Close()
			linuxTestByte(t, owner, 'R', process.diagnostics)
			linuxTestWrite(t, owner, 'S')
			linuxTestByte(t, owner, 'E', process.diagnostics)
			if master != nil {
				ready := []unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}
				if n, err := unix.Poll(ready, 10000); err != nil || n != 1 || ready[0].Revents&unix.POLLIN == 0 {
					t.Fatal("Grok did not start on the private terminal")
				}
				var data [4096]byte
				if n, err := master.Read(data[:]); err != nil || n == 0 {
					t.Fatal("Grok did not start on the private terminal")
				}
				linuxTestWrite(t, owner, byte(unix.SIGTERM))
			}
			linuxTestByte(t, owner, 'X', process.diagnostics)
			if err := process.Wait(); err != nil {
				t.Fatalf("contained Grok %s failed; retained %s: %v\n%s", mode, root, err, process.diagnostics())
			}
			if err := os.RemoveAll(root); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLinuxGrokSupervisorHelper(t *testing.T) {
	mode, root := os.Getenv("ACS_TEST_GROK_MODE"), os.Getenv("ACS_TEST_ROOT")
	if mode == "" {
		return
	}
	secret := []byte("ACS_SYNTHETIC_GROK_AUTH_NOT_VALID\n")
	hostAuth := filepath.Join(root, "host", ".grok", "auth.json")
	if err := os.MkdirAll(filepath.Dir(hostAuth), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hostAuth, secret, 0600); err != nil {
		t.Fatal(err)
	}
	session, err := CreateProtectedSession(filepath.Join(root, "state", "sessions"))
	if err != nil {
		t.Fatal(err)
	}
	home, tmp, work := filepath.Join(session.RootDir, "home"), filepath.Join(session.RootDir, "tmp"), filepath.Join(root, "work")
	for _, path := range []string{home, tmp, work} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	binary := linuxGrokTestBinary(t)
	f := linuxNativeFixture{base: root, wire: linuxLaunchWire{Home: home, Temporary: tmp, Directory: work, Executable: binary}}
	request, tree := linuxRecipeFixtureRequest(t, f, false)
	if mode == "version" {
		request.arguments = []string{"--version"}
	}
	recipe, err := linuxCompileRecipe(linuxRecipeAdmission{true}, linuxGrokRecipe, request, tree, mode == "interactive")
	if err != nil {
		t.Fatal(err)
	}
	challenge := bytes.Repeat([]byte{0x47}, RecoveryProofChallengeSize)
	if PrepareSessionCleanupProof(session.RootDir, challenge) != nil {
		t.Fatal("prepare cleanup proof")
	}
	var terminal *os.File
	if mode == "interactive" {
		terminal = os.Stdin
	}
	cleanup, err := linuxPrepareCleanup(session, challenge, terminal)
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.Create(filepath.Join(root, "output"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	stdio := [3]*os.File{input, output, output}
	if mode == "interactive" {
		stdio = [3]*os.File{os.Stdin, os.Stdout, os.Stderr}
	}
	helper, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer helper.Close()
	result, err := linuxRunRecipe(context.Background(), linuxRecipeAdmission{true}, recipe, os.NewFile(3, "owner"), helper,
		[]string{"-test.run=^TestLinuxRecipeInitHelper$", "--", "acs-recipe-init"}, stdio, linuxTestLease(t, nil), cleanup)
	proof, proofErr := VerifySessionCleanupProof(session.RootDir, challenge)
	if err != nil || !result.Settled || !result.Exited || proofErr != nil || !proof {
		t.Fatalf("Grok probe did not prove complete settlement; retain Session: result=%+v error=%v proof=%t proof error=%v", result, err, proof, proofErr)
	}
	data, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, secret) {
		t.Fatal("Grok printed the host credential")
	}
	current, err := os.ReadFile(hostAuth)
	if err != nil || !bytes.Equal(current, secret) {
		t.Fatal("Grok changed the host credential")
	}
	if mode == "version" {
		if !result.Status.Exited() || result.Status.ExitStatus() != 0 || !grokcompat.AcceptsOutput(string(data)) {
			t.Fatalf("Grok version probe failed: %v %q", result.Status, data)
		}
	}
	if err := session.Remove(); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}
