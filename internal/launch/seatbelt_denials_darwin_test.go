//go:build darwin

package launch

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// These tests verify that host automation, pasteboard, Keychain and inbound
// network operations stay unavailable inside the production policy. Each case
// logs a single "sandbox-denial-evidence" line so CI output records the
// observed outcome on the runner, including when a case is inconclusive.

const seatbeltDenialProbeRun = "-test.run=^TestSeatbeltDenialProbeHelper$"

// seatbeltDenialFIONREAD is FIONREAD from <sys/filio.h> (_IOR('f', 127, int)).
const seatbeltDenialFIONREAD = 0x4004667f

func seatbeltDenialToken(t *testing.T) string {
	t.Helper()
	value := make([]byte, 12)
	if _, err := rand.Read(value); err != nil {
		t.Fatal(err)
	}
	return "acs-denial-" + hex.EncodeToString(value)
}

func seatbeltDenialEvidence(t *testing.T, format string, arguments ...any) {
	t.Helper()
	t.Logf("sandbox-denial-evidence %s: %s", t.Name(), fmt.Sprintf(format, arguments...))
}

func seatbeltDenialHostOutput(name string, arguments ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, name, arguments...).CombinedOutput()
	return string(output), err
}

func seatbeltDenialRunProbe(t *testing.T, argv ...string) string {
	t.Helper()
	request := seatbeltTestRequest(t)
	result := filepath.Join(request.sessionDirectory, "probe-result")
	request.arguments = append([]string{seatbeltDenialProbeRun, "--", "exec", result}, argv...)
	settled, err := seatbeltTerminalNativeRun(request)
	if !settled {
		t.Fatalf("probe cleanup was not proven: %v", err)
	}
	contents, readErr := os.ReadFile(result)
	if readErr != nil {
		t.Fatalf("probe produced no result: run=%v read=%v", err, readErr)
	}
	return string(contents)
}

func TestSeatbeltVerifiesHostAutomationIsDenied(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	outside := t.TempDir()

	t.Run("launchctl-submit", func(t *testing.T) {
		marker := filepath.Join(outside, "launchctl-marker")
		label := "dev.acs.test." + seatbeltDenialToken(t)
		t.Cleanup(func() { _, _ = seatbeltDenialHostOutput("/bin/launchctl", "remove", label) })
		result := seatbeltDenialRunProbe(t, "/bin/launchctl", "submit", "-l", label, "--", "/usr/bin/touch", marker)
		time.Sleep(2 * time.Second)
		_, markerErr := os.Stat(marker)
		// launchctl list exits zero only when the label is loaded; its error
		// output also contains the label, so the exit status decides.
		_, listErr := seatbeltDenialHostOutput("/bin/launchctl", "list", label)
		listed := listErr == nil
		seatbeltDenialEvidence(t, "probe=%s marker_exists=%v job_listed=%v", result, markerErr == nil, listed)
		if markerErr == nil || listed {
			t.Fatal("sandboxed launchctl submitted a host job")
		}
	})

	t.Run("osascript", func(t *testing.T) {
		marker := filepath.Join(outside, "osascript-marker")
		result := seatbeltDenialRunProbe(t, "/usr/bin/osascript", "-e", `do shell script "/usr/bin/touch `+marker+`"`)
		_, markerErr := os.Stat(marker)
		seatbeltDenialEvidence(t, "probe=%s marker_exists=%v", result, markerErr == nil)
		if markerErr == nil {
			t.Fatal("sandboxed osascript ran a host command")
		}
	})

	t.Run("open", func(t *testing.T) {
		const application = "TextEdit"
		if running, _ := seatbeltDenialHostOutput("/usr/bin/pgrep", "-x", application); strings.TrimSpace(running) != "" {
			t.Skipf("%s is already running on this host; outcome would be ambiguous", application)
		}
		t.Cleanup(func() { _, _ = seatbeltDenialHostOutput("/usr/bin/pkill", "-x", application) })
		result := seatbeltDenialRunProbe(t, "/usr/bin/open", "-g", "-j", "-a", application)
		time.Sleep(2 * time.Second)
		running, _ := seatbeltDenialHostOutput("/usr/bin/pgrep", "-x", application)
		seatbeltDenialEvidence(t, "probe=%s launched=%v", result, strings.TrimSpace(running) != "")
		if strings.TrimSpace(running) != "" {
			t.Fatal("sandboxed open launched a host application")
		}
	})

	t.Run("pasteboard-write", func(t *testing.T) {
		sentinel := seatbeltDenialToken(t)
		if err := seatbeltDenialHostPasteboardSet(sentinel); err != nil {
			t.Skipf("host pasteboard unavailable: %v", err)
		}
		if got, _ := seatbeltDenialHostOutput("/usr/bin/pbpaste"); got != sentinel {
			t.Skipf("host pasteboard did not round-trip (got %d bytes)", len(got))
		}
		token := seatbeltDenialToken(t)
		result := seatbeltDenialRunProbe(t, "/bin/sh", "-c", "printf %s "+token+" | /usr/bin/pbcopy")
		got, _ := seatbeltDenialHostOutput("/usr/bin/pbpaste")
		seatbeltDenialEvidence(t, "probe=%s host_pasteboard_changed=%v", result, got == token)
		if got == token {
			t.Fatal("sandboxed pbcopy changed the host pasteboard")
		}
	})

	t.Run("pasteboard-read", func(t *testing.T) {
		token := seatbeltDenialToken(t)
		if err := seatbeltDenialHostPasteboardSet(token); err != nil {
			t.Skipf("host pasteboard unavailable: %v", err)
		}
		result := seatbeltDenialRunProbe(t, "/usr/bin/pbpaste")
		seatbeltDenialEvidence(t, "probe=%s token_visible=%v", strings.ReplaceAll(result, token, "<token>"), strings.Contains(result, token))
		if strings.Contains(result, token) {
			t.Fatal("sandboxed pbpaste read the host pasteboard")
		}
	})

	t.Run("keychain", func(t *testing.T) {
		service := seatbeltDenialToken(t)
		secret := seatbeltDenialToken(t)
		if output, err := seatbeltDenialHostOutput("/usr/bin/security", "add-generic-password", "-a", "acs-test", "-s", service, "-w", secret, "-U"); err != nil {
			t.Skipf("host Keychain item could not be created: %v: %s", err, output)
		}
		t.Cleanup(func() {
			_, _ = seatbeltDenialHostOutput("/usr/bin/security", "delete-generic-password", "-a", "acs-test", "-s", service)
		})
		if output, err := seatbeltDenialHostOutput("/usr/bin/security", "find-generic-password", "-s", service, "-w"); err != nil || strings.TrimSpace(output) != secret {
			t.Skipf("host Keychain item is not readable outside the sandbox: %v", err)
		}
		find := seatbeltDenialRunProbe(t, "/usr/bin/security", "find-generic-password", "-s", service, "-w")
		dump := seatbeltDenialRunProbe(t, "/usr/bin/security", "dump-keychain")
		list := seatbeltDenialRunProbe(t, "/usr/bin/security", "list-keychains")
		leaked := strings.Contains(find, secret) || strings.Contains(dump, service)
		redact := strings.NewReplacer(secret, "<secret>", service, "<service>")
		seatbeltDenialEvidence(t, "find=%s dump_mentions_item=%v list=%s", redact.Replace(find), strings.Contains(dump, service), redact.Replace(list))
		if leaked {
			t.Fatal("sandboxed security tool read a host Keychain item")
		}
	})
}

func seatbeltDenialHostPasteboardSet(value string) error {
	command := exec.Command("/usr/bin/pbcopy")
	command.Stdin = strings.NewReader(value)
	return command.Run()
}

func TestSeatbeltVerifiesInboundConnectionsAreNotAccepted(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	portFile := filepath.Join(request.sessionDirectory, "listen-port")
	result := filepath.Join(request.sessionDirectory, "listen-result")
	request.arguments = []string{seatbeltDenialProbeRun, "--", "listen", portFile, result}
	dialOutcome := make(chan string, 1)
	go func() {
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			contents, err := os.ReadFile(portFile)
			if err == nil && len(contents) > 0 {
				value := string(contents)
				if !strings.HasPrefix(value, "port ") {
					dialOutcome <- "not-dialed: " + value
					return
				}
				connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strings.TrimPrefix(value, "port ")), 2*time.Second)
				if err != nil {
					dialOutcome <- "dial-error: " + err.Error()
					return
				}
				_, writeErr := connection.Write([]byte("x"))
				_ = connection.Close()
				dialOutcome <- fmt.Sprintf("dial-connected write_err=%v", writeErr)
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		dialOutcome <- "not-dialed: no port published"
	}()
	settled, err := seatbeltTerminalNativeRun(request)
	if !settled {
		t.Fatalf("listener cleanup was not proven: %v", err)
	}
	dialed := <-dialOutcome
	contents, _ := os.ReadFile(result)
	seatbeltDenialEvidence(t, "listener=%q host=%q run_err=%v", string(contents), dialed, err)
	if string(contents) == "accepted" {
		t.Fatal("sandboxed listener accepted a host connection")
	}
}

// Parent cleanup settles detached descendants after supervisor loss while
// preserving a concurrent launch with the same paths and permissions.
func TestSeatbeltCleansDetachedDescendantAfterSupervisorLoss(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	heartbeat := filepath.Join(request.sessionDirectory, "heartbeat")
	pidFile := filepath.Join(request.sessionDirectory, "heartbeat-pid")
	request.arguments = []string{seatbeltDenialProbeRun, "--", "detach-and-signal-supervisor", heartbeat, pidFile}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	bystanderRequest := request
	bystanderPIDFile := filepath.Join(request.sessionDirectory, "bystander-pid")
	bystanderRequest.arguments = []string{seatbeltDenialProbeRun, "--", "heartbeat", filepath.Join(request.sessionDirectory, "bystander-heartbeat"), bystanderPIDFile}
	bystander, err := newSeatbeltBackend(seatbeltExecutable).prepare(ctx, bystanderRequest)
	if err != nil {
		t.Fatal(err)
	}
	if err := bystander.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = bystander.Signal(syscall.SIGKILL)
		_ = bystander.Wait()
	})
	seatbeltWaitForMarker(t, filepath.Join(request.sessionDirectory, "bystander-heartbeat"))
	contents, err := os.ReadFile(bystanderPIDFile)
	if err != nil {
		t.Fatal(err)
	}
	bystanderPID, err := strconv.Atoi(strings.TrimSpace(string(contents)))
	if err != nil || bystanderPID <= 1 {
		t.Fatalf("bystander PID = %q: %v", contents, err)
	}
	api, err := loadSeatbeltProcAPI()
	if err != nil {
		t.Fatal(err)
	}
	bystanderIdentity, err := api.info(bystanderPID)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := newSeatbeltBackend(seatbeltExecutable).prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	process := prepared.(*seatbeltProcess)
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = process.closeControl()
		_ = process.settleSession()
		_ = process.command.Process.Kill()
	})
	if err := process.Wait(); err == nil || !strings.Contains(err.Error(), errSandboxSessionCleanupRecovered.Error()) {
		t.Fatalf("supervisor loss result = %v, want recovered cleanup report", err)
	}
	select {
	case <-process.CleanupDone():
	default:
		t.Fatal("parent did not verify Session cleanup")
	}
	contents, err = os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(contents)))
	if err != nil || pid <= 1 {
		t.Fatalf("detached descendant PID = %q: %v", contents, err)
	}
	if info, err := api.info(pid); err == nil && info.Status != seatbeltProcStatusZombie {
		t.Fatalf("detached descendant survived: %+v", info)
	} else if err != nil && !errors.Is(err, syscall.ESRCH) {
		t.Fatal(err)
	}
	if remaining, err := process.sessionProcesses.allPIDs(); err != nil || len(remaining) != 0 {
		t.Fatalf("remaining Session processes = %v: %v", remaining, err)
	}
	if info, err := api.info(bystanderPID); err != nil || info.StartSecond != bystanderIdentity.StartSecond ||
		info.StartMicrosecond != bystanderIdentity.StartMicrosecond || info.Status == seatbeltProcStatusZombie || info.Status == seatbeltProcStatusStop {
		t.Fatalf("concurrent sandbox changed during cleanup: %+v, %v", info, err)
	}
}

// The target queues bytes on its controlling terminal. The record shows
// whether the queueing ioctl is permitted and whether bytes remain pending on
// the terminal after the backend returns it to the caller.
func TestSeatbeltReportsTerminalInputQueueAfterTargetExit(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	fixture := newSeatbeltTerminalNativeFixture(t)
	root := fixture.root
	master, terminal := seatbeltTerminalNativePair(t)
	if err := seatbeltTerminalNativeRaw(terminal); err != nil {
		t.Fatal(err)
	}
	output := &seatbeltBoundedCapture{limit: 4096}
	drainCancel := make(chan struct{})
	drainDone := make(chan error, 1)
	go func() { drainDone <- seatbeltTerminalNativeDrain(master, output, drainCancel) }()
	defer func() {
		close(drainCancel)
		<-drainDone
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], seatbeltDenialProbeRun, "--", "terminal-queue-harness", root)
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	command.WaitDelay = time.Second
	fixture.settled = false
	if err := command.Run(); err != nil {
		t.Logf("harness exit: %s", fixture.diagnostic(err))
	}
	fixture.settled = string(readSeatbeltPTYFile(filepath.Join(root, "harness-cleanup-proven"))) == seatbeltTerminalProbeOK
	target := string(readSeatbeltPTYFile(filepath.Join(root, "target-result")))
	pending := string(readSeatbeltPTYFile(filepath.Join(root, "pending-input")))
	seatbeltDenialEvidence(t, "settled=%v target=%q pending_after_restore=%q", fixture.settled, fixture.diagnostic(target), pending)
	if !fixture.settled {
		t.Fatal("terminal queue probe cleanup was not proven")
	}
	if pending != "0" && pending != "" {
		t.Skipf("input queued by the target remained pending after restore (%s bytes)", pending)
	}
}

// Exclusions of paths that do not exist yet are matched by pathname. The
// record shows whether alternate spellings that resolve to the same entry on
// the runner's volume can be created by a workspace-writable target.
func TestSeatbeltReportsAbsentExclusionSpellingVariants(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	for _, test := range []struct{ name, excluded, variant string }{
		{name: "control", excluded: ".envrc", variant: "unrelated"},
		{name: "exact", excluded: ".envrc", variant: ".envrc"},
		{name: "case-file", excluded: ".envrc", variant: ".ENVRC"},
		{name: "case-directory", excluded: "secrets", variant: "Secrets/token"},
		{name: "unicode-normalization", excluded: "caf\u00e9", variant: "cafe\u0301"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := seatbeltTestRequest(t)
			request.workspaceAccess = WorkspaceAccessReadWrite
			excluded := filepath.Join(request.workspace, test.excluded)
			request.filesystemExclusions = []FilesystemExclusion{{ID: "absent", path: excluded, logicalPath: excluded}}
			result := filepath.Join(request.sessionDirectory, "create-result")
			request.arguments = []string{seatbeltDenialProbeRun, "--", "create", result, filepath.Join(request.workspace, test.variant)}
			settled, err := seatbeltTerminalNativeRun(request)
			if !settled {
				t.Fatalf("create probe cleanup was not proven: %v", err)
			}
			outcome := string(readSeatbeltPTYFile(result))
			_, excludedErr := os.Stat(excluded)
			seatbeltDenialEvidence(t, "variant_create=%q excluded_path_exists_afterwards=%v", outcome, excludedErr == nil)
			if test.name == "control" {
				if outcome != "created" {
					t.Fatalf("workspace-writable target could not create an unrelated file: %s", outcome)
				}
				return
			}
			if test.name == "exact" {
				if outcome == "created" {
					t.Fatal("sandbox permitted creating an excluded path")
				}
				return
			}
			if outcome == "created" && excludedErr == nil {
				t.Skip("an alternate spelling created the excluded path on this volume")
			}
		})
	}
}

func TestSeatbeltDenialProbeHelper(t *testing.T) {
	var arguments []string
	for index, argument := range os.Args {
		if argument == "--" {
			arguments = os.Args[index+1:]
			break
		}
	}
	if len(arguments) == 0 {
		return
	}
	switch arguments[0] {
	case "exec":
		if len(arguments) < 3 {
			os.Exit(125)
		}
		os.Exit(seatbeltDenialProbeExec(arguments[1], arguments[2:]))
	case "listen":
		if len(arguments) != 3 {
			os.Exit(125)
		}
		os.Exit(seatbeltDenialProbeListen(arguments[1], arguments[2]))
	case "detach-and-signal-supervisor":
		if len(arguments) != 3 {
			os.Exit(125)
		}
		child := exec.Command(os.Args[0], seatbeltDenialProbeRun, "--", "heartbeat", arguments[1], arguments[2])
		child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := child.Start(); err != nil {
			os.Exit(91)
		}
		deadline := time.Now().Add(2 * time.Second)
		for {
			contents, err := os.ReadFile(arguments[2])
			if err == nil && strings.TrimSpace(string(contents)) == strconv.Itoa(child.Process.Pid) {
				break
			}
			if time.Now().After(deadline) {
				os.Exit(93)
			}
			time.Sleep(10 * time.Millisecond)
		}
		if err := syscall.Kill(os.Getppid(), syscall.SIGKILL); err != nil {
			os.Exit(92)
		}
		time.Sleep(100 * time.Millisecond)
		os.Exit(0)
	case "heartbeat":
		if len(arguments) != 3 {
			os.Exit(125)
		}
		_ = os.WriteFile(arguments[2], []byte(strconv.Itoa(os.Getpid())), 0o600)
		// Bounded so a leaked probe cannot outlive the CI job meaningfully.
		for count := 1; count <= 300; count++ {
			_ = os.WriteFile(arguments[1], []byte(strconv.Itoa(count)), 0o600)
			time.Sleep(100 * time.Millisecond)
		}
		os.Exit(0)
	case "create":
		if len(arguments) != 3 {
			os.Exit(125)
		}
		outcome := "created"
		if err := os.MkdirAll(filepath.Dir(arguments[2]), 0o700); err != nil {
			outcome = "mkdir-error: " + err.Error()
		} else if err := os.WriteFile(arguments[2], []byte("probe"), 0o600); err != nil {
			outcome = "write-error: " + err.Error()
		}
		_ = os.WriteFile(arguments[1], []byte(outcome), 0o600)
		os.Exit(0)
	case "terminal-queue-harness":
		if len(arguments) != 2 {
			os.Exit(125)
		}
		os.Exit(seatbeltDenialTerminalQueueHarness(arguments[1]))
	case "terminal-queue":
		if len(arguments) != 2 {
			os.Exit(125)
		}
		_ = os.WriteFile(arguments[1], []byte(seatbeltDenialQueueTerminalInput()), 0o600)
		os.Exit(0)
	}
	os.Exit(125)
}

func seatbeltDenialProbeExec(result string, argv []string) int {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
	output, err := command.CombinedOutput()
	code := -1
	if command.ProcessState != nil {
		code = command.ProcessState.ExitCode()
	}
	text := string(output)
	if len(text) > 512 {
		text = text[:512]
	}
	record := fmt.Sprintf("exit=%d err=%v output=%q", code, err, text)
	if writeErr := os.WriteFile(result, []byte(record), 0o600); writeErr != nil {
		return 90
	}
	return 0
}

func seatbeltDenialProbeListen(portFile, result string) int {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = os.WriteFile(portFile, []byte("listen-error: "+err.Error()), 0o600)
		_ = os.WriteFile(result, []byte("listen-error: "+err.Error()), 0o600)
		return 0
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	if err := os.WriteFile(portFile, []byte("port "+strconv.Itoa(port)), 0o600); err != nil {
		return 90
	}
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	connection, err := listener.Accept()
	if err != nil {
		_ = os.WriteFile(result, []byte("accept-error: "+err.Error()), 0o600)
		return 0
	}
	_ = connection.Close()
	_ = os.WriteFile(result, []byte("accepted"), 0o600)
	return 0
}

func seatbeltDenialTerminalQueueHarness(root string) int {
	request, err := seatbeltNativePTYRequest(root)
	if err != nil {
		return 93
	}
	result := filepath.Join(request.sessionDirectory, "terminal-queue-result")
	request.arguments = []string{seatbeltDenialProbeRun, "--", "terminal-queue", result}
	request.terminal = Terminal{Input: os.Stdin, Output: os.Stdout, ErrorOutput: os.Stderr}
	settled, runErr := seatbeltTerminalNativeRun(request)
	pending, pendingErr := unix.IoctlGetInt(int(os.Stdin.Fd()), seatbeltDenialFIONREAD)
	pendingRecord := strconv.Itoa(pending)
	if pendingErr != nil {
		pendingRecord = "error: " + pendingErr.Error()
	}
	_ = os.WriteFile(filepath.Join(root, "pending-input"), []byte(pendingRecord), 0o600)
	target := string(readSeatbeltPTYFile(result))
	if runErr != nil {
		target += fmt.Sprintf(" run_err=%v", runErr)
	}
	_ = os.WriteFile(filepath.Join(root, "target-result"), []byte(target), 0o600)
	// Leave nothing queued for whichever process reads this disposable PTY next.
	_ = unix.IoctlSetPointerInt(int(os.Stdin.Fd()), unix.TIOCFLUSH, 0x1)
	if settled {
		_ = os.WriteFile(filepath.Join(root, "harness-cleanup-proven"), []byte(seatbeltTerminalProbeOK), 0o600)
	}
	return 0
}

// seatbeltDenialQueueTerminalInput returns "queued", or the first error.
func seatbeltDenialQueueTerminalInput() string {
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return "open-error: " + err.Error()
	}
	defer terminal.Close()
	for _, value := range []byte("acs-queued-input\n") {
		character := value
		if _, _, errno := unix.Syscall(unix.SYS_IOCTL, terminal.Fd(), uintptr(unix.TIOCSTI), uintptr(unsafe.Pointer(&character))); errno != 0 {
			if errors.Is(errno, syscall.EPERM) || errors.Is(errno, syscall.EACCES) {
				return "denied: " + errno.Error()
			}
			return "error: " + errno.Error()
		}
	}
	return "queued"
}
