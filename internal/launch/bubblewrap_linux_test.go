//go:build linux

package launch

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	handled, err := RunBubblewrapHelper(os.Args[1:])
	if handled {
		if err != nil {
			if exitCode, isTargetExit := BubblewrapHelperExitCode(err); isTargetExit {
				os.Exit(exitCode)
			}
			fmt.Fprintln(os.Stderr, "launch: Bubblewrap helper failed")
			os.Exit(1)
		}
		return
	}
	os.Exit(m.Run())
}

var bubblewrapNativeTargetArguments = []string{"ordinary", "--", "--setenv", "PWD=/private/workspace", ""}

func TestBubblewrapNativeContainmentContract(t *testing.T) {
	platform, err := CurrentPlatform()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlatform(platform); err != nil {
		t.Fatalf("native Bubblewrap test requires certified Ubuntu 24.04: %v", err)
	}

	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	sessions := filepath.Join(root, "sessions")
	session := filepath.Join(sessions, "session-native")
	home := filepath.Join(session, "home")
	temporary := filepath.Join(session, "tmp")
	for _, directory := range []string{workspace, home, temporary} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	runtimeInput := filepath.Join(root, "runtime.txt")
	if err := os.WriteFile(runtimeInput, []byte("runtime-input"), 0o600); err != nil {
		t.Fatal(err)
	}
	hostSecret := filepath.Join(root, "host-secret")
	if err := os.WriteFile(hostSecret, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hostSecret, filepath.Join(workspace, "secret-link")); err != nil {
		t.Fatal(err)
	}
	hostDescriptor, err := os.Open(hostSecret)
	if err != nil {
		t.Fatal(err)
	}
	defer hostDescriptor.Close()
	if _, err := unix.FcntlInt(hostDescriptor.Fd(), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	hostSocket := filepath.Join(root, "host.sock")
	unixListener, err := net.Listen("unix", hostSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer unixListener.Close()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
		}
		accepted <- acceptErr
	}()

	var output bytes.Buffer
	sandbox := NewProcessSandbox()
	process, err := sandbox.Prepare(context.Background(), ProcessRequest{
		Workspace:          workspace,
		SessionsDirectory:  sessions,
		SessionDirectory:   session,
		SessionHome:        home,
		TemporaryDirectory: temporary,
		Executable:         os.Args[0],
		RuntimeInputs:      []string{runtimeInput},
		Arguments: []string{
			"-test.run=^TestBubblewrapNativeHelper$", "--",
			workspace, session, temporary, runtimeInput, hostSecret, listener.Addr().String(), hostSocket, strconv.Itoa(int(hostDescriptor.Fd())),
		},
		Terminal: Terminal{Input: strings.NewReader(""), Output: &output, ErrorOutput: &output},
	})
	if err != nil {
		t.Fatalf("prepare native Bubblewrap process: %v", err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatalf("native containment helper failed: %v; output=%q", err, output.String())
	}
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("accept sandbox IP connection: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sandbox did not preserve outbound IP networking")
	}
	for _, marker := range []string{
		filepath.Join(workspace, "workspace-writable"),
		filepath.Join(session, "session-writable"),
		filepath.Join(temporary, "temporary-writable"),
		filepath.Join(session, "descendant-contained"),
	} {
		if _, err := os.Stat(marker); err != nil {
			t.Errorf("expected sandbox marker %s: %v", filepath.Base(marker), err)
		}
	}
	if got := strings.TrimSpace(output.String()); got != "runtime-input" {
		t.Errorf("sandbox helper output = %q, want runtime input", got)
	}
}

func TestBubblewrapNativeSanitizesDescriptorsAcrossConcurrentLaunches(t *testing.T) {
	platform, err := CurrentPlatform()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlatform(platform); err != nil {
		t.Fatalf("native Bubblewrap test requires certified Ubuntu 24.04: %v", err)
	}
	secret := filepath.Join(t.TempDir(), "host-secret")
	if err := os.WriteFile(secret, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	descriptor, err := os.Open(secret)
	if err != nil {
		t.Fatal(err)
	}
	defer descriptor.Close()
	if _, err := unix.FcntlInt(descriptor.Fd(), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}

	processes := make([]Process, 4)
	for index := range processes {
		request := validProcessRequest(t)
		request.Executable = os.Args[0]
		request.Arguments = []string{
			"-test.run=^TestBubblewrapNativeDescriptorHelper$", "--", strconv.Itoa(int(descriptor.Fd())), secret,
		}
		process, err := NewProcessSandbox().Prepare(context.Background(), request)
		if err != nil {
			t.Fatalf("prepare concurrent sandbox %d: %v", index, err)
		}
		processes[index] = process
	}

	start := make(chan struct{})
	errors := make(chan error, len(processes))
	var group sync.WaitGroup
	for _, process := range processes {
		group.Add(1)
		go func(process Process) {
			defer group.Done()
			<-start
			if err := process.Start(); err != nil {
				errors <- err
				return
			}
			errors <- process.Wait()
		}(process)
	}
	close(start)
	group.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatalf("concurrent sandbox process failed: %v", err)
		}
	}
	flags, err := unix.FcntlInt(descriptor.Fd(), unix.F_GETFD, 0)
	if err != nil || flags&unix.FD_CLOEXEC != 0 {
		t.Fatalf("parent descriptor flags = %d, err = %v, want non-CLOEXEC", flags, err)
	}
	if contents, err := os.ReadFile(descriptor.Name()); err != nil || string(contents) != "private" {
		t.Fatalf("parent descriptor changed after concurrent launch: contents=%q, err=%v", contents, err)
	}
}

func TestBubblewrapNativeStartupDescriptorsDoNotReachTarget(t *testing.T) {
	platform, err := CurrentPlatform()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlatform(platform); err != nil {
		t.Fatalf("native Bubblewrap test requires certified Ubuntu 24.04: %v", err)
	}
	request := validProcessRequest(t)
	request.Executable = os.Args[0]
	request.Arguments = []string{
		"-test.run=^TestBubblewrapNativeStartupDescriptorHelper$", "--", "INFORMATION_PIPE", "RELEASE_PIPE",
	}
	prepared, err := NewProcessSandbox().Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	sanitized, ok := prepared.(sanitizedProcess)
	if !ok {
		t.Fatalf("prepared process = %T, want sanitizedProcess", prepared)
	}
	process, ok := sanitized.process.(*bubblewrapProcess)
	if !ok {
		t.Fatalf("sanitized process = %T, want *bubblewrapProcess", sanitized.process)
	}
	informationPipe, err := os.Readlink(filepath.Join("/proc/self/fd", strconv.Itoa(int(process.childDescriptors[0].Fd()))))
	if err != nil {
		t.Fatal(err)
	}
	releasePipe, err := os.Readlink(filepath.Join("/proc/self/fd", strconv.Itoa(int(process.childDescriptors[1].Fd()))))
	if err != nil {
		t.Fatal(err)
	}
	for index, argument := range process.command.Args {
		switch argument {
		case "INFORMATION_PIPE":
			process.command.Args[index] = informationPipe
		case "RELEASE_PIPE":
			process.command.Args[index] = releasePipe
		}
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestBubblewrapCapabilityProbeArgumentsUseProductionMergedUsrTopology(t *testing.T) {
	want := []string{
		"--unshare-user", "--unshare-ipc", "--unshare-pid", "--unshare-uts", "--unshare-cgroup",
		"--die-with-parent", "--clearenv", "--proc", "/proc", "--dev", "/dev",
		"--dir", "/tmp",
		"--symlink", "usr/bin", "/bin",
		"--symlink", "usr/sbin", "/sbin",
		"--symlink", "usr/lib", "/lib",
		"--symlink", "usr/lib64", "/lib64",
		"--ro-bind", "/usr", "/usr", "--remount-ro", "/",
		"--setenv", "PATH", safeProcessPath, "--chdir", "/tmp", "--", "/usr/bin/true",
	}
	if got := bubblewrapCapabilityProbeArguments(); !reflect.DeepEqual(got, want) {
		t.Fatalf("capability probe arguments = %q, want %q", got, want)
	}
}

func TestBubblewrapHelperArgumentsDoNotDependOnExecutableName(t *testing.T) {
	arguments := []string{"--setenv", "TERM", "xterm-256color", "--", "/opt/devin/bin/devin", "skills", "list", "--json"}
	want := append([]string{"/proc/self/exe", bubblewrapHelperFlag, "0"}, arguments...)
	originalExecutable := os.Args[0]
	defer func() { os.Args[0] = originalExecutable }()

	for _, executable := range []string{"/usr/local/bin/acs", "/tmp/launch.test", "/tmp/arbitrary-name"} {
		t.Run(filepath.Base(executable), func(t *testing.T) {
			os.Args[0] = executable
			command, err := newBubblewrapCommand(context.Background(), arguments)
			if err != nil {
				t.Fatal(err)
			}
			if got := command.Args; !reflect.DeepEqual(got, want) {
				t.Fatalf("helper arguments for %q = %q, want %q", executable, got, want)
			}
		})
	}
}

func TestBubblewrapTargetSupervisorRequestMountsOriginalTarget(t *testing.T) {
	request := validatedProcessRequest{
		executable:    "/opt/devin/bin/devin",
		runtimeInputs: []string{"/opt/devin/runtime"},
		arguments:     []string{"skills", "list", "--json"},
	}
	prepared, err := bubblewrapTargetSupervisorRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if prepared.executable == request.executable {
		t.Fatal("target supervisor did not replace the Bubblewrap executable")
	}
	if !slices.Contains(prepared.runtimeInputs, request.executable) {
		t.Fatalf("target supervisor runtime inputs = %q, want original target %q", prepared.runtimeInputs, request.executable)
	}
	want := []string{bubblewrapTargetSupervisorFlag, request.executable, "skills", "list", "--json"}
	if !reflect.DeepEqual(prepared.arguments, want) {
		t.Fatalf("target supervisor arguments = %q, want %q", prepared.arguments, want)
	}
}

func newPreparedBubblewrapProcess(t *testing.T) *bubblewrapProcess {
	t.Helper()
	process, err := (bubblewrapBackend{}).prepare(context.Background(), validatedProcessRequest{
		workspace: "/workspace", sessionDirectory: "/session", executable: os.Args[0], environment: []string{"PATH=" + safeProcessPath},
	})
	if err != nil {
		t.Fatal(err)
	}
	bubblewrap, ok := process.(*bubblewrapProcess)
	if !ok {
		t.Fatalf("prepared process = %T, want *bubblewrapProcess", process)
	}
	t.Cleanup(bubblewrap.closeStartupDescriptors)
	return bubblewrap
}

func TestBubblewrapPreparedProcessKeepsParentDeathSignal(t *testing.T) {
	bubblewrap := newPreparedBubblewrapProcess(t)
	if bubblewrap.command.SysProcAttr == nil || bubblewrap.command.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("parent death signal = %v, want %v", bubblewrap.command.SysProcAttr, syscall.SIGKILL)
	}
	if got := len(bubblewrap.command.ExtraFiles); got != 2 {
		t.Fatalf("Bubblewrap startup descriptor count = %d, want 2", got)
	}
	for _, argument := range []string{"--as-pid-1", "--info-fd", "3", "--userns-block-fd", "4"} {
		if !slices.Contains(bubblewrap.command.Args, argument) {
			t.Fatalf("prepared Bubblewrap arguments lack %q: %q", argument, bubblewrap.command.Args)
		}
	}
}

func TestBubblewrapPreparedProcessCancellationStopsStableIdentities(t *testing.T) {
	bubblewrap := newPreparedBubblewrapProcess(t)
	bubblewrap.targetDescriptor = 77
	bubblewrap.monitorDescriptor = 88
	var signals []string
	bubblewrap.pidfdSignal = func(descriptor int, signal unix.Signal) error {
		signals = append(signals, fmt.Sprintf("target:%d:%s", descriptor, signal))
		return nil
	}
	bubblewrap.monitorPidfdSignal = func(descriptor int, signal unix.Signal) error {
		signals = append(signals, fmt.Sprintf("monitor:%d:%s", descriptor, signal))
		return nil
	}
	if err := bubblewrap.command.Cancel(); err != nil {
		t.Fatal(err)
	}
	wantSignals := []string{"target:77:killed", "monitor:88:killed"}
	if !reflect.DeepEqual(signals, wantSignals) {
		t.Fatalf("context cancellation signals = %q, want %q", signals, wantSignals)
	}
	targetErr := errors.New("target signal denied")
	monitorErr := errors.New("monitor signal denied")
	bubblewrap.pidfdSignal = func(int, unix.Signal) error { return targetErr }
	bubblewrap.monitorPidfdSignal = func(int, unix.Signal) error { return monitorErr }
	err := bubblewrap.command.Cancel()
	if !errors.Is(err, targetErr) || !errors.Is(err, monitorErr) {
		t.Fatalf("context cancellation error = %v, want target and monitor failures", err)
	}
}

func TestBubblewrapStartEstablishesStableIdentityBeforeImmediateSignal(t *testing.T) {
	process := newBubblewrapHandshakeTestProcess(t, context.Background(), `{ "child-pid": 101 }`, 5*time.Second)
	openedPID := 0
	process.pidfdOpen = func(pid, flags int) (int, error) {
		openedPID = pid
		return 77, nil
	}
	process.pidfdClose = func(int) error { return nil }
	aliveChecks := 0
	process.pidfdAlive = func(descriptor int) error {
		if descriptor != 77 {
			t.Fatalf("identity check used descriptor %d, want pidfd 77", descriptor)
		}
		aliveChecks++
		return nil
	}
	mappedPID := 0
	process.configureUserNS = func(pid int) error {
		mappedPID = pid
		return nil
	}
	process.targetReady = func(int, int) (bool, error) { return true, nil }
	process.signalCaught = func(int, syscall.Signal) (bool, error) { return true, nil }
	process.pidfdSignal = func(descriptor int, signal unix.Signal) error {
		if descriptor != 77 || signal != unix.SIGTERM {
			t.Fatalf("stable signal target = (%d, %v), want (77, SIGTERM)", descriptor, signal)
		}
		return nil
	}

	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if openedPID != 101 {
		t.Fatalf("pidfd opened for %d, want reported child 101", openedPID)
	}
	if mappedPID != 101 || aliveChecks != 2 {
		t.Fatalf("startup identity evidence = mapped PID %d, alive checks %d; want 101 and 2", mappedPID, aliveChecks)
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestBubblewrapSignalCannotBeRetargetedByPIDSubstitution(t *testing.T) {
	process := newBubblewrapHandshakeTestProcess(t, context.Background(), `{ "child-pid": 101 }`, 5*time.Second)
	process.pidfdOpen = func(pid, flags int) (int, error) { return 77, nil }
	process.pidfdClose = func(int) error { return nil }
	process.pidfdAlive = func(int) error { return nil }
	process.configureUserNS = func(int) error { return nil }
	process.targetReady = func(int, int) (bool, error) { return true, nil }
	process.signalCaught = func(int, syscall.Signal) (bool, error) { return true, nil }
	process.pidfdSignal = func(descriptor int, signal unix.Signal) error {
		if descriptor != 77 {
			t.Fatalf("signal used substituted PID identity %d, want original pidfd 77", descriptor)
		}
		return nil
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	process.targetPID = 202
	if err := process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestBubblewrapDefaultTerminatingSignalStopsStableTargetAndMonitor(t *testing.T) {
	process := newBubblewrapHandshakeTestProcess(t, context.Background(), `{ "child-pid": 101 }`, 5*time.Second)
	process.monitorPidfdOpen = func(pid, flags int) (int, error) { return 88, nil }
	process.monitorPidfdClose = func(int) error { return nil }
	process.pidfdOpen = func(pid, flags int) (int, error) { return 77, nil }
	process.pidfdClose = func(int) error { return nil }
	process.pidfdAlive = func(int) error { return nil }
	process.configureUserNS = func(int) error { return nil }
	process.targetReady = func(int, int) (bool, error) { return true, nil }
	process.signalCaught = func(int, syscall.Signal) (bool, error) { return false, nil }
	var signals []string
	process.pidfdSignal = func(descriptor int, signal unix.Signal) error {
		signals = append(signals, fmt.Sprintf("target:%d:%s", descriptor, signal))
		return nil
	}
	process.monitorPidfdSignal = func(descriptor int, signal unix.Signal) error {
		signals = append(signals, fmt.Sprintf("monitor:%d:%s", descriptor, signal))
		return nil
	}
	process.monitorPidfdWait = func(descriptor int) error {
		if process.command.ProcessState != nil {
			return nil
		}
		signals = append(signals, fmt.Sprintf("wait:%d", descriptor))
		return nil
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	wantSignals := []string{"target:77:stopped (signal)", "monitor:88:terminated", "wait:88", "target:77:killed"}
	if !reflect.DeepEqual(signals, wantSignals) {
		t.Fatalf("default termination signals = %q, want %q", signals, wantSignals)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestBubblewrapTerminatingSignalBoundsMonitorExitProofAndStillKillsTarget(t *testing.T) {
	process := &bubblewrapProcess{
		monitorDescriptor: 88,
		targetDescriptor:  77,
		targetPID:         101,
		teardownTimeout:   5 * time.Millisecond,
		signalCaught:      func(int, syscall.Signal) (bool, error) { return false, nil },
	}
	var signals []string
	process.pidfdSignal = func(descriptor int, signal unix.Signal) error {
		signals = append(signals, fmt.Sprintf("target:%d:%s", descriptor, signal))
		return nil
	}
	process.monitorPidfdSignal = func(descriptor int, signal unix.Signal) error {
		signals = append(signals, fmt.Sprintf("monitor:%d:%s", descriptor, signal))
		return nil
	}
	pollCalls := 0
	process.pidfdPoll = func(_ []unix.PollFd, timeout int) (int, error) {
		if timeout <= 0 {
			t.Fatalf("pidfd poll timeout = %d, want a positive bound", timeout)
		}
		pollCalls++
		return 0, nil
	}
	started := time.Now()
	err := process.Signal(syscall.SIGTERM)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Signal error = %v, want bounded monitor exit timeout", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Signal remained blocked for %v after monitor exit proof timed out", elapsed)
	}
	if pollCalls == 0 {
		t.Fatal("Signal did not poll the stable monitor identity")
	}
	wantSignals := []string{"target:77:stopped (signal)", "monitor:88:terminated", "target:77:killed"}
	if !reflect.DeepEqual(signals, wantSignals) {
		t.Fatalf("bounded termination signals = %q, want %q", signals, wantSignals)
	}
}

func TestBubblewrapCancellationAfterSuccessfulExitReturnsProcessDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	command := exec.CommandContext(ctx, "/bin/true")
	process := &bubblewrapProcess{
		ctx:               ctx,
		command:           command,
		monitorDescriptor: -1,
		targetDescriptor:  -1,
	}
	command.Cancel = process.cancel
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	descriptor, err := unix.PidfdOpen(command.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	process.monitorDescriptor = descriptor
	poll := []unix.PollFd{{Fd: int32(descriptor), Events: unix.POLLIN}}
	if ready, err := unix.Poll(poll, 2_000); err != nil || ready != 1 || poll[0].Revents&unix.POLLIN == 0 {
		t.Fatalf("successful command did not become waitable: ready=%d revents=%#x err=%v", ready, poll[0].Revents, err)
	}
	cancel()
	if err := process.Wait(); err != nil {
		t.Fatalf("Wait after successful exit and context cancellation = %v, want nil", err)
	}
}

func TestBubblewrapWaitProvesStableTargetAndMonitorExitBeforeReturning(t *testing.T) {
	process := &bubblewrapProcess{
		command:           exec.Command("/bin/true"),
		monitorDescriptor: 88,
		targetDescriptor:  77,
		cleanupDone:       make(chan struct{}),
	}
	var events []string
	process.pidfdWait = func(descriptor int) error {
		events = append(events, fmt.Sprintf("target-wait:%d", descriptor))
		return nil
	}
	process.monitorPidfdWait = func(descriptor int) error {
		events = append(events, fmt.Sprintf("monitor-wait:%d", descriptor))
		return nil
	}
	process.pidfdClose = func(descriptor int) error {
		events = append(events, fmt.Sprintf("target-close:%d", descriptor))
		return nil
	}
	process.monitorPidfdClose = func(descriptor int) error {
		events = append(events, fmt.Sprintf("monitor-close:%d", descriptor))
		return nil
	}
	if err := process.command.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	want := []string{"target-wait:77", "monitor-wait:88", "target-close:77", "monitor-close:88"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("Wait lifecycle events = %q, want %q", events, want)
	}
	select {
	case <-process.CleanupDone():
	default:
		t.Fatal("Wait returned before process-tree cleanup completed")
	}
}

func TestBubblewrapWaitQuarantinesAnUnprovenProcessTree(t *testing.T) {
	process := &bubblewrapProcess{
		command:           exec.Command("/bin/true"),
		monitorDescriptor: 88,
		targetDescriptor:  77,
		cleanupDone:       make(chan struct{}),
	}
	proofErr := fmt.Errorf("target exit proof unavailable")
	process.pidfdWait = func(int) error { return proofErr }
	process.monitorPidfdWait = func(int) error { return nil }
	quarantined := false
	process.cleanupQuarantine = func(got *bubblewrapProcess) {
		if got != process {
			t.Fatalf("quarantined process = %p, want %p", got, process)
		}
		quarantined = true
	}
	if err := process.command.Start(); err != nil {
		t.Fatal(err)
	}
	err := process.Wait()
	if !errors.Is(err, proofErr) {
		t.Fatalf("Wait error = %v, want stable target proof failure", err)
	}
	if !quarantined {
		t.Fatal("Wait did not transfer the unproven tree to cleanup quarantine")
	}
	if process.targetDescriptor != 77 || process.monitorDescriptor != 88 {
		t.Fatal("Wait closed stable identities before quarantined cleanup completed")
	}
	select {
	case <-process.CleanupDone():
		t.Fatal("Wait reported cleanup completion for an unproven process tree")
	default:
	}
}

func TestBubblewrapStartupHandshakeFailures(t *testing.T) {
	t.Run("malformed status", func(t *testing.T) {
		process := newBubblewrapHandshakeTestProcess(t, context.Background(), `not-json`, 5*time.Second)
		if err := process.Start(); err == nil || !strings.Contains(err.Error(), "startup handshake") {
			t.Fatalf("start error = %v, want handshake failure", err)
		}
	})

	t.Run("timeout", func(t *testing.T) {
		process := newBubblewrapHandshakeTestProcess(t, context.Background(), "", 20*time.Millisecond)
		if err := process.Start(); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("start error = %v, want deadline exceeded", err)
		}
	})

	t.Run("cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		process := newBubblewrapHandshakeTestProcess(t, ctx, "", 5*time.Second)
		informationFile := process.information
		heldWriterDescriptor, err := unix.FcntlInt(process.childDescriptors[0].Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		heldWriter := os.NewFile(uintptr(heldWriterDescriptor), "held-bubblewrap-information-writer")
		defer heldWriter.Close()
		callbackRegistered := make(chan struct{})
		callbackScheduled := make(chan struct{})
		runCallback := make(chan struct{})
		callbackDone := make(chan struct{})
		process.afterFunc = func(ctx context.Context, callback func()) func() bool {
			process.information = nil
			close(callbackRegistered)
			go func() {
				<-ctx.Done()
				close(callbackScheduled)
				<-runCallback
				callback()
				close(callbackDone)
			}()
			return func() bool { return false }
		}
		releaseCallback := sync.OnceFunc(func() { close(runCallback) })
		defer releaseCallback()
		result := make(chan error, 1)
		go func() { result <- process.Start() }()
		waitForSignal := func(signal <-chan struct{}, description string) {
			t.Helper()
			select {
			case <-signal:
			case <-time.After(2 * time.Second):
				t.Fatalf("timed out waiting for %s", description)
			}
		}
		waitForSignal(callbackRegistered, "cancellation callback registration")
		cancel()
		waitForSignal(callbackScheduled, "cancellation callback scheduling")
		releaseCallback()
		waitForSignal(callbackDone, "cancellation callback completion")
		if _, err := informationFile.Stat(); !errors.Is(err, os.ErrClosed) {
			_ = informationFile.Close()
			select {
			case <-result:
			case <-time.After(2 * time.Second):
			}
			t.Fatalf("captured startup information descriptor remains open after callback: %v", err)
		}
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("start error = %v, want cancellation", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for canceled startup")
		}
		if process.information != nil {
			t.Fatal("startup information descriptor ownership was not cleared")
		}
		if err := heldWriter.Close(); err != nil {
			t.Fatalf("close held startup information writer: %v", err)
		}
	})

	t.Run("namespace setup", func(t *testing.T) {
		process := newBubblewrapHandshakeTestProcess(t, context.Background(), `{ "child-pid": 101 }`, 5*time.Second)
		process.pidfdOpen = func(int, int) (int, error) { return 77, nil }
		process.pidfdClose = func(int) error { return nil }
		process.pidfdAlive = func(int) error { return nil }
		process.configureUserNS = func(int) error { return errors.New("mapping rejected") }
		if err := process.Start(); err == nil || !strings.Contains(err.Error(), "configure Bubblewrap user namespace") {
			t.Fatalf("start error = %v, want namespace handshake failure", err)
		}
	})
}

func TestBubblewrapPreIdentityAbortKillsBlockedChildWithoutParentDeathSignal(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "target-executed")
	process := newBubblewrapPreIdentityBlockedTargetTestProcess(t, context.Background(), marker, 5*time.Second)
	if err := process.Start(); err == nil || !strings.Contains(err.Error(), "startup handshake") {
		t.Fatalf("Start error = %v, want malformed startup handshake", err)
	}
	if process.command.ProcessState == nil {
		t.Fatal("Bubblewrap monitor was not reaped")
	}
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("blocked child survived pre-identity cleanup and crossed the release barrier")
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBubblewrapPreIdentityCancellationKillsBlockedChildWithoutParentDeathSignal(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "target-executed")
	ctx, cancel := context.WithCancel(context.Background())
	process := newBubblewrapPreIdentityCancellationTestProcess(t, ctx, marker, 5*time.Second)
	result := make(chan error, 1)
	go func() { result <- process.Start() }()
	ready := marker + ".ready"
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("blocked child did not reach the pre-identity release barrier")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Start error = %v, want context cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled startup cleanup did not complete")
	}
	deadline = time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			t.Fatal("blocked child survived pre-identity cancellation and crossed the release barrier")
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBubblewrapStartupFailuresCannotReleaseBlockedTarget(t *testing.T) {
	tests := []struct {
		name         string
		configure    func(context.CancelFunc, *int) func(int) error
		alive        func(*int) func(int) error
		releaseReady func(int, int) error
		targetKill   error
		wantError    error
		contains     string
	}{
		{
			name: "mapping failure",
			configure: func(_ context.CancelFunc, targetPID *int) func(int) error {
				return func(pid int) error {
					*targetPID = pid
					return errors.New("mapping rejected")
				}
			},
			contains: "configure Bubblewrap user namespace",
		},
		{
			name: "cancellation after mapping",
			configure: func(cancel context.CancelFunc, targetPID *int) func(int) error {
				return func(pid int) error {
					*targetPID = pid
					cancel()
					return nil
				}
			},
			wantError: context.Canceled,
		},
		{
			name: "readiness failure after mapping",
			configure: func(_ context.CancelFunc, targetPID *int) func(int) error {
				return func(pid int) error {
					*targetPID = pid
					return nil
				}
			},
			releaseReady: func(int, int) error { return errors.New("not ready") },
			contains:     "verify Bubblewrap target readiness",
		},
		{
			name: "identity failure after mapping",
			configure: func(_ context.CancelFunc, targetPID *int) func(int) error {
				return func(pid int) error {
					*targetPID = pid
					return nil
				}
			},
			alive: func(calls *int) func(int) error {
				return func(descriptor int) error {
					*calls++
					if *calls == 2 {
						return errors.New("identity changed")
					}
					return unix.PidfdSendSignal(descriptor, 0, nil, 0)
				}
			},
			contains: "reverify Bubblewrap target identity",
		},
		{
			name: "target kill failure",
			configure: func(_ context.CancelFunc, targetPID *int) func(int) error {
				return func(pid int) error {
					*targetPID = pid
					return errors.New("mapping rejected")
				}
			},
			targetKill: unix.EPERM,
			contains:   "configure Bubblewrap user namespace",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := openDescriptorCount(t)
			marker := filepath.Join(t.TempDir(), "target-executed")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			process := newBubblewrapBlockedTargetTestProcess(t, ctx, marker, 500*time.Millisecond)
			targetPID := 0
			process.configureUserNS = test.configure(cancel, &targetPID)
			aliveCalls := 0
			if test.alive != nil {
				process.pidfdAlive = test.alive(&aliveCalls)
			}
			if test.releaseReady != nil {
				process.releaseReady = test.releaseReady
			}
			if test.targetKill != nil {
				process.pidfdSignal = func(descriptor int, signal unix.Signal) error {
					if signal == unix.SIGKILL {
						return test.targetKill
					}
					return unix.PidfdSendSignal(descriptor, signal, nil, 0)
				}
			}
			var targetExitDescriptor int
			process.pidfdOpen = func(pid, flags int) (int, error) {
				descriptor, err := unix.PidfdOpen(pid, flags)
				if err != nil {
					return -1, err
				}
				targetExitDescriptor, err = unix.Dup(descriptor)
				if err != nil {
					_ = unix.Close(descriptor)
					return -1, err
				}
				return descriptor, nil
			}

			result := make(chan error, 1)
			go func() { result <- process.Start() }()
			var startErr error
			select {
			case startErr = <-result:
			case <-time.After(2 * time.Second):
				t.Fatal("startup cleanup did not complete within two seconds")
			}
			if startErr == nil {
				t.Fatal("Start succeeded after injected startup failure")
			}
			if test.wantError != nil && !errors.Is(startErr, test.wantError) {
				t.Fatalf("start error = %v, want %v", startErr, test.wantError)
			}
			if test.contains != "" && !strings.Contains(startErr.Error(), test.contains) {
				t.Fatalf("start error = %v, want %q", startErr, test.contains)
			}
			if targetPID <= 0 || targetExitDescriptor < 0 {
				t.Fatalf("startup did not establish target identity: pid=%d pidfd=%d", targetPID, targetExitDescriptor)
			}
			poll := []unix.PollFd{{Fd: int32(targetExitDescriptor), Events: unix.POLLIN}}
			if ready, err := unix.Poll(poll, 2_000); err != nil || ready != 1 || poll[0].Revents&unix.POLLIN == 0 {
				t.Fatalf("blocked target survived cleanup: ready=%d revents=%#x err=%v", ready, poll[0].Revents, err)
			}
			if err := unix.Close(targetExitDescriptor); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("blocked target executed after Start failed: %v", err)
			}
			if process.command.ProcessState == nil {
				t.Fatal("Bubblewrap monitor was not reaped")
			}
			if process.information != nil || process.release != nil || process.childDescriptors != nil || process.monitorDescriptor >= 0 || process.targetDescriptor >= 0 {
				t.Fatal("startup cleanup retained a protocol or identity descriptor")
			}
			if after := openDescriptorCount(t); after != before {
				t.Fatalf("startup cleanup leaked descriptors: before=%d after=%d", before, after)
			}
		})
	}
}

func TestBubblewrapAbortStartUsesProtocolSafeOrdering(t *testing.T) {
	t.Run("target identity available", func(t *testing.T) {
		process := newBubblewrapHandshakeTestProcess(t, context.Background(), `{ "child-pid": 101 }`, 5*time.Second)
		process.pidfdOpen = func(int, int) (int, error) { return 77, nil }
		process.pidfdClose = func(int) error { return nil }
		targetProven := false
		process.pidfdWait = func(descriptor int) error {
			if descriptor != 77 || process.release == nil {
				t.Fatalf("target exit proof = (%d, gate open %t), want (77, true)", descriptor, process.release != nil)
			}
			targetProven = true
			return nil
		}
		process.pidfdAlive = func(int) error { return nil }
		process.configureUserNS = func(int) error { return errors.New("mapping rejected") }
		process.pidfdSignal = func(int, unix.Signal) error {
			if process.release == nil {
				t.Fatal("release descriptor closed before stable target kill")
			}
			return nil
		}
		monitorSignaled := false
		process.monitorPidfdSignal = func(int, unix.Signal) error {
			if process.release != nil || !targetProven {
				t.Fatal("monitor stopped before target death proof and protocol descriptor closure")
			}
			monitorSignaled = true
			return nil
		}
		waitCalls := 0
		process.monitorWait = func() error {
			waitCalls++
			if !monitorSignaled {
				t.Fatal("monitor reaped before it was signaled")
			}
			if process.release != nil {
				t.Fatal("monitor reaped before protocol descriptors closed after stable target kill")
			}
			return process.command.Wait()
		}
		if err := process.Start(); err == nil {
			t.Fatal("Start succeeded after mapping failure")
		}
		if waitCalls != 1 {
			t.Fatalf("monitor wait calls = %d, want 1", waitCalls)
		}
	})

	t.Run("before target identity", func(t *testing.T) {
		process := newBubblewrapHandshakeTestProcess(t, context.Background(), `not-json`, 5*time.Second)
		monitorFrozen := false
		monitorKilled := false
		childKilled := false
		childExited := false
		retryCalls := 0
		process.monitorPidfdSignal = func(descriptor int, signal unix.Signal) error {
			if process.release == nil {
				t.Fatal("release descriptor closed before stable monitor teardown")
			}
			if descriptor != 88 {
				t.Fatalf("monitor signal descriptor = %d, want 88", descriptor)
			}
			switch signal {
			case unix.SIGSTOP:
				monitorFrozen = true
				return nil
			case unix.SIGKILL:
				if !childExited {
					t.Fatal("monitor killed before its stable child was proved dead")
				}
				monitorKilled = true
				return process.command.Process.Kill()
			default:
				t.Fatalf("unexpected monitor signal %v", signal)
				return nil
			}
		}
		process.monitorPidfdStopped = func(descriptor int) error {
			if descriptor != 88 || !monitorFrozen {
				t.Fatalf("monitor stop proof = (%d, %t), want (88, true)", descriptor, monitorFrozen)
			}
			return nil
		}
		process.monitorChildren = func(pid int) ([]int, error) {
			if pid != process.command.Process.Pid || !monitorFrozen {
				t.Fatalf("monitor child enumeration = (%d, %t), want (%d, true)", pid, monitorFrozen, process.command.Process.Pid)
			}
			if retryCalls == 0 {
				return nil, unix.EIO
			}
			return []int{202}, nil
		}
		process.cleanupRetry = func() {
			if process.release == nil || monitorKilled {
				t.Fatal("cleanup failure released the gate or killed the monitor before retry")
			}
			retryCalls++
		}
		process.pidfdOpen = func(pid, flags int) (int, error) {
			if pid != 202 || flags != 0 {
				t.Fatalf("child pidfd open = (%d, %d), want (202, 0)", pid, flags)
			}
			return 99, nil
		}
		process.pidfdClose = func(int) error { return nil }
		process.pidfdSignal = func(descriptor int, signal unix.Signal) error {
			if descriptor != 99 || signal != unix.SIGKILL {
				t.Fatalf("child signal = (%d, %v), want (99, SIGKILL)", descriptor, signal)
			}
			childKilled = true
			return nil
		}
		process.pidfdWait = func(descriptor int) error {
			if descriptor != 99 || !childKilled {
				t.Fatalf("child exit proof = (%d, %t), want (99, true)", descriptor, childKilled)
			}
			childExited = true
			return nil
		}
		waitCalls := 0
		process.monitorWait = func() error {
			waitCalls++
			if !monitorKilled {
				t.Fatal("monitor reaped before it was signaled")
			}
			if process.release == nil {
				t.Fatal("release descriptor closed before fallback monitor reap")
			}
			return process.command.Wait()
		}
		if err := process.Start(); err == nil {
			t.Fatal("Start succeeded after malformed handshake")
		}
		if waitCalls != 1 {
			t.Fatalf("monitor wait calls = %d, want 1", waitCalls)
		}
		if retryCalls != 1 {
			t.Fatalf("cleanup retry calls = %d, want 1", retryCalls)
		}
	})

	t.Run("persistent pre-identity cleanup failure is quarantined", func(t *testing.T) {
		process := newBubblewrapHandshakeTestProcess(t, context.Background(), `not-json`, 5*time.Second)
		process.teardownTimeout = 5 * time.Millisecond
		process.monitorPidfdSignal = func(descriptor int, signal unix.Signal) error {
			if descriptor != 88 || signal != unix.SIGSTOP {
				t.Fatalf("monitor signal = (%d, %v), want stable SIGSTOP only", descriptor, signal)
			}
			return nil
		}
		process.monitorPidfdStopped = func(int) error { return nil }
		process.monitorChildren = func(int) ([]int, error) { return nil, unix.EIO }
		process.cleanupRetry = func() {}
		quarantined := false
		process.cleanupQuarantine = func(got *bubblewrapProcess) {
			if got != process {
				t.Fatalf("quarantined process = %p, want %p", got, process)
			}
			if process.release == nil || process.command.ProcessState != nil || process.monitorDescriptor < 0 {
				t.Fatal("quarantine did not retain the closed gate, live monitor, and stable identity")
			}
			quarantined = true
		}
		started := time.Now()
		err := process.Start()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Start error = %v, want bounded cleanup timeout", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("persistent cleanup failure blocked Start for %v", elapsed)
		}
		if !quarantined {
			t.Fatal("persistent cleanup failure was not transferred to quarantine ownership")
		}
		if process.release == nil {
			t.Fatal("persistent cleanup failure closed the unproven child's release gate")
		}

		process.monitorChildren = func(int) ([]int, error) { return nil, nil }
		process.monitorPidfdSignal = func(_ int, signal unix.Signal) error {
			if signal == unix.SIGSTOP {
				return nil
			}
			if signal != unix.SIGKILL {
				t.Fatalf("cleanup signal = %v, want SIGKILL", signal)
			}
			return process.command.Process.Kill()
		}
		if err := process.stopStableMonitorTree(); err != nil {
			t.Fatal(err)
		}
		process.reapStableMonitor()
		process.closeStartupDescriptors()
		process.closeIdentityDescriptors()
	})

	t.Run("persistent monitor stop proof failure is quarantined", func(t *testing.T) {
		process := newBubblewrapHandshakeTestProcess(t, context.Background(), `not-json`, 5*time.Second)
		process.teardownTimeout = 5 * time.Millisecond
		process.monitorPidfdSignal = func(descriptor int, signal unix.Signal) error {
			if descriptor != 88 || signal != unix.SIGSTOP {
				t.Fatalf("monitor signal = (%d, %v), want stable SIGSTOP only", descriptor, signal)
			}
			return nil
		}
		process.monitorWaitid = func(_ int, _ int, _ *unix.Siginfo, _ int, _ *unix.Rusage) error {
			return nil
		}
		quarantined := false
		process.cleanupQuarantine = func(got *bubblewrapProcess) {
			if got != process || process.release == nil || process.command.ProcessState != nil {
				t.Fatal("stop-proof timeout did not transfer the closed gate and live monitor to quarantine")
			}
			quarantined = true
		}
		started := time.Now()
		err := process.Start()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Start error = %v, want bounded monitor stop-proof timeout", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("persistent monitor stop-proof failure blocked Start for %v", elapsed)
		}
		if !quarantined || process.release == nil {
			t.Fatal("stop-proof timeout released the unproven child's gate")
		}

		process.monitorPidfdStopped = func(int) error { return nil }
		process.monitorChildren = func(int) ([]int, error) { return nil, nil }
		process.monitorPidfdSignal = func(_ int, signal unix.Signal) error {
			if signal == unix.SIGSTOP {
				return nil
			}
			return process.command.Process.Kill()
		}
		if err := process.stopStableMonitorTree(); err != nil {
			t.Fatal(err)
		}
		process.reapStableMonitor()
		process.closeStartupDescriptors()
		process.closeIdentityDescriptors()
	})

	t.Run("target kill failure", func(t *testing.T) {
		process := newBubblewrapHandshakeTestProcess(t, context.Background(), `{ "child-pid": 101 }`, 5*time.Second)
		process.pidfdOpen = func(int, int) (int, error) { return 77, nil }
		process.pidfdClose = func(int) error { return nil }
		process.pidfdAlive = func(int) error { return nil }
		process.configureUserNS = func(int) error { return errors.New("mapping rejected") }
		process.pidfdSignal = func(int, unix.Signal) error { return unix.EPERM }
		monitorSignaled := false
		process.pidfdWait = func(descriptor int) error {
			if descriptor != 77 || !monitorSignaled || process.command.ProcessState == nil || process.release == nil {
				t.Fatal("target death was not proved after monitor reap with the release gate held")
			}
			return nil
		}
		process.monitorPidfdSignal = func(int, unix.Signal) error {
			if process.release == nil {
				t.Fatal("release descriptor closed after target kill failed but before stable monitor kill")
			}
			monitorSignaled = true
			return process.command.Process.Kill()
		}
		waitCalls := 0
		process.monitorWait = func() error {
			waitCalls++
			if !monitorSignaled {
				t.Fatal("monitor reaped before it was signaled")
			}
			if process.release == nil {
				t.Fatal("release descriptor closed after target kill failure but before monitor reap")
			}
			return process.command.Wait()
		}
		if err := process.Start(); err == nil {
			t.Fatal("Start succeeded after mapping failure")
		}
		if waitCalls != 1 {
			t.Fatalf("monitor wait calls = %d, want 1", waitCalls)
		}
	})

	t.Run("persistent monitor kill failure is quarantined", func(t *testing.T) {
		process := newBubblewrapHandshakeTestProcess(t, context.Background(), `{ "child-pid": 101 }`, 5*time.Second)
		process.pidfdOpen = func(int, int) (int, error) { return 77, nil }
		process.pidfdClose = func(int) error { return nil }
		process.pidfdWait = func(int) error { return nil }
		process.pidfdAlive = func(int) error { return nil }
		process.configureUserNS = func(int) error { return errors.New("mapping rejected") }
		process.pidfdSignal = func(int, unix.Signal) error { return unix.EPERM }
		process.monitorPidfdSignal = func(int, unix.Signal) error { return unix.EPERM }
		process.monitorKill = func() error { return unix.EPERM }
		quarantined := false
		process.cleanupQuarantine = func(got *bubblewrapProcess) {
			if got != process || process.release == nil || process.command.ProcessState != nil {
				t.Fatal("monitor-kill failure did not transfer the closed gate and live process tree to quarantine")
			}
			quarantined = true
		}
		started := time.Now()
		err := process.Start()
		if !errors.Is(err, unix.EPERM) {
			t.Fatalf("Start error = %v, want monitor kill failure", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("persistent monitor kill failure blocked Start for %v", elapsed)
		}
		if !quarantined || process.release == nil {
			t.Fatal("persistent monitor kill failure released the unproven target gate")
		}

		process.monitorPidfdSignal = func(int, unix.Signal) error { return process.command.Process.Kill() }
		process.monitorKill = nil
		if err := process.stopStableMonitorAndWait(); err != nil {
			t.Fatal(err)
		}
		process.reapStableMonitor()
		process.closeStartupDescriptors()
		process.closeIdentityDescriptors()
	})
}

func TestBubblewrapTrustFailuresStopBeforeTheCapabilityProbe(t *testing.T) {
	tests := []struct {
		name       string
		metadataOK bool
		outputs    []bubblewrapCommandResult
	}{
		{name: "replaced executable", metadataOK: false},
		{name: "mismatched package", metadataOK: true, outputs: []bubblewrapCommandResult{{output: []byte("other: /usr/bin/bwrap\n")}}},
		{name: "mismatched architecture", metadataOK: true, outputs: []bubblewrapCommandResult{
			{output: []byte("bubblewrap: /usr/bin/bwrap\n")},
			{output: []byte("ii \nbubblewrap\nbubblewrap\narm64\n")},
		}},
		{name: "failed packaged integrity", metadataOK: true, outputs: []bubblewrapCommandResult{
			{output: []byte("bubblewrap: /usr/bin/bwrap\n")},
			{output: []byte("ii \nbubblewrap\nbubblewrap\namd64\n")},
			{output: []byte("??5??????   /usr/bin/bwrap\n")},
		}},
		{name: "integrity warning", metadataOK: true, outputs: []bubblewrapCommandResult{
			{output: []byte("bubblewrap: /usr/bin/bwrap\n")},
			{output: []byte("ii \nbubblewrap\nbubblewrap\namd64\n")},
			{stderr: []byte("untrusted integrity warning containing a host path")},
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			targetMarker := filepath.Join(t.TempDir(), "target-marker")
			resultIndex := 0
			checker := bubblewrapTrustChecker{
				architecture: "amd64",
				validExecutable: func(path string) bool {
					return test.metadataOK
				},
				run: func(_ context.Context, path string, _ ...string) bubblewrapCommandResult {
					if path == bubblewrapExecutable {
						if err := os.WriteFile(targetMarker, []byte("started"), 0o600); err != nil {
							t.Fatal(err)
						}
						return bubblewrapCommandResult{}
					}
					if resultIndex >= len(test.outputs) {
						return bubblewrapCommandResult{}
					}
					result := test.outputs[resultIndex]
					resultIndex++
					return result
				},
			}
			if err := checker.check(context.Background()); err == nil || err.Error() != bubblewrapUnavailable().Error() {
				t.Fatalf("trust check error = %v, want exact sanitized backend_unavailable", err)
			}
			if _, err := os.Stat(targetMarker); !os.IsNotExist(err) {
				t.Fatalf("target marker exists after trust validation failed: %v", err)
			}
		})
	}
}

func TestBubblewrapCapabilityProbeFailureProvidesAppArmorRemediationWithoutBackendOutput(t *testing.T) {
	privateOutput := filepath.Join(t.TempDir(), "PRIVATE_CAPABILITY_OUTPUT")
	resultIndex := 0
	checker := bubblewrapTrustChecker{
		architecture:    "amd64",
		validExecutable: func(string) bool { return true },
		run: func(_ context.Context, path string, _ ...string) bubblewrapCommandResult {
			if path == bubblewrapExecutable {
				return bubblewrapCommandResult{stderr: []byte("AppArmor denied " + privateOutput), err: errors.New("probe failed")}
			}
			results := []bubblewrapCommandResult{
				{output: []byte("bubblewrap: /usr/bin/bwrap\n")},
				{output: []byte("ii \nbubblewrap\nbubblewrap\namd64\n")},
				{},
			}
			result := results[resultIndex]
			resultIndex++
			return result
		},
	}

	err := checker.check(context.Background())
	assertSandboxCategory(t, err, SandboxBackendUnavailable)
	if got, want := err.Error(), "backend_unavailable: process sandbox unavailable: required system backend is unavailable; review and enable the targeted AppArmor 'bwrap-userns-restrict' profile for /usr/bin/bwrap"; got != want {
		t.Fatalf("capability probe error = %q, want %q", got, want)
	}
	for _, private := range []string{privateOutput, "AppArmor denied", "probe failed"} {
		if strings.Contains(err.Error(), private) {
			t.Fatalf("capability remediation leaked %q: %v", private, err)
		}
	}
}

func TestBubblewrapTrustPassesOnlyAfterPackagedIntegrityVerification(t *testing.T) {
	var commands [][]string
	checker := bubblewrapTrustChecker{
		architecture:    "amd64",
		validExecutable: func(string) bool { return true },
		run: func(_ context.Context, path string, arguments ...string) bubblewrapCommandResult {
			commands = append(commands, append([]string{path}, arguments...))
			switch len(commands) {
			case 1:
				return bubblewrapCommandResult{output: []byte("bubblewrap: /usr/bin/bwrap\n")}
			case 2:
				return bubblewrapCommandResult{output: []byte("ii \nbubblewrap\nbubblewrap\namd64\n")}
			default:
				return bubblewrapCommandResult{}
			}
		},
	}
	if err := checker.check(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{dpkgQueryExecutable, "--search", bubblewrapExecutable},
		{dpkgQueryExecutable, "--show", "--showformat=${db:Status-Abbrev}\n${binary:Package}\n${source:Package}\n${Architecture}\n", "bubblewrap"},
		{dpkgExecutable, "--verify", "--verify-format=rpm", "bubblewrap"},
		append([]string{bubblewrapExecutable}, bubblewrapCapabilityProbeArguments()...),
	}
	if !reflect.DeepEqual(commands, want) {
		t.Fatalf("commands = %q, want %q", commands, want)
	}
}

func TestBubblewrapNativeContextCancellationStopsTheTarget(t *testing.T) {
	platform, err := CurrentPlatform()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlatform(platform); err != nil {
		t.Fatalf("native Bubblewrap test requires certified Ubuntu 24.04: %v", err)
	}
	request := validProcessRequest(t)
	request.Executable = os.Args[0]
	ready := filepath.Join(request.SessionDirectory, "cancel-ready")
	survived := filepath.Join(request.SessionDirectory, "descendant-survived")
	request.Arguments = []string{"-test.run=^TestBubblewrapNativeCancellationHelper$", "--", ready, survived}
	ctx, cancel := context.WithCancel(context.Background())
	process, err := NewProcessSandbox().Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("sandbox cancellation helper did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	childDescriptor := openOnlyBubblewrapChildPidfd(t, process)
	defer unix.Close(childDescriptor)
	cancel()
	wait := make(chan error, 1)
	go func() { wait <- process.Wait() }()
	select {
	case err := <-wait:
		if err == nil {
			t.Fatal("cancelled sandbox process exited successfully")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("context cancellation did not stop the sandbox process tree")
	}
	assertPidfdExited(t, childDescriptor)
	if _, err := os.Stat(survived); !os.IsNotExist(err) {
		t.Fatalf("sandbox descendant survived cancellation: %v", err)
	}
}

func TestBubblewrapNativeWaitProvesNormalProcessTreeDeath(t *testing.T) {
	platform, err := CurrentPlatform()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlatform(platform); err != nil {
		t.Fatalf("native Bubblewrap test requires certified Ubuntu 24.04: %v", err)
	}
	request := validProcessRequest(t)
	request.Executable = os.Args[0]
	ready := filepath.Join(request.SessionDirectory, "normal-wait-ready")
	release := filepath.Join(request.SessionDirectory, "normal-wait-release")
	request.Arguments = []string{"-test.run=^TestBubblewrapNativeNormalWaitTreeHelper$", "--", ready, release}
	process, err := NewProcessSandbox().Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	waitForBubblewrapMarker(t, ready)
	childDescriptor := openOnlyBubblewrapChildPidfd(t, process)
	defer unix.Close(childDescriptor)
	if err := os.WriteFile(release, []byte("release"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	assertPidfdExited(t, childDescriptor)
}

func TestBubblewrapNativePreservesTargetExitStatus(t *testing.T) {
	platform, err := CurrentPlatform()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlatform(platform); err != nil {
		t.Fatalf("native Bubblewrap test requires certified Ubuntu 24.04: %v", err)
	}
	request := validProcessRequest(t)
	request.Executable = os.Args[0]
	request.Arguments = []string{"-test.run=^TestBubblewrapNativeExitHelper$"}
	process, err := NewProcessSandbox().Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	err = process.Wait()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 23 {
		t.Fatalf("sandbox exit error = %v, want target exit 23", err)
	}
}

func TestBubblewrapNativeMultiExecShebangDoesNotBlockStartup(t *testing.T) {
	platform, err := CurrentPlatform()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlatform(platform); err != nil {
		t.Fatalf("native Bubblewrap test requires certified Ubuntu 24.04: %v", err)
	}
	request := validProcessRequest(t)
	if err := os.WriteFile(request.Executable, []byte("#!/usr/bin/env sh\nexit 23\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	process, err := NewProcessSandbox().Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	err = process.Wait()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 23 {
		t.Fatalf("multi-exec shebang error = %v, want target exit 23", err)
	}
}

func TestBubblewrapNativeImmediateSignalAfterStartIsDelivered(t *testing.T) {
	platform, err := CurrentPlatform()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlatform(platform); err != nil {
		t.Fatalf("native Bubblewrap test requires certified Ubuntu 24.04: %v", err)
	}
	request := validProcessRequest(t)
	if err := os.WriteFile(request.Executable, []byte("#!/bin/sh\nwhile :; do :; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	request.Terminal = Terminal{Output: &output, ErrorOutput: &output}
	process, err := NewProcessSandbox().Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Signal(syscall.SIGKILL) })
	if err := process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- process.Wait() }()
	select {
	case err = <-wait:
	case <-time.After(5 * time.Second):
		t.Fatal("immediate signal was not delivered to the target")
	}
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) {
		t.Fatalf("sandbox exit error = %v, want signal termination; output=%q", err, output.String())
	}
	status, ok := exitError.Sys().(syscall.WaitStatus)
	requestedSignal := ok && status.Signaled() && status.Signal() == syscall.SIGTERM
	if !requestedSignal {
		t.Fatalf("sandbox wait status = %v, want requested SIGTERM", exitError.Sys())
	}
}

func TestBubblewrapNativeReadyTargetHandlesSignalAndExits42(t *testing.T) {
	platform, err := CurrentPlatform()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlatform(platform); err != nil {
		t.Fatalf("native Bubblewrap test requires certified Ubuntu 24.04: %v", err)
	}
	request := validProcessRequest(t)
	ready := filepath.Join(request.SessionDirectory, "signal-ready")
	if err := os.WriteFile(request.Executable, []byte("#!/bin/sh\ntrap 'exit 42' TERM\n: > \"$1\"\nwhile :; do :; done\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	request.Arguments = []string{ready}
	process, err := NewProcessSandbox().Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Signal(syscall.SIGKILL) })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("target signal handler did not become ready")
		}
		time.Sleep(time.Millisecond)
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err = process.Wait()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 42 {
		t.Fatalf("sandbox exit error = %v, want target handler exit 42", err)
	}
}

func TestBubblewrapNativePreservesTargetArgumentsWithoutPWD(t *testing.T) {
	platform, err := CurrentPlatform()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlatform(platform); err != nil {
		t.Fatalf("native Bubblewrap test requires certified Ubuntu 24.04: %v", err)
	}
	request := validProcessRequest(t)
	request.Executable = os.Args[0]
	request.Arguments = append([]string{"-test.run=^TestBubblewrapNativeTargetArgumentsHelper$", "--"}, bubblewrapNativeTargetArguments...)
	process, err := NewProcessSandbox().Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestBubblewrapNativePreservesRawTerminalDescriptors(t *testing.T) {
	platform, err := CurrentPlatform()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlatform(platform); err != nil {
		t.Fatalf("native Bubblewrap test requires certified Ubuntu 24.04: %v", err)
	}
	request := validProcessRequest(t)
	request.Executable = os.Args[0]
	request.Arguments = []string{"-test.run=^TestBubblewrapNativeRawTerminalHelper$"}
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	settings, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	settings.Lflag &^= unix.ICANON | unix.ECHO
	if err := unix.IoctlSetTermios(int(terminal.Fd()), unix.TCSETS, settings); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	request.Terminal = Terminal{Input: terminal, Output: &output, ErrorOutput: &output}
	process, err := NewProcessSandbox().Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatalf("raw-terminal target failed: %v; output=%q", err, output.String())
	}
	if got := strings.TrimSpace(output.String()); got != "raw" {
		t.Fatalf("raw terminal output = %q, want raw", got)
	}
}

const bubblewrapNativePTYHarnessEnvironment = "ACS_BUBBLEWRAP_NATIVE_PTY_HARNESS"

const bubblewrapNativePTYExitHarnessEnvironment = "ACS_BUBBLEWRAP_NATIVE_PTY_EXIT_HARNESS"

func TestBubblewrapNativeRoutesTerminalSignalsOnlyToContainedTarget(t *testing.T) {
	platform, err := CurrentPlatform()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlatform(platform); err != nil {
		t.Fatalf("native Bubblewrap test requires certified Ubuntu 24.04: %v", err)
	}
	for _, test := range []struct {
		name   string
		signal syscall.Signal
	}{
		{name: "terminal interrupt", signal: syscall.SIGINT},
		{name: "terminal resize", signal: syscall.SIGWINCH},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			master, terminal, err := pty.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer master.Close()
			defer terminal.Close()
			command := exec.Command(os.Args[0], "-test.run=^TestBubblewrapNativePTYHarness$")
			command.Env = append(os.Environ(),
				bubblewrapNativePTYHarnessEnvironment+"=1",
				"ACS_BUBBLEWRAP_NATIVE_PTY_ROOT="+root,
				"ACS_BUBBLEWRAP_NATIVE_PTY_SIGNAL="+strconv.Itoa(int(test.signal)),
			)
			command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
			command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = command.Process.Kill() })
			if err := terminal.Close(); err != nil {
				t.Fatal(err)
			}

			paths := bubblewrapNativePTYPaths(root)
			waitForBubblewrapMarker(t, paths.ready)
			switch test.signal {
			case syscall.SIGINT:
				if _, err := master.Write([]byte{3}); err != nil {
					t.Fatal(err)
				}
			case syscall.SIGWINCH:
				if err := pty.Setsize(master, &pty.Winsize{Rows: 41, Cols: 119}); err != nil {
					t.Fatal(err)
				}
			}
			waitForBubblewrapMarker(t, paths.received)
			if _, err := master.Write([]byte("snapshot\n")); err != nil {
				t.Fatal(err)
			}
			waitForBubblewrapMarker(t, paths.snapshot)
			if _, err := master.Write([]byte("release\n")); err != nil {
				t.Fatal(err)
			}
			waitNativePTYHarness(t, command)
			if count, err := os.ReadFile(paths.observed); err != nil || string(count) != "1\n" {
				t.Fatalf("terminal %s deliveries after release = %q, %v; want exactly one", test.signal, count, err)
			}
			if count, err := os.ReadFile(paths.harnessObserved); err != nil || string(count) != "0\n" {
				t.Fatalf("harness %s deliveries = %q, %v; want none", test.signal, count, err)
			}
		})
	}
}

func TestBubblewrapNativeTerminalSupervisorPreservesTargetExitStatus(t *testing.T) {
	platform, err := CurrentPlatform()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlatform(platform); err != nil {
		t.Fatalf("native Bubblewrap test requires certified Ubuntu 24.04: %v", err)
	}
	for _, test := range []struct {
		name       string
		targetTest string
		exitCode   int
	}{
		{name: "ordinary target exit", targetTest: "TestBubblewrapNativeExitHelper", exitCode: 23},
		{name: "signaled target exit", targetTest: "TestBubblewrapNativeSignalExitHelper", exitCode: 128 + int(syscall.SIGTERM)},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			master, terminal, err := pty.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer master.Close()
			defer terminal.Close()
			command := exec.Command(os.Args[0], "-test.run=^TestBubblewrapNativePTYExitHarness$")
			command.Env = append(os.Environ(),
				bubblewrapNativePTYExitHarnessEnvironment+"=1",
				"ACS_BUBBLEWRAP_NATIVE_PTY_ROOT="+root,
				"ACS_BUBBLEWRAP_NATIVE_PTY_TARGET_TEST="+test.targetTest,
				"ACS_BUBBLEWRAP_NATIVE_PTY_TARGET_EXIT_CODE="+strconv.Itoa(test.exitCode),
			)
			command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
			command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = command.Process.Kill() })
			if err := terminal.Close(); err != nil {
				t.Fatal(err)
			}
			waitNativePTYHarness(t, command)
		})
	}
}

func TestBubblewrapNativePTYHarness(t *testing.T) {
	if os.Getenv(bubblewrapNativePTYHarnessEnvironment) != "1" {
		return
	}
	root := os.Getenv("ACS_BUBBLEWRAP_NATIVE_PTY_ROOT")
	signalNumber, err := strconv.Atoi(os.Getenv("ACS_BUBBLEWRAP_NATIVE_PTY_SIGNAL"))
	if err != nil {
		t.Fatal(err)
	}
	paths := bubblewrapNativePTYPaths(root)
	request, err := bubblewrapNativePTYRequest(root)
	if err != nil {
		t.Fatal(err)
	}
	request.Arguments = []string{
		"-test.run=^TestBubblewrapNativePTYTarget$", "--", strconv.Itoa(signalNumber),
		paths.ready, paths.received, paths.snapshot, paths.observed,
	}
	request.Terminal = Terminal{Input: os.Stdin, Output: os.Stdout, ErrorOutput: os.Stderr}
	harnessSignals := make(chan os.Signal, 8)
	signal.Notify(harnessSignals, syscall.Signal(signalNumber))
	defer signal.Stop(harnessSignals)
	process, err := NewProcessSandbox().Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	waitForBubblewrapMarker(t, paths.ready)
	assertNativePTYHarnessIsNotForeground(t, os.Stdin)
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	assertNativePTYForegroundRestored(t, os.Stdin)
	signal.Stop(harnessSignals)
	harnessDeliveries := drainNativePTYSignals(t, harnessSignals, syscall.Signal(signalNumber))
	if err := os.WriteFile(paths.harnessObserved, []byte(strconv.Itoa(harnessDeliveries)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBubblewrapNativePTYExitHarness(t *testing.T) {
	if os.Getenv(bubblewrapNativePTYExitHarnessEnvironment) != "1" {
		return
	}
	root := os.Getenv("ACS_BUBBLEWRAP_NATIVE_PTY_ROOT")
	targetTest := os.Getenv("ACS_BUBBLEWRAP_NATIVE_PTY_TARGET_TEST")
	exitCode, err := strconv.Atoi(os.Getenv("ACS_BUBBLEWRAP_NATIVE_PTY_TARGET_EXIT_CODE"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := bubblewrapNativePTYRequest(root)
	if err != nil {
		t.Fatal(err)
	}
	request.Arguments = []string{"-test.run=^" + targetTest + "$"}
	request.Terminal = Terminal{Input: os.Stdin, Output: os.Stdout, ErrorOutput: os.Stderr}
	process, err := NewProcessSandbox().Prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	err = process.Wait()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != exitCode {
		t.Fatalf("terminal-supervised target exit = %v, want exit %d", err, exitCode)
	}
	assertNativePTYForegroundRestored(t, os.Stdin)
}

func TestBubblewrapNativePTYTarget(t *testing.T) {
	arguments := nativePTYTargetArguments()
	if arguments == nil {
		return
	}
	signalNumber, err := strconv.Atoi(arguments[0])
	if err != nil {
		t.Fatal(err)
	}
	want := syscall.Signal(signalNumber)
	signals := make(chan os.Signal, 8)
	signal.Notify(signals, want)
	defer signal.Stop(signals)
	commands := make(chan string, 2)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			commands <- scanner.Text()
		}
	}()
	foregroundGroup, err := unix.IoctlGetInt(int(os.Stdin.Fd()), unix.TIOCGPGRP)
	if err != nil {
		t.Fatal(err)
	}
	if foregroundGroup != syscall.Getpgrp() {
		t.Fatalf("terminal foreground group = %d, target group = %d; want the target to own its terminal", foregroundGroup, syscall.Getpgrp())
	}
	if err := os.WriteFile(arguments[1], []byte("ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	deliveries := 0
	observed := false
	for {
		select {
		case received := <-signals:
			if received != want {
				t.Fatalf("received terminal signal %v, want %v", received, want)
			}
			deliveries++
			if err := os.WriteFile(arguments[2], []byte(strconv.Itoa(deliveries)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		case command := <-commands:
			switch command {
			case "snapshot":
				if err := os.WriteFile(arguments[3], []byte("snapshot\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				observed = true
			case "release":
				if !observed {
					t.Fatal("terminal signal delivery was released before observation")
				}
				signal.Stop(signals)
				deliveries += drainNativePTYSignals(t, signals, want)
				if err := os.WriteFile(arguments[4], []byte(strconv.Itoa(deliveries)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return
			default:
				t.Fatalf("unexpected native PTY command %q", command)
			}
		}
	}
}

func drainNativePTYSignals(t *testing.T, signals <-chan os.Signal, want syscall.Signal) int {
	t.Helper()
	deliveries := 0
	for {
		select {
		case received := <-signals:
			if received != want {
				t.Fatalf("received terminal signal %v, want %v", received, want)
			}
			deliveries++
		default:
			return deliveries
		}
	}
}

type nativePTYPaths struct {
	ready, received, snapshot, observed, harnessObserved string
}

func bubblewrapNativePTYPaths(root string) nativePTYPaths {
	base := filepath.Join(root, "sessions", "session-one")
	return nativePTYPaths{
		ready: filepath.Join(base, "terminal-signal-ready"), received: filepath.Join(base, "terminal-signal-received"),
		snapshot: filepath.Join(base, "terminal-signal-snapshot"), observed: filepath.Join(base, "terminal-signal-observed"),
		harnessObserved: filepath.Join(base, "harness-terminal-signal-observed"),
	}
}

func bubblewrapNativePTYRequest(root string) (ProcessRequest, error) {
	workspace := filepath.Join(root, "workspace")
	session := filepath.Join(root, "sessions", "session-one")
	home := filepath.Join(session, "home")
	temporary := filepath.Join(session, "tmp")
	for _, directory := range []string{workspace, home, temporary} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return ProcessRequest{}, err
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return ProcessRequest{}, err
	}
	return ProcessRequest{
		Workspace: workspace, SessionsDirectory: filepath.Dir(session), SessionDirectory: session,
		SessionHome: home, TemporaryDirectory: temporary, Executable: executable,
	}, nil
}

func nativePTYTargetArguments() []string {
	for index, argument := range os.Args {
		if argument == "--" {
			arguments := os.Args[index+1:]
			if len(arguments) == 5 {
				return arguments
			}
			break
		}
	}
	return nil
}

func assertNativePTYHarnessIsNotForeground(t *testing.T, terminal *os.File) {
	t.Helper()
	foregroundGroup, err := unix.IoctlGetInt(int(terminal.Fd()), unix.TIOCGPGRP)
	if err != nil {
		t.Fatal(err)
	}
	if foregroundGroup == syscall.Getpgrp() {
		t.Fatalf("terminal foreground group = %d, harness group = %d; want the harness outside the foreground group", foregroundGroup, syscall.Getpgrp())
	}
}

func assertNativePTYForegroundRestored(t *testing.T, terminal *os.File) {
	t.Helper()
	foregroundGroup, err := unix.IoctlGetInt(int(terminal.Fd()), unix.TIOCGPGRP)
	if err != nil {
		t.Fatal(err)
	}
	if foregroundGroup != syscall.Getpgrp() {
		t.Fatalf("terminal foreground group after native cleanup = %d, want harness group %d", foregroundGroup, syscall.Getpgrp())
	}
}

func waitNativePTYHarness(t *testing.T, command *exec.Cmd) {
	t.Helper()
	wait := make(chan error, 1)
	go func() { wait <- command.Wait() }()
	select {
	case err := <-wait:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		_ = command.Process.Kill()
		<-wait
		t.Fatal("native PTY harness did not exit after target release")
	}
}

func TestBubblewrapNativeDescriptorHelper(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 {
		return
	}
	arguments := os.Args[separator+1:]
	if len(arguments) != 2 {
		t.Fatalf("descriptor helper arguments = %q", arguments)
	}
	descriptor, err := strconv.Atoi(arguments[0])
	if err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join("/proc/self/fd", strconv.Itoa(descriptor))); err == nil && target == arguments[1] {
		t.Fatal("unexpected host file descriptor was inherited")
	}
}

func TestBubblewrapNativeStartupDescriptorHelper(t *testing.T) {
	separator := slices.Index(os.Args, "--")
	if separator < 0 {
		return
	}
	wantAbsent := os.Args[separator+1:]
	if len(wantAbsent) != 2 {
		t.Fatalf("startup descriptor helper arguments = %q", wantAbsent)
	}
	descriptors, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, descriptor := range descriptors {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", descriptor.Name()))
		if err != nil {
			continue
		}
		if slices.Contains(wantAbsent, target) {
			t.Fatalf("Bubblewrap startup descriptor reached target as fd %s", descriptor.Name())
		}
	}
}

func TestBubblewrapNativeTargetArgumentsHelper(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 {
		return
	}
	if got := os.Args[separator+1:]; !reflect.DeepEqual(got, bubblewrapNativeTargetArguments) {
		t.Fatalf("target arguments = %q, want %q", got, bubblewrapNativeTargetArguments)
	}
	if _, exists := os.LookupEnv("PWD"); exists {
		t.Fatal("target environment unexpectedly contains PWD")
	}
}

func TestBubblewrapNativeRawTerminalHelper(t *testing.T) {
	if os.Getenv("HOME") == "" || !strings.Contains(os.Getenv("HOME"), "session-") {
		return
	}
	settings, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TCGETS)
	if err != nil || settings.Lflag&unix.ICANON != 0 || settings.Lflag&unix.ECHO != 0 {
		os.Exit(83)
	}
	fmt.Print("raw")
	os.Exit(0)
}

func TestBubblewrapStartupHandshakeHelper(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 {
		return
	}
	arguments := os.Args[separator+1:]
	if len(arguments) != 1 {
		t.Fatalf("startup handshake helper arguments = %q", arguments)
	}
	information := os.NewFile(bubblewrapInfoDescriptor, "bubblewrap-information")
	release := os.NewFile(bubblewrapReleaseDescriptor, "bubblewrap-release")
	defer information.Close()
	defer release.Close()
	if arguments[0] != "" {
		if _, err := information.WriteString(arguments[0]); err != nil {
			t.Fatal(err)
		}
	}
	var released [1]byte
	_, _ = release.Read(released[:])
}

func TestBubblewrapBlockedTargetMonitorHelper(t *testing.T) {
	separator := slices.Index(os.Args, "--")
	if separator < 0 {
		return
	}
	arguments := os.Args[separator+1:]
	if len(arguments) < 1 || len(arguments) > 2 {
		t.Fatalf("blocked-target monitor arguments = %q", arguments)
	}
	information := os.NewFile(bubblewrapInfoDescriptor, "bubblewrap-information")
	release := os.NewFile(bubblewrapReleaseDescriptor, "bubblewrap-release")
	commandArguments := []string{"-test.run=^TestBubblewrapBlockedTargetExecutableHelper$", "--", arguments[0]}
	if len(arguments) == 2 {
		commandArguments = append(commandArguments, arguments[1])
	}
	command := exec.Command("/proc/self/exe", commandArguments...)
	command.ExtraFiles = []*os.File{information, release}
	if len(arguments) == 1 {
		command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	_ = information.Close()
	_ = release.Close()
	if err := command.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestBubblewrapBlockedTargetExecutableHelper(t *testing.T) {
	separator := slices.Index(os.Args, "--")
	if separator < 0 {
		return
	}
	arguments := os.Args[separator+1:]
	if len(arguments) < 1 || len(arguments) > 2 {
		t.Fatalf("blocked-target executable arguments = %q", arguments)
	}
	information := os.NewFile(bubblewrapInfoDescriptor, "bubblewrap-information")
	release := os.NewFile(bubblewrapReleaseDescriptor, "bubblewrap-release")
	defer information.Close()
	defer release.Close()
	if err := os.WriteFile(arguments[0]+".ready", []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	if len(arguments) == 2 && arguments[1] == "malformed" {
		if _, err := information.WriteString("not-json"); err != nil {
			t.Fatal(err)
		}
	} else if len(arguments) == 1 {
		if err := json.NewEncoder(information).Encode(bubblewrapInformation{ChildPID: os.Getpid()}); err != nil {
			t.Fatal(err)
		}
	}
	var released [1]byte
	_, _ = release.Read(released[:])
	if err := os.WriteFile(arguments[0], []byte("executed"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newBubblewrapHandshakeTestProcess(t *testing.T, ctx context.Context, information string, timeout time.Duration) *bubblewrapProcess {
	t.Helper()
	command := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestBubblewrapStartupHandshakeHelper$", "--", information)
	process := newBubblewrapPipeTestProcess(t, ctx, command, timeout)
	process.monitorPidfdOpen = func(int, int) (int, error) { return 88, nil }
	process.monitorPidfdClose = func(int) error { return nil }
	process.monitorPidfdWait = func(int) error { return nil }
	process.pidfdWait = func(int) error { return nil }
	process.releaseReady = func(int, int) error { return nil }
	return process
}

func newBubblewrapBlockedTargetTestProcess(t *testing.T, ctx context.Context, marker string, timeout time.Duration) *bubblewrapProcess {
	t.Helper()
	command := exec.Command("/proc/self/exe", "-test.run=^TestBubblewrapBlockedTargetMonitorHelper$", "--", marker)
	return newBubblewrapPipeTestProcess(t, ctx, command, timeout)
}

func newBubblewrapPipeTestProcess(t *testing.T, ctx context.Context, command *exec.Cmd, timeout time.Duration) *bubblewrapProcess {
	t.Helper()
	informationReader, informationWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	releaseReader, releaseWriter, err := os.Pipe()
	if err != nil {
		_ = informationReader.Close()
		_ = informationWriter.Close()
		t.Fatal(err)
	}
	command.ExtraFiles = []*os.File{informationWriter, releaseReader}
	return &bubblewrapProcess{
		ctx:               ctx,
		command:           command,
		information:       informationReader,
		release:           releaseWriter,
		childDescriptors:  []*os.File{informationWriter, releaseReader},
		monitorDescriptor: -1,
		targetDescriptor:  -1,
		handshakeTimeout:  timeout,
		cleanupDone:       make(chan struct{}),
		releaseReady:      func(int, int) error { return nil },
	}
}

func newBubblewrapPreIdentityBlockedTargetTestProcess(t *testing.T, ctx context.Context, marker string, timeout time.Duration) *bubblewrapProcess {
	t.Helper()
	process := newBubblewrapBlockedTargetTestProcess(t, ctx, marker, timeout)
	process.command.Args = append(process.command.Args, "malformed")
	return process
}

func newBubblewrapPreIdentityCancellationTestProcess(t *testing.T, ctx context.Context, marker string, timeout time.Duration) *bubblewrapProcess {
	t.Helper()
	process := newBubblewrapBlockedTargetTestProcess(t, ctx, marker, timeout)
	process.command = exec.CommandContext(ctx, process.command.Path, append(process.command.Args[1:], "silent")...)
	process.command.ExtraFiles = process.childDescriptors
	process.command.Cancel = process.cancel
	return process
}

func openDescriptorCount(t *testing.T) int {
	t.Helper()
	descriptors, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(descriptors)
}

func TestBubblewrapNativeHelper(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 {
		return
	}
	arguments := os.Args[separator+1:]
	if len(arguments) != 8 {
		t.Fatalf("helper arguments = %q", arguments)
	}
	workspace, session, temporary := arguments[0], arguments[1], arguments[2]
	runtimeInput, hostSecret, networkAddress, hostSocket := arguments[3], arguments[4], arguments[5], arguments[6]
	hostDescriptor, err := strconv.Atoi(arguments[7])
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		filepath.Join(workspace, "workspace-writable"),
		filepath.Join(session, "session-writable"),
		filepath.Join(temporary, "temporary-writable"),
	} {
		if err := os.WriteFile(path, []byte("ok"), 0o600); err != nil {
			t.Fatalf("write allowed path %s: %v", path, err)
		}
	}
	contents, err := os.ReadFile(runtimeInput)
	if err != nil {
		t.Fatalf("read runtime input: %v", err)
	}
	fmt.Print(string(contents))
	if err := os.WriteFile(runtimeInput, []byte("changed"), 0o600); err == nil {
		t.Fatal("runtime input was writable")
	}
	for _, path := range []string{hostSecret, filepath.Join(workspace, "secret-link")} {
		if _, err := os.ReadFile(path); err == nil {
			t.Fatalf("host secret was readable through %s", path)
		}
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(workspace), "outside-write"), []byte("escape"), 0o600); err == nil {
		t.Fatal("outside write succeeded")
	}
	if err := os.WriteFile("/run/acs-unexpected-write", []byte("escape"), 0o600); err == nil {
		t.Fatal("startup handshake made /run writable")
	}
	connection, err := net.DialTimeout("tcp4", networkAddress, 3*time.Second)
	if err != nil {
		t.Fatalf("outbound IP connection failed: %v", err)
	}
	_ = connection.Close()
	if connection, err := net.DialTimeout("unix", hostSocket, time.Second); err == nil {
		_ = connection.Close()
		t.Fatal("host Unix socket was exposed")
	}
	if target, err := os.Readlink(filepath.Join("/proc/self/fd", strconv.Itoa(hostDescriptor))); err == nil && target == hostSecret {
		t.Fatal("unexpected host file descriptor was inherited")
	}

	wantEnvironment := map[string]string{
		"HOME":            filepath.Join(session, "home"),
		"PATH":            safeProcessPath,
		"TMPDIR":          temporary,
		"XDG_CACHE_HOME":  filepath.Join(session, "home", ".cache"),
		"XDG_CONFIG_HOME": filepath.Join(session, "home", ".config"),
		"XDG_DATA_HOME":   filepath.Join(session, "home", ".local", "share"),
		"XDG_STATE_HOME":  filepath.Join(session, "home", ".local", "state"),
	}
	optional := map[string]bool{"TERM": true, "COLORTERM": true, "LANG": true, "LC_ALL": true, "LC_CTYPE": true}
	gotEnvironment := os.Environ()
	sort.Strings(gotEnvironment)
	for _, entry := range gotEnvironment {
		key, value, found := strings.Cut(entry, "=")
		if !found {
			t.Fatalf("malformed environment entry %q", entry)
		}
		if want, required := wantEnvironment[key]; required {
			if value != want {
				t.Fatalf("environment %s = %q, want %q", key, value, want)
			}
			delete(wantEnvironment, key)
			continue
		}
		if !optional[key] || !safeEnvironmentValue(value) {
			t.Fatalf("unexpected environment entry %q", entry)
		}
	}
	if len(wantEnvironment) != 0 {
		t.Fatalf("environment omitted required entries: %v", wantEnvironment)
	}

	child := exec.Command(os.Args[0], "-test.run=^TestBubblewrapNativeDescendantHelper$", "--", hostSecret, session)
	child.Env = os.Environ()
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("contained descendant failed: %v; output=%q", err, output)
	}
	os.Exit(0)
}

func TestBubblewrapNativeDescendantHelper(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 {
		return
	}
	hostSecret, session := os.Args[separator+1], os.Args[separator+2]
	if _, err := os.ReadFile(hostSecret); err == nil {
		t.Fatal("descendant read host secret")
	}
	if err := os.WriteFile(filepath.Join(session, "descendant-contained"), []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBubblewrapNativeExitHelper(t *testing.T) {
	if os.Getenv("HOME") == "" || !strings.Contains(os.Getenv("HOME"), "session-") {
		return
	}
	os.Exit(23)
}

func TestBubblewrapNativeSignalExitHelper(t *testing.T) {
	if os.Getenv("HOME") == "" || !strings.Contains(os.Getenv("HOME"), "session-") {
		return
	}
	if err := syscall.Kill(os.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	t.Fatal("target survived SIGTERM")
}

func TestBubblewrapNativeCancellationHelper(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 {
		return
	}
	ready, survived := os.Args[separator+1], os.Args[separator+2]
	child := exec.Command(os.Args[0], "-test.run=^TestBubblewrapNativeCancellationDescendantHelper$", "--", survived)
	child.Env = os.Environ()
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func TestBubblewrapNativeCancellationDescendantHelper(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 {
		return
	}
	time.Sleep(500 * time.Millisecond)
	if err := os.WriteFile(os.Args[separator+1], []byte("survived"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestBubblewrapNativeNormalWaitTreeHelper(t *testing.T) {
	separator := slices.Index(os.Args, "--")
	if separator < 0 {
		return
	}
	ready, release := os.Args[separator+1], os.Args[separator+2]
	child := exec.Command(os.Args[0], "-test.run=^TestBubblewrapNativeLongLivedDescendantHelper$")
	child.Env = os.Environ()
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ready, []byte("ready"), 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(release); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestBubblewrapNativeLongLivedDescendantHelper(t *testing.T) {
	if os.Getenv("HOME") == "" || !strings.Contains(os.Getenv("HOME"), "session-") {
		return
	}
	time.Sleep(time.Hour)
}

func waitForBubblewrapMarker(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for Bubblewrap marker %q", filepath.Base(path))
		}
		time.Sleep(time.Millisecond)
	}
}

func openOnlyBubblewrapChildPidfd(t *testing.T, prepared Process) int {
	t.Helper()
	sanitized, ok := prepared.(sanitizedProcess)
	if !ok {
		t.Fatalf("prepared process = %T, want sanitizedProcess", prepared)
	}
	process, ok := sanitized.process.(*bubblewrapProcess)
	if !ok {
		t.Fatalf("sanitized process = %T, want *bubblewrapProcess", sanitized.process)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		children, err := bubblewrapMonitorChildren(process.targetPID)
		if err == nil && len(children) == 1 {
			descriptor, err := unix.PidfdOpen(children[0], 0)
			if err == nil {
				return descriptor
			}
		}
		if err != nil && !errors.Is(err, unix.ENOENT) && !errors.Is(err, unix.ESRCH) {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("stable Bubblewrap target children = %v, err = %v; want one descendant", children, err)
		}
		time.Sleep(time.Millisecond)
	}
}

func assertPidfdExited(t *testing.T, descriptor int) {
	t.Helper()
	poll := []unix.PollFd{{Fd: int32(descriptor), Events: unix.POLLIN}}
	ready, err := unix.Poll(poll, 0)
	if err != nil || ready != 1 || poll[0].Revents&unix.POLLIN == 0 {
		t.Fatalf("stable descendant identity remained alive after Wait: ready=%d revents=%#x err=%v", ready, poll[0].Revents, err)
	}
}
