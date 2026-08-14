//go:build linux

package launch

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	handled, err := RunBubblewrapHelper(os.Args[1:])
	if handled {
		if err != nil {
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
	want := append([]string{"/proc/self/exe", bubblewrapHelperFlag}, arguments...)
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

func TestBubblewrapPreparedProcessKeepsParentDeathSignal(t *testing.T) {
	process, err := (bubblewrapBackend{}).prepare(context.Background(), validatedProcessRequest{
		workspace: "/workspace", sessionDirectory: "/session", executable: "/target", environment: []string{"PATH=" + safeProcessPath},
	})
	if err != nil {
		t.Fatal(err)
	}
	bubblewrap, ok := process.(*bubblewrapProcess)
	if !ok {
		t.Fatalf("prepared process = %T, want *bubblewrapProcess", process)
	}
	if bubblewrap.command.SysProcAttr == nil || bubblewrap.command.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("parent death signal = %v, want %v", bubblewrap.command.SysProcAttr, syscall.SIGKILL)
	}
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
	time.Sleep(750 * time.Millisecond)
	if _, err := os.Stat(survived); !os.IsNotExist(err) {
		t.Fatalf("sandbox descendant survived cancellation: %v", err)
	}
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
