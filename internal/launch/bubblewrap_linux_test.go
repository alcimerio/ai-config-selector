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
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

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
