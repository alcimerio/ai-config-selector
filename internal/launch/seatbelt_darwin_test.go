//go:build darwin

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
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

func TestSeatbeltPolicyIsDefaultDenyAndUsesParametersForValidatedPaths(t *testing.T) {
	request := validatedProcessRequest{
		workspace:        `/private/tmp/workspace-\"quoted`,
		sessionDirectory: "/private/tmp/session\nprivate",
		executable:       "/private/tmp/bin/devin",
		runtimeInputs:    []string{"/private/tmp/runtime/input.pem"},
	}
	policy, definitions, err := buildSeatbeltPolicy(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"(version 1)", "(deny default)", `(param "WORKSPACE")`,
		`(param "SESSION")`, `(param "EXECUTABLE")`, `(param "RUNTIME_0")`,
		`(remote ip)`, `(literal "/private/var/run/mDNSResponder")`,
		`(literal "/private/var/select/sh")`,
		`(literal "/dev/tty")`, `(target same-sandbox)`,
	} {
		if !strings.Contains(policy, want) {
			t.Errorf("policy omits %q", want)
		}
	}
	for _, forbidden := range []string{
		request.workspace, request.sessionDirectory, request.executable,
		request.runtimeInputs[0], "(allow file-read*)\n", "(allow mach-lookup)",
		"(allow sysctl-read)\n", "(allow iokit", "(allow network*)",
	} {
		if strings.Contains(policy, forbidden) {
			t.Errorf("policy contains forbidden text %q", forbidden)
		}
	}
	wantDefinitions := []string{
		"-DWORKSPACE=" + request.workspace,
		"-DSESSION=" + request.sessionDirectory,
		"-DEXECUTABLE=" + request.executable,
		"-DRUNTIME_0=" + request.runtimeInputs[0],
	}
	if strings.Join(definitions, "\n") != strings.Join(wantDefinitions, "\n") {
		t.Fatalf("definitions = %#v, want %#v", definitions, wantDefinitions)
	}
}

func TestSeatbeltCheckRejectsUnsafeSystemExecutable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox-exec")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	backend := newSeatbeltBackend(path)
	err := backend.check(context.Background())
	if err == nil {
		t.Fatal("unsafe backend accepted")
	}
	assertSandboxCategory(t, err, SandboxBackendUnavailable)
	if strings.Contains(err.Error(), path) {
		t.Fatalf("backend error leaked path: %v", err)
	}
}

func TestSeatbeltInvalidPolicyStopsBeforeTargetMarker(t *testing.T) {
	request := seatbeltTestRequest(t)
	marker := filepath.Join(request.workspace, "target-started")
	request.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", "mark", marker}
	backend := newSeatbeltBackend(seatbeltExecutable)
	backend.policy = func(validatedProcessRequest) (string, []string, error) {
		return `(version 1) (invalid-operation default)`, nil, nil
	}
	process, err := backend.prepare(context.Background(), request)
	if err != nil {
		t.Fatalf("prepare invalid policy: %v", err)
	}
	if err := process.Start(); err != nil {
		t.Fatalf("start sandbox verifier: %v", err)
	}
	if err := process.Wait(); err == nil {
		t.Fatal("invalid policy unexpectedly succeeded")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("target marker exists after invalid policy: %v", err)
	}
}

func TestSeatbeltContainsFilesystemNetworkEnvironmentAndDescendants(t *testing.T) {
	request := seatbeltTestRequest(t)
	root := filepath.Dir(filepath.Dir(request.workspace))
	hostHome := filepath.Join(root, "home")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(hostHome, "secret")
	if err := os.WriteFile(secret, []byte("private"), 0o600); err != nil {
		t.Fatal(err)
	}
	readable := filepath.Join(request.workspace, "readable")
	if err := os.WriteFile(readable, []byte("workspace"), 0o600); err != nil {
		t.Fatal(err)
	}
	sessionReadable := filepath.Join(request.sessionDirectory, "readable")
	if err := os.WriteFile(sessionReadable, []byte("session"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeInput := filepath.Join(root, "runtime.pem")
	if err := os.WriteFile(runtimeInput, []byte("runtime"), 0o600); err != nil {
		t.Fatal(err)
	}
	request.runtimeInputs = []string{runtimeInput}
	readEscape := filepath.Join(request.workspace, "read-escape")
	writeEscape := filepath.Join(request.workspace, "write-escape")
	if err := os.Symlink(secret, readEscape); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, writeEscape); err != nil {
		t.Fatal(err)
	}

	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	go acceptSeatbeltTestConnection(tcp)
	unixPath := filepath.Join(hostHome, "agent.sock")
	unixListener, err := net.Listen("unix", unixPath)
	if err != nil {
		t.Fatal(err)
	}
	defer unixListener.Close()
	go acceptSeatbeltTestConnection(unixListener)

	request.arguments = []string{
		"-test.run=TestSeatbeltHelperProcess", "--", "containment",
		request.workspace, request.sessionDirectory, secret, outside,
		readable, sessionReadable, runtimeInput, readEscape, writeEscape,
		tcp.Addr().String(), unixPath,
		"/private/var/run/mDNSResponder",
	}
	var output bytes.Buffer
	request.terminal = Terminal{Output: &output, ErrorOutput: &output}
	backend := newSeatbeltBackend(seatbeltExecutable)
	process, err := backend.prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatalf("contained helper failed: %v; output=%q", err, output.String())
	}
	if got := strings.TrimSpace(output.String()); got != "contained" {
		t.Fatalf("contained helper output = %q", got)
	}
}

func TestSeatbeltPreservesRawTerminalDescriptors(t *testing.T) {
	request := seatbeltTestRequest(t)
	request.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", "raw-terminal"}
	master, terminal, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer master.Close()
	defer terminal.Close()
	settings, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TIOCGETA)
	if err != nil {
		t.Fatal(err)
	}
	settings.Lflag &^= unix.ICANON | unix.ECHO
	if err := unix.IoctlSetTermios(int(terminal.Fd()), unix.TIOCSETA, settings); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	request.terminal = Terminal{Input: terminal, Output: &output, ErrorOutput: &output}
	process, err := newSeatbeltBackend(seatbeltExecutable).prepare(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(output.String()); got != "raw" {
		t.Fatalf("raw terminal output = %q", got)
	}
}

func TestSeatbeltHelperProcess(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || separator+1 >= len(os.Args) {
		return
	}
	arguments := os.Args[separator+1:]
	switch arguments[0] {
	case "mark":
		if err := os.WriteFile(arguments[1], []byte("started"), 0o600); err != nil {
			os.Exit(71)
		}
		os.Exit(0)
	case "containment":
		runSeatbeltContainmentHelper(arguments[1:])
	case "grandchild":
		if _, err := os.ReadFile(arguments[1]); !isSeatbeltPermission(err) {
			os.Exit(72)
		}
		os.Exit(0)
	case "child":
		if _, err := os.ReadFile(arguments[1]); !isSeatbeltPermission(err) {
			os.Exit(84)
		}
		grandchild := exec.Command(os.Args[0], "-test.run=TestSeatbeltHelperProcess", "--", "grandchild", arguments[1])
		grandchild.Env = os.Environ()
		if err := grandchild.Run(); err != nil {
			os.Exit(85)
		}
		os.Exit(0)
	case "raw-terminal":
		settings, err := unix.IoctlGetTermios(int(os.Stdin.Fd()), unix.TIOCGETA)
		if err != nil || settings.Lflag&unix.ICANON != 0 || settings.Lflag&unix.ECHO != 0 {
			os.Exit(83)
		}
		fmt.Fprintln(os.Stdout, "raw")
		os.Exit(0)
	}
}

func runSeatbeltContainmentHelper(arguments []string) {
	if len(arguments) != 12 {
		os.Exit(73)
	}
	workspace, session, secret, outside := arguments[0], arguments[1], arguments[2], arguments[3]
	readEscape, writeEscape := arguments[7], arguments[8]
	for _, readable := range []string{arguments[4], arguments[5], arguments[6]} {
		if _, err := os.ReadFile(readable); err != nil {
			os.Exit(74)
		}
	}
	for _, path := range []string{filepath.Join(workspace, "created"), filepath.Join(session, "created")} {
		if err := os.WriteFile(path, []byte("allowed"), 0o600); err != nil {
			os.Exit(75)
		}
	}
	for _, path := range []string{secret, readEscape} {
		if _, err := os.ReadFile(path); !isSeatbeltPermission(err) {
			os.Exit(76)
		}
	}
	for _, path := range []string{filepath.Join(outside, "created"), filepath.Join(writeEscape, "created")} {
		if err := os.WriteFile(path, []byte("denied"), 0o600); !isSeatbeltPermission(err) {
			os.Exit(77)
		}
	}
	if os.Getenv("AWS_SECRET_ACCESS_KEY") != "" || os.Getenv("SSH_AUTH_SOCK") != "" {
		os.Exit(78)
	}
	tcp, err := net.DialTimeout("tcp4", arguments[9], 2*time.Second)
	if err != nil {
		os.Exit(79)
	}
	_ = tcp.Close()
	unixConnection, err := net.DialTimeout("unix", arguments[10], 300*time.Millisecond)
	if err == nil {
		_ = unixConnection.Close()
		os.Exit(80)
	}
	if !isSeatbeltPermission(err) {
		os.Exit(86)
	}
	resolver, err := net.DialTimeout("unix", arguments[11], 300*time.Millisecond)
	if err != nil {
		os.Exit(82)
	}
	_ = resolver.Close()
	child := exec.Command(os.Args[0], "-test.run=TestSeatbeltHelperProcess", "--", "child", secret)
	child.Env = os.Environ()
	if err := child.Run(); err != nil {
		os.Exit(81)
	}
	fmt.Fprintln(os.Stdout, "contained")
	os.Exit(0)
}

func isSeatbeltPermission(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

func acceptSeatbeltTestConnection(listener net.Listener) {
	connection, err := listener.Accept()
	if err == nil {
		_ = connection.Close()
	}
}

func seatbeltTestRequest(t *testing.T) validatedProcessRequest {
	t.Helper()
	root, err := os.MkdirTemp("/private/tmp", "acs-seatbelt-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	workspace := filepath.Join(root, "home", "workspace")
	session := filepath.Join(root, "sessions", "session-one")
	home := filepath.Join(session, "home")
	temporary := filepath.Join(session, "tmp")
	for _, directory := range []string{workspace, home, temporary} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := buildProcessEnvironment(home, temporary, []string{
		"TERM=xterm-256color", "AWS_SECRET_ACCESS_KEY=private", "SSH_AUTH_SOCK=/private/agent.sock",
	})
	if err != nil {
		t.Fatal(err)
	}
	return validatedProcessRequest{
		workspace: workspace, sessionsDirectory: filepath.Dir(session), sessionDirectory: session,
		sessionHome: home, temporaryDirectory: temporary, executable: executable,
		environment: environment,
	}
}
