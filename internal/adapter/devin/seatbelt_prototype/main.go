// seatbelt_prototype is throwaway code for issue #56. It proves or disproves
// a macOS Seatbelt containment contract without touching real user data.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"
)

const sandboxExecutable = "/usr/bin/sandbox-exec"
const realDevinAcknowledgement = "I_ACKNOWLEDGE_LOCAL_CREDENTIAL_ACCESS"

type probeReport struct {
	Checks []check `json:"checks"`
}

type check struct {
	Name     string `json:"name"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Passed   bool   `json:"passed"`
}

type fixture struct {
	root       string
	workspace  string
	session    string
	hostHome   string
	systemFile string
	tcpAddress string
	unixSocket string
	executable string
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--probe":
			runProbe(parseFixture(os.Args[2:]))
			return
		case "--descendant":
			runDescendant(parseFixture(os.Args[2:]))
			return
		case "--exit-23":
			os.Exit(23)
		case "--wait-signal":
			waitForSignal()
			return
		case "--pty-resize":
			reportPTYResize()
			return
		case "--mark-start":
			if len(os.Args) != 3 {
				os.Exit(2)
			}
			_ = os.WriteFile(os.Args[2], []byte("started"), 0o600)
			return
		case "--real-devin":
			if err := runRealDevinSmoke(true); err != nil {
				fmt.Fprintf(os.Stderr, "seatbelt prototype: %v\n", err)
				os.Exit(1)
			}
			return
		case "--real-devin-preflight":
			if err := runRealDevinSmoke(false); err != nil {
				fmt.Fprintf(os.Stderr, "seatbelt prototype: %v\n", err)
				os.Exit(1)
			}
			return
		}
	}
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "seatbelt prototype: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("requires macOS; current platform is %s", runtime.GOOS)
	}
	if info, err := os.Lstat(sandboxExecutable); err != nil {
		return fmt.Errorf("resolve %s: %w", sandboxExecutable, err)
	} else if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a regular system executable", sandboxExecutable)
	}

	fx, cleanup, err := createFixture()
	if err != nil {
		return err
	}
	defer cleanup()
	if err := os.Setenv("ACS_SYNTHETIC_SECRET", "must-not-cross"); err != nil {
		return fmt.Errorf("set synthetic environment fixture: %w", err)
	}
	defer os.Unsetenv("ACS_SYNTHETIC_SECRET")

	tcpListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("create synthetic TCP endpoint: %w", err)
	}
	defer tcpListener.Close()
	fx.tcpAddress = tcpListener.Addr().String()
	go acceptOnce(tcpListener)

	unixListener, err := net.Listen("unix", fx.unixSocket)
	if err != nil {
		return fmt.Errorf("create synthetic denied Unix socket: %w", err)
	}
	defer unixListener.Close()
	go acceptOnce(unixListener)

	report, stderr, err := executeSandboxed(fx, "--probe")
	if err != nil {
		if stderr != "" {
			return fmt.Errorf("run probe: %w (%s)", err, stderr)
		}
		return fmt.Errorf("run probe: %w", err)
	}

	exitCheck := verifyExitStatus(fx)
	report.Checks = append(
		report.Checks,
		exitCheck,
		verifySignalDelivery(fx),
		verifyPTYResize(fx),
		verifyFailClosed(fx),
	)
	sort.Slice(report.Checks, func(i, j int) bool { return report.Checks[i].Name < report.Checks[j].Name })

	fmt.Println("Seatbelt process containment prototype")
	fmt.Println("Synthetic fixtures only; no real home or credential access.")
	fmt.Println()
	failed := false
	for _, result := range report.Checks {
		status := "PASS"
		if !result.Passed {
			status = "FAIL"
			failed = true
		}
		fmt.Printf("%-4s  %-28s expected=%-10s observed=%s\n", status, result.Name, result.Expected, result.Observed)
	}
	if failed {
		return errors.New("one or more containment checks failed")
	}
	fmt.Println()
	fmt.Println("VERDICT: core filesystem, environment, descendant, socket and network contract is viable")
	return nil
}

func createFixture() (fixture, func(), error) {
	root, err := os.MkdirTemp("/private/tmp", "acs-sb-*")
	if err != nil {
		return fixture{}, nil, fmt.Errorf("create prototype root: %w", err)
	}
	cleanup := func() { _ = os.RemoveAll(root) }
	sourceExecutable, err := os.Executable()
	if err != nil {
		cleanup()
		return fixture{}, nil, fmt.Errorf("resolve prototype executable: %w", err)
	}
	sourceExecutable, err = filepath.EvalSymlinks(sourceExecutable)
	if err != nil {
		cleanup()
		return fixture{}, nil, fmt.Errorf("resolve prototype executable links: %w", err)
	}
	fx := fixture{
		root:       root,
		hostHome:   filepath.Join(root, "synthetic-host-home"),
		systemFile: "/private/etc/hosts",
		unixSocket: filepath.Join(root, "synthetic-host-home", "sensitive.sock"),
	}
	fx.workspace = filepath.Join(fx.hostHome, "workspace")
	fx.session = filepath.Join(fx.hostHome, ".acs", "session")
	fx.executable = filepath.Join(fx.hostHome, ".local", "bin", "seatbelt-prototype")
	for _, directory := range []string{fx.workspace, fx.session, fx.hostHome, filepath.Join(fx.session, "tmp"), filepath.Dir(fx.executable)} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			cleanup()
			return fixture{}, nil, fmt.Errorf("create synthetic fixture: %w", err)
		}
	}
	if err := copyExecutable(sourceExecutable, fx.executable); err != nil {
		cleanup()
		return fixture{}, nil, err
	}
	for path, contents := range map[string]string{
		filepath.Join(fx.workspace, "readable.txt"): "workspace",
		filepath.Join(fx.session, "readable.txt"):   "session",
		filepath.Join(fx.hostHome, "secret.txt"):    "synthetic-secret",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			cleanup()
			return fixture{}, nil, fmt.Errorf("write synthetic fixture: %w", err)
		}
	}
	outsideDirectory := filepath.Join(root, "outside")
	if err := os.MkdirAll(outsideDirectory, 0o700); err != nil {
		cleanup()
		return fixture{}, nil, fmt.Errorf("create synthetic outside fixture: %w", err)
	}
	for link, target := range map[string]string{
		filepath.Join(fx.workspace, "secret-link"):  filepath.Join(fx.hostHome, "secret.txt"),
		filepath.Join(fx.workspace, "outside-link"): outsideDirectory,
	} {
		if err := os.Symlink(target, link); err != nil {
			cleanup()
			return fixture{}, nil, fmt.Errorf("create synthetic symlink fixture: %w", err)
		}
	}
	return fx, cleanup, nil
}

func executeSandboxed(fx fixture, mode string) (probeReport, string, error) {
	command := sandboxCommand(fx, seatbeltPolicy(), mode, fixtureArguments(fx)...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if mode != "--probe" {
		return probeReport{}, sanitized(stderr.String()), err
	}
	if err != nil {
		return probeReport{}, sanitized(stderr.String()), err
	}
	var report probeReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		return probeReport{}, sanitized(stderr.String()), fmt.Errorf("decode probe report: %w", err)
	}
	return report, sanitized(stderr.String()), nil
}

func sandboxCommand(fx fixture, policy, mode string, modeArguments ...string) *exec.Cmd {
	targetArguments := append([]string{mode}, modeArguments...)
	return sandboxTargetCommand(fx, policy, fx.executable, targetArguments...)
}

func sandboxTargetCommand(fx fixture, policy, target string, targetArguments ...string) *exec.Cmd {
	arguments := []string{
		"-p", policy,
		"-DWORKSPACE=" + fx.workspace,
		"-DSESSION=" + fx.session,
		"-DHOST_HOME=" + fx.hostHome,
		"-DEXECUTABLE=" + fx.executable,
		"--", target,
	}
	arguments = append(arguments, targetArguments...)
	command := exec.Command(sandboxExecutable, arguments...)
	command.Dir = fx.workspace
	command.Env = []string{
		"ACS_ALLOWED_MARKER=present",
		"HOME=" + fx.session,
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"TMPDIR=" + filepath.Join(fx.session, "tmp"),
	}
	return command
}

func runRealDevinSmoke(interactive bool) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("real-Devin smoke requires macOS; current platform is %s", runtime.GOOS)
	}
	if os.Getenv("ACS_SEATBELT_PROTOTYPE_REAL_DEVIN") != realDevinAcknowledgement {
		return errors.New("real-Devin smoke requires explicit local credential authorization")
	}
	binary, err := exec.LookPath("devin")
	if err != nil {
		return errors.New("real-Devin smoke requires an installed Devin CLI")
	}
	binary, err = filepath.EvalSymlinks(binary)
	if err != nil {
		return errors.New("real-Devin smoke could not resolve the installed Devin CLI safely")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return errors.New("real-Devin smoke could not resolve the existing home")
	}
	workingDirectory, err := os.Getwd()
	if err != nil {
		return errors.New("real-Devin smoke could not resolve the working directory")
	}
	root, err := os.MkdirTemp("/private/tmp", "acs-sb-devin-*")
	if err != nil {
		return errors.New("real-Devin smoke could not create an ephemeral root")
	}
	defer os.RemoveAll(root)

	adapter, err := devin.New(devin.Config{BinaryPath: binary, ExistingHomeDir: home})
	if err != nil {
		return errors.New("real-Devin smoke could not configure the Adapter")
	}
	session, err := adapter.PrepareSession(root, workingDirectory, nil)
	if err != nil {
		return errors.New("real-Devin smoke could not prepare the allowlisted Session")
	}
	for _, directory := range []string{
		filepath.Join(session.HomeDir, ".cache"),
		filepath.Join(session.HomeDir, ".local", "state"),
		filepath.Join(session.HomeDir, "tmp"),
	} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return errors.New("real-Devin smoke could not complete the ephemeral Session")
		}
	}

	preflightContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := adapter.Preflight(preflightContext, session); err != nil {
		return fmt.Errorf("real-Devin Adapter preflight failed: %w", err)
	}

	fx := fixture{
		workspace:  session.WorkingDirectory,
		session:    session.HomeDir,
		hostHome:   home,
		executable: binary,
	}
	environment := realDevinEnvironment(session.HomeDir)
	auth := sandboxTargetCommand(fx, seatbeltPolicy(), binary, "auth", "status")
	auth.Env = environment
	auth.Stdout = io.Discard
	auth.Stderr = io.Discard
	if err := auth.Run(); err != nil {
		return errors.New("sandboxed Devin authentication preflight failed")
	}
	if !interactive {
		fmt.Println("VERDICT: real Devin preflight passed inside Seatbelt with an ephemeral credential copy")
		return nil
	}

	fmt.Println("Synthetic checks passed and sandboxed authentication succeeded.")
	fmt.Println("Starting Devin inside Seatbelt. Exit Devin normally to complete the smoke.")
	command := sandboxTargetCommand(fx, seatbeltPolicy(), binary)
	command.Env = environment
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return fmt.Errorf("sandboxed Devin exited with status %d", exitError.ExitCode())
		}
		return errors.New("sandboxed Devin could not start")
	}
	fmt.Println("VERDICT: authenticated Devin completed a normal sandboxed lifecycle")
	return nil
}

func realDevinEnvironment(sessionHome string) []string {
	values := map[string]string{
		"HOME":            sessionHome,
		"PATH":            os.Getenv("PATH"),
		"TMPDIR":          filepath.Join(sessionHome, "tmp"),
		"XDG_CACHE_HOME":  filepath.Join(sessionHome, ".cache"),
		"XDG_CONFIG_HOME": filepath.Join(sessionHome, ".config"),
		"XDG_DATA_HOME":   filepath.Join(sessionHome, ".local", "share"),
		"XDG_STATE_HOME":  filepath.Join(sessionHome, ".local", "state"),
	}
	for _, name := range []string{"COLORTERM", "LANG", "LC_ALL", "TERM"} {
		if value := os.Getenv(name); value != "" {
			values[name] = value
		}
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	environment := make([]string, 0, len(keys))
	for _, key := range keys {
		environment = append(environment, key+"="+values[key])
	}
	return environment
}

func seatbeltPolicy() string {
	return `(version 1)
(deny default)

; Broad runtime capabilities keep this spike focused on filesystem, environment,
; sockets, descendants and terminal lifecycle. A production policy must narrow
; these capabilities after the real Devin smoke identifies its requirements.
(allow process-exec)
(allow process-fork)
(allow process-info* (target same-sandbox))
(allow signal (target same-sandbox))
(allow mach-priv-task-port (target same-sandbox))
(allow user-preference-read)
(allow mach-lookup)
(allow ipc-posix*)
(allow iokit-open)
(allow iokit-get-properties)
(allow sysctl-read)
(allow sysctl-write)
(allow system-mac-syscall)
(allow distributed-notification-post)
(allow system-socket)

; Read system runtime files by default, hide the synthetic home, then restore
; only the repository and Session nested beneath it.
(allow file-read*)
(deny file-read* (subpath (param "HOST_HOME")))
(allow file-read-metadata (vnode-type DIRECTORY))
(allow file-read*
	(literal (param "EXECUTABLE"))
  (subpath (param "WORKSPACE"))
  (subpath (param "SESSION")))

; Writes are closed by default and limited to the two explicit roots.
(allow file-write*
  (subpath (param "WORKSPACE"))
  (subpath (param "SESSION")))

; Keep IP networking available while rejecting host Unix sockets.
(allow network*)
(deny network-bind (local unix-socket))
(deny network-outbound (remote unix-socket))

; Preserve an inherited or newly allocated terminal.
(allow pseudo-tty)
(allow file-ioctl file-read-data file-write-data
  (literal "/dev/null")
  (literal "/dev/zero")
  (literal "/dev/random")
  (literal "/dev/urandom"))
(allow file-read* file-write* file-ioctl (literal "/dev/ptmx"))
(allow file-read* file-write* (regex #"^/dev/ttys[0-9]+"))
(allow file-ioctl (regex #"^/dev/ttys[0-9]+"))

; Inherited standard descriptors remain usable.
(allow file-read-data (subpath "/dev/fd"))
(allow file-write-data (subpath "/dev/fd"))`
}

func fixtureArguments(fx fixture) []string {
	return []string{
		fx.workspace,
		fx.session,
		fx.hostHome,
		fx.systemFile,
		fx.tcpAddress,
		fx.unixSocket,
		fx.executable,
	}
}

func parseFixture(arguments []string) fixture {
	if len(arguments) != 7 {
		fmt.Fprintln(os.Stderr, "invalid prototype fixture")
		os.Exit(2)
	}
	return fixture{
		workspace:  arguments[0],
		session:    arguments[1],
		hostHome:   arguments[2],
		systemFile: arguments[3],
		tcpAddress: arguments[4],
		unixSocket: arguments[5],
		executable: arguments[6],
	}
}

func runProbe(fx fixture) {
	report := probeReport{Checks: []check{
		allowedRead("workspace-read", filepath.Join(fx.workspace, "readable.txt")),
		allowedWrite("workspace-write", filepath.Join(fx.workspace, "created.txt")),
		allowedRead("session-read", filepath.Join(fx.session, "readable.txt")),
		allowedWrite("session-write", filepath.Join(fx.session, "created.txt")),
		allowedRead("system-read", fx.systemFile),
		deniedRead("host-home-read", filepath.Join(fx.hostHome, "secret.txt")),
		deniedWrite("host-home-write", filepath.Join(fx.hostHome, "created.txt")),
		deniedWrite("outside-root-write", filepath.Join(filepath.Dir(fx.hostHome), "outside-created.txt")),
		deniedRead("workspace-symlink-read", filepath.Join(fx.workspace, "secret-link")),
		deniedWrite("workspace-symlink-write", filepath.Join(fx.workspace, "outside-link", "created.txt")),
		verifyEnvironment(),
		verifyTCP(fx.tcpAddress),
		verifyDeniedUnixSocket(fx.unixSocket),
		verifyDescendant(fx),
	}}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		os.Exit(2)
	}
}

func runDescendant(fx fixture) {
	checks := []check{
		allowedWrite("descendant-workspace-write", filepath.Join(fx.workspace, "descendant.txt")),
		deniedRead("descendant-host-home-read", filepath.Join(fx.hostHome, "secret.txt")),
	}
	if err := json.NewEncoder(os.Stdout).Encode(probeReport{Checks: checks}); err != nil {
		os.Exit(2)
	}
}

func allowedRead(name, path string) check {
	_, err := os.ReadFile(path)
	return operationCheck(name, "allowed", err == nil, err)
}

func allowedWrite(name, path string) check {
	err := os.WriteFile(path, []byte("prototype"), 0o600)
	return operationCheck(name, "allowed", err == nil, err)
}

func deniedRead(name, path string) check {
	_, err := os.ReadFile(path)
	return operationCheck(name, "denied", isPermissionError(err), err)
}

func deniedWrite(name, path string) check {
	err := os.WriteFile(path, []byte("prototype"), 0o600)
	return operationCheck(name, "denied", isPermissionError(err), err)
}

func operationCheck(name, expected string, passed bool, err error) check {
	observed := "allowed"
	if err != nil {
		observed = "denied"
		if !isPermissionError(err) {
			observed = "other-error"
		}
	}
	return check{Name: name, Expected: expected, Observed: observed, Passed: passed}
}

func isPermissionError(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

func verifyEnvironment() check {
	allowed := os.Getenv("ACS_ALLOWED_MARKER") == "present"
	_, secretPresent := os.LookupEnv("ACS_SYNTHETIC_SECRET")
	return check{
		Name:     "environment-allowlist",
		Expected: "filtered",
		Observed: map[bool]string{true: "filtered", false: "leaked"}[allowed && !secretPresent],
		Passed:   allowed && !secretPresent,
	}
}

func verifyTCP(address string) check {
	connection, err := net.DialTimeout("tcp4", address, 2*time.Second)
	if err == nil {
		_ = connection.Close()
	}
	return operationCheck("tcp-network", "allowed", err == nil, err)
}

func verifyDeniedUnixSocket(path string) check {
	connection, err := net.DialTimeout("unix", path, 500*time.Millisecond)
	if err == nil {
		_ = connection.Close()
	}
	return operationCheck("host-unix-socket", "denied", isPermissionError(err), err)
}

func verifyDescendant(fx fixture) check {
	command := exec.Command(fx.executable, append([]string{"--descendant"}, fixtureArguments(fx)...)...)
	command.Env = os.Environ()
	command.Dir = fx.workspace
	output, err := command.Output()
	if err != nil {
		return check{Name: "descendant-inheritance", Expected: "enforced", Observed: "launch-error", Passed: false}
	}
	var report probeReport
	if err := json.Unmarshal(output, &report); err != nil {
		return check{Name: "descendant-inheritance", Expected: "enforced", Observed: "invalid-report", Passed: false}
	}
	passed := len(report.Checks) == 2
	for _, result := range report.Checks {
		passed = passed && result.Passed
	}
	observed := "enforced"
	if !passed {
		observed = "escaped"
	}
	return check{Name: "descendant-inheritance", Expected: "enforced", Observed: observed, Passed: passed}
}

func verifyExitStatus(fx fixture) check {
	command := sandboxCommand(fx, seatbeltPolicy(), "--exit-23")
	err := command.Run()
	var exitError *exec.ExitError
	passed := errors.As(err, &exitError) && exitError.ExitCode() == 23
	observed := "unexpected"
	if passed {
		observed = "23"
	} else if exitError != nil {
		observed = fmt.Sprintf("%d", exitError.ExitCode())
	} else if err == nil {
		observed = "0"
	}
	return check{Name: "exit-status", Expected: "23", Observed: observed, Passed: passed}
}

func verifySignalDelivery(fx fixture) check {
	command := sandboxCommand(fx, seatbeltPolicy(), "--wait-signal")
	stdout, err := command.StdoutPipe()
	if err != nil {
		return failedCheck("signal-delivery", "delivered", "pipe-error")
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return failedCheck("signal-delivery", "delivered", "launch-error")
	}
	reader := bufio.NewReader(stdout)
	ready := make(chan string, 1)
	go func() {
		line, _ := reader.ReadString('\n')
		ready <- strings.TrimSpace(line)
	}()
	select {
	case marker := <-ready:
		if marker != "READY" {
			_ = command.Process.Kill()
			_ = command.Wait()
			return failedCheck("signal-delivery", "delivered", "not-ready")
		}
	case <-time.After(3 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		return failedCheck("signal-delivery", "delivered", "ready-timeout")
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return failedCheck("signal-delivery", "delivered", "send-error")
	}
	delivered := make(chan string, 1)
	go func() {
		line, _ := reader.ReadString('\n')
		delivered <- strings.TrimSpace(line)
	}()
	select {
	case marker := <-delivered:
		err := command.Wait()
		passed := marker == "SIGTERM" && err == nil
		observed := "delivered"
		if !passed {
			observed = "lost"
		}
		return check{Name: "signal-delivery", Expected: "delivered", Observed: observed, Passed: passed}
	case <-time.After(3 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		return failedCheck("signal-delivery", "delivered", "delivery-timeout")
	}
}

func waitForSignal() {
	received := make(chan os.Signal, 1)
	signal.Notify(received, syscall.SIGTERM)
	defer signal.Stop(received)
	fmt.Println("READY")
	select {
	case <-received:
		fmt.Println("SIGTERM")
	case <-time.After(5 * time.Second):
		fmt.Println("TIMEOUT")
		os.Exit(3)
	}
}

type ptyReport struct {
	InitialColumns int `json:"initialColumns"`
	InitialRows    int `json:"initialRows"`
	FinalColumns   int `json:"finalColumns"`
	FinalRows      int `json:"finalRows"`
}

func verifyPTYResize(fx fixture) check {
	master, terminal, err := pty.Open()
	if err != nil {
		return failedCheck("pty-resize", "80x24->120x40", "pty-error")
	}
	defer master.Close()
	defer terminal.Close()
	if err := pty.Setsize(master, &pty.Winsize{Cols: 80, Rows: 24}); err != nil {
		return failedCheck("pty-resize", "80x24->120x40", "initial-size-error")
	}
	command := sandboxCommand(fx, seatbeltPolicy(), "--pty-resize")
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := command.Start(); err != nil {
		return failedCheck("pty-resize", "80x24->120x40", "launch-error")
	}
	reader := bufio.NewReader(master)
	ready := make(chan string, 1)
	go func() {
		line, _ := reader.ReadString('\n')
		ready <- strings.TrimSpace(line)
	}()
	select {
	case marker := <-ready:
		if marker != "READY" {
			_ = command.Process.Kill()
			_ = command.Wait()
			return failedCheck("pty-resize", "80x24->120x40", "not-ready")
		}
	case <-time.After(3 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		return failedCheck("pty-resize", "80x24->120x40", "ready-timeout")
	}
	if err := pty.Setsize(master, &pty.Winsize{Cols: 120, Rows: 40}); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		return failedCheck("pty-resize", "80x24->120x40", "resize-error")
	}
	reportLine := make(chan string, 1)
	go func() {
		line, _ := reader.ReadString('\n')
		reportLine <- strings.TrimSpace(line)
	}()
	select {
	case line := <-reportLine:
		waitErr := command.Wait()
		var report ptyReport
		decodeErr := json.Unmarshal([]byte(line), &report)
		passed := waitErr == nil && decodeErr == nil &&
			report.InitialColumns == 80 && report.InitialRows == 24 &&
			report.FinalColumns == 120 && report.FinalRows == 40
		observed := fmt.Sprintf("%dx%d->%dx%d", report.InitialColumns, report.InitialRows, report.FinalColumns, report.FinalRows)
		if decodeErr != nil {
			observed = "invalid-report"
		}
		return check{Name: "pty-resize", Expected: "80x24->120x40", Observed: observed, Passed: passed}
	case <-time.After(3 * time.Second):
		_ = command.Process.Kill()
		_ = command.Wait()
		return failedCheck("pty-resize", "80x24->120x40", "report-timeout")
	}
}

func reportPTYResize() {
	initial, err := unix.IoctlGetWinsize(int(os.Stdin.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		os.Exit(2)
	}
	resized := make(chan os.Signal, 1)
	signal.Notify(resized, syscall.SIGWINCH)
	defer signal.Stop(resized)
	fmt.Println("READY")
	select {
	case <-resized:
	case <-time.After(5 * time.Second):
		os.Exit(3)
	}
	final, err := unix.IoctlGetWinsize(int(os.Stdin.Fd()), unix.TIOCGWINSZ)
	if err != nil {
		os.Exit(2)
	}
	_ = json.NewEncoder(os.Stdout).Encode(ptyReport{
		InitialColumns: int(initial.Col),
		InitialRows:    int(initial.Row),
		FinalColumns:   int(final.Col),
		FinalRows:      int(final.Row),
	})
}

func verifyFailClosed(fx fixture) check {
	marker := filepath.Join(fx.workspace, "invalid-policy-started")
	command := sandboxCommand(fx, `(version 1) (invalid-operation default)`, "--mark-start", marker)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	err := command.Run()
	_, statErr := os.Stat(marker)
	passed := err != nil && errors.Is(statErr, os.ErrNotExist)
	observed := "blocked-before-start"
	if !passed {
		observed = "started-or-succeeded"
	}
	return check{Name: "invalid-policy-fail-closed", Expected: "blocked-before-start", Observed: observed, Passed: passed}
}

func failedCheck(name, expected, observed string) check {
	return check{Name: name, Expected: expected, Observed: observed, Passed: false}
}

func acceptOnce(listener net.Listener) {
	connection, err := listener.Accept()
	if err == nil {
		_ = connection.Close()
	}
}

func copyExecutable(sourcePath, destinationPath string) error {
	source, err := os.Open(sourcePath)
	if err != nil {
		return fmt.Errorf("open prototype executable: %w", err)
	}
	defer source.Close()
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		return fmt.Errorf("create synthetic target executable: %w", err)
	}
	if _, err := io.Copy(destination, source); err != nil {
		_ = destination.Close()
		return fmt.Errorf("copy synthetic target executable: %w", err)
	}
	if err := destination.Sync(); err != nil {
		_ = destination.Close()
		return fmt.Errorf("sync synthetic target executable: %w", err)
	}
	if err := destination.Close(); err != nil {
		return fmt.Errorf("close synthetic target executable: %w", err)
	}
	return nil
}

func sanitized(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	return "sandbox command reported an error"
}
