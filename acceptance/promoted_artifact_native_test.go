//go:build darwin || linux

package acceptance_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/charmbracelet/x/term"
)

const (
	fakeDevinConfigurationName = ".acs-native-candidate-fixture.json"
	fakeDevinResultName        = ".acs-native-candidate-result.json"
	privateEnvironmentValue    = "candidate-secret-value"
	privateDescriptorValue     = "candidate-descriptor-value"
)

// TestMain also makes this test executable a credential-free fake Devin. The
// installed ACS candidate resolves it like a normal target executable; no test
// hook, build tag, or environment variable is available to the candidate.
func TestMain(m *testing.M) {
	if runPromotedArtifactFakeDevin(os.Args[1:]) {
		return
	}
	os.Exit(m.Run())
}

func TestPromotedArtifactNativeContainmentContract(t *testing.T) {
	if promotedSandboxCapability(t) != "available" {
		t.Skip("native containment requires the configured native backend")
	}

	t.Run("readiness is native and sanitized", assertPromotedArtifactNativeReadiness)
	t.Run("filesystem environment descriptors sockets IP preflight and descendants", assertPromotedArtifactNativeContainment)
	t.Run("preflight failure is categorized without target details", assertPromotedArtifactNativePreflightFailureIsSafe)
	t.Run("missing required backend cannot start a marker", assertPromotedArtifactMissingBackendFailsClosed)
	t.Run("invalid native launch input cannot start a marker", assertPromotedArtifactInvalidNativeInputFailsClosed)
}

func assertPromotedArtifactNativeReadiness(t *testing.T) {
	binary := promotedBinary(t)
	home, path := prepareRuntimeHome(t)
	workspace := realTemporaryDirectory(t)
	command := exec.Command(binary, "devin", "--profile", "reviews", "--dry-run")
	command.Env = nativeCandidateEnvironment(home, path, nil)
	command.Dir = workspace
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatal("installed candidate did not report native readiness")
	}
	for _, marker := range []string{
		"required sandbox mode: native",
		"supported platform: supported",
		"backend readiness: ready",
		"ACS will not start Devin without the required sandbox.",
	} {
		if !strings.Contains(string(output), marker) {
			t.Fatalf("native readiness omitted required observation %q", marker)
		}
	}
	if strings.Contains(string(output), privateEnvironmentValue) || containsControlCharacter(string(output)) {
		t.Fatal("native readiness exposed unsafe host detail")
	}
	assertNoSessions(t, home)
}

func assertPromotedArtifactNativeContainment(t *testing.T) {
	binary := promotedBinary(t)
	home, path := prepareRuntimeHome(t)
	fixtureRoot := realTemporaryDirectory(t)
	workspace := filepath.Join(fixtureRoot, "workspace")
	tools := filepath.Join(fixtureRoot, "tools")
	for _, directory := range []string{workspace, tools} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	installPromotedArtifactFakeDevin(t, tools)

	hostSecret := filepath.Join(fixtureRoot, "host-secret")
	if err := os.WriteFile(hostSecret, []byte("native-host-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(hostSecret, filepath.Join(workspace, "host-secret-link")); err != nil {
		t.Fatal(err)
	}
	socketDirectory, err := os.MkdirTemp("/tmp", "acs-native-socket-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDirectory) })
	hostSocket := filepath.Join(socketDirectory, "host.sock")
	unixListener, err := net.Listen("unix", hostSocket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unixListener.Close() })
	ipListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ipListener.Close() })
	ipAccepted := make(chan struct{}, 1)
	go func() {
		connection, acceptErr := ipListener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
			ipAccepted <- struct{}{}
		}
	}()

	config := fakeDevinConfiguration{
		Mode:                "containment",
		HostSecret:          hostSecret,
		HostSocket:          hostSocket,
		OutboundAddress:     ipListener.Addr().String(),
		EnvironmentSentinel: privateEnvironmentValue,
		DescriptorSentinel:  privateDescriptorValue,
	}
	writeFakeDevinConfiguration(t, workspace, config)

	descriptor, err := os.Open(hostSecret)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = descriptor.Close() })
	command := exec.Command(binary, "devin", "--profile", "reviews")
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, tools+string(os.PathListSeparator)+path, map[string]string{
		"ACS_NATIVE_CANDIDATE_SECRET": privateEnvironmentValue,
	})
	command.ExtraFiles = []*os.File{descriptor}
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		t.Fatal("installed candidate failed the native containment fixture")
	}
	if output.Len() != 0 {
		t.Fatal("native containment fixture produced target output")
	}

	result := readFakeDevinResult(t, workspace)
	if !result.PreflightSkills || !result.PreflightAuthentication {
		t.Fatal("candidate did not run both preflight probes in the contained Session")
	}
	for name, actual := range map[string]bool{
		"workspace write":     result.WorkspaceWritable,
		"Session write":       result.SessionWritable,
		"Session temporary":   result.TemporaryWritable,
		"allowed environment": result.AllowedEnvironment,
		"outbound IP":         result.OutboundIP,
		"descendant start":    result.DescendantStarted,
	} {
		if !actual {
			t.Fatalf("native containment did not preserve %s", name)
		}
	}
	for name, actual := range map[string]bool{
		"host file":            result.HostFileReadable,
		"symlink escape":       result.SymlinkEscapeReadable,
		"secret environment":   result.BlockedEnvironmentVisible,
		"inherited descriptor": result.DescriptorLeaked,
		"host Unix socket":     result.HostSocketReachable,
	} {
		if actual {
			t.Fatalf("native containment exposed %s", name)
		}
	}
	select {
	case <-ipAccepted:
	case <-time.After(5 * time.Second):
		t.Fatal("native containment did not permit outbound IP")
	}
	assertMarkerExists(t, filepath.Join(workspace, "workspace-write"))
	assertMarkerExists(t, filepath.Join(workspace, "descendant-ready"))
	time.Sleep(750 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(workspace, "descendant-survived")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("native containment did not clean a descendant before Session removal")
	}
	assertNoSessions(t, home)
}

func assertPromotedArtifactNativePreflightFailureIsSafe(t *testing.T) {
	binary := promotedBinary(t)
	home, path := prepareRuntimeHome(t)
	fixtureRoot := realTemporaryDirectory(t)
	workspace := filepath.Join(fixtureRoot, "workspace")
	tools := filepath.Join(fixtureRoot, "tools")
	for _, directory := range []string{workspace, tools} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	installPromotedArtifactFakeDevin(t, tools)
	privatePath := filepath.Join(fixtureRoot, "private-account")
	writeFakeDevinConfiguration(t, workspace, fakeDevinConfiguration{
		Mode:          "authentication-failure",
		PrivatePath:   privatePath,
		PrivateOutput: "credential=never-log\x1b[31m",
	})

	command := exec.Command(binary, "devin", "--profile", "reviews")
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, tools+string(os.PathListSeparator)+path, nil)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("candidate accepted a failed authentication preflight")
	}
	assertSafeCandidateFailure(t, output, "authentication_preflight_failed", privatePath, "credential=never-log")
	if _, err := os.Stat(filepath.Join(workspace, "interactive-started")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("authentication failure started the interactive target")
	}
	assertNoSessions(t, home)
}

func assertPromotedArtifactMissingBackendFailsClosed(t *testing.T) {
	binary := promotedBinary(t)
	home, path := prepareRuntimeHome(t)
	fixtureRoot := realTemporaryDirectory(t)
	workspace := filepath.Join(fixtureRoot, "workspace")
	tools := filepath.Join(fixtureRoot, "tools")
	for _, directory := range []string{workspace, tools} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeFakeDevin(t, filepath.Join(tools, "devin"), "#!/bin/sh\ntouch ./interactive-started\n")

	command := promotedArtifactMissingBackendCommand(t, binary, home, tools+string(os.PathListSeparator)+path, workspace)
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("candidate accepted a missing required backend")
	}
	assertSafeCandidateFailure(t, output, "backend_unavailable", fixtureRoot)
	for _, marker := range []string{"preflight-skills", "preflight-authentication", "interactive-started"} {
		if _, err := os.Stat(filepath.Join(workspace, marker)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("missing required backend started a target marker")
		}
	}
	assertNoSessions(t, home)
}

func assertPromotedArtifactInvalidNativeInputFailsClosed(t *testing.T) {
	binary := promotedBinary(t)
	home, path := prepareRuntimeHome(t)
	fixtureRoot := realTemporaryDirectory(t)
	workspace := filepath.Join(fixtureRoot, "workspace")
	tools := filepath.Join(fixtureRoot, "tools")
	for _, directory := range []string{workspace, tools} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	installPromotedArtifactFakeDevin(t, tools)
	privatePath := filepath.Join(fixtureRoot, "private-policy-input")
	writeFakeDevinConfiguration(t, workspace, fakeDevinConfiguration{Mode: "containment", PrivatePath: privatePath})

	command := exec.Command(binary, "devin", "--profile", "reviews")
	command.Dir = workspace
	command.Env = nativeCandidateEnvironment(home, tools+string(os.PathListSeparator)+path, map[string]string{
		"TERM": "unsafe\nterminal-value",
	})
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("candidate accepted invalid native launch input")
	}
	assertSafeCandidateFailure(t, output, "invalid_environment", privatePath, "unsafe", "terminal-value")
	for _, marker := range []string{"preflight-skills", "preflight-authentication", "interactive-started"} {
		if _, err := os.Stat(filepath.Join(workspace, marker)); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("invalid native launch input started a target marker")
		}
	}
	assertNoSessions(t, home)
}

type fakeDevinConfiguration struct {
	Mode                string `json:"mode"`
	HostSecret          string `json:"hostSecret,omitempty"`
	HostSocket          string `json:"hostSocket,omitempty"`
	OutboundAddress     string `json:"outboundAddress,omitempty"`
	EnvironmentSentinel string `json:"environmentSentinel,omitempty"`
	DescriptorSentinel  string `json:"descriptorSentinel,omitempty"`
	PrivatePath         string `json:"privatePath,omitempty"`
	PrivateOutput       string `json:"privateOutput,omitempty"`
}

type fakeDevinResult struct {
	PreflightSkills           bool `json:"preflightSkills"`
	PreflightAuthentication   bool `json:"preflightAuthentication"`
	WorkspaceWritable         bool `json:"workspaceWritable"`
	SessionWritable           bool `json:"sessionWritable"`
	TemporaryWritable         bool `json:"temporaryWritable"`
	HostFileReadable          bool `json:"hostFileReadable"`
	SymlinkEscapeReadable     bool `json:"symlinkEscapeReadable"`
	AllowedEnvironment        bool `json:"allowedEnvironment"`
	BlockedEnvironmentVisible bool `json:"blockedEnvironmentVisible"`
	DescriptorLeaked          bool `json:"descriptorLeaked"`
	HostSocketReachable       bool `json:"hostSocketReachable"`
	OutboundIP                bool `json:"outboundIP"`
	DescendantStarted         bool `json:"descendantStarted"`
}

func installPromotedArtifactFakeDevin(t *testing.T, tools string) {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(binary, filepath.Join(tools, "devin")); err != nil {
		t.Fatal(err)
	}
}

func writeFakeDevinConfiguration(t *testing.T, workspace string, configuration fakeDevinConfiguration) {
	t.Helper()
	contents, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, fakeDevinConfigurationName), contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFakeDevinConfiguration() (fakeDevinConfiguration, error) {
	contents, err := os.ReadFile(filepath.Join(mustGetwd(), fakeDevinConfigurationName))
	if err != nil {
		return fakeDevinConfiguration{}, err
	}
	var configuration fakeDevinConfiguration
	if err := json.Unmarshal(contents, &configuration); err != nil {
		return fakeDevinConfiguration{}, err
	}
	return configuration, nil
}

func readFakeDevinResult(t *testing.T, workspace string) fakeDevinResult {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(workspace, fakeDevinResultName))
	if err != nil {
		t.Fatal("contained fake Devin did not record its result")
	}
	var result fakeDevinResult
	if err := json.Unmarshal(contents, &result); err != nil {
		t.Fatal("contained fake Devin wrote an invalid result")
	}
	return result
}

func runPromotedArtifactFakeDevin(arguments []string) bool {
	if len(arguments) == 1 && arguments[0] == "--acs-native-candidate-descendant" {
		runFakeDevinDescendant()
		return true
	}
	if len(arguments) == 3 && arguments[0] == "skills" && arguments[1] == "list" && arguments[2] == "--json" {
		runFakeDevinSkills()
		return true
	}
	if len(arguments) == 2 && arguments[0] == "auth" && arguments[1] == "status" {
		runFakeDevinAuthentication()
		return true
	}
	if len(arguments) == 0 {
		runFakeDevinInteractive()
		return true
	}
	return false
}

func runFakeDevinSkills() {
	workspace := mustGetwd()
	writeFakeDevinMarker(filepath.Join(workspace, "preflight-skills"))
	base := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "devin", "skills", "review")
	_ = json.NewEncoder(os.Stdout).Encode([]map[string]string{{"name": "review", "provider": "Devin", "base_dir": base}})
	return
}

func runFakeDevinAuthentication() {
	configuration, err := readFakeDevinConfiguration()
	if err != nil {
		os.Exit(71)
	}
	if configuration.Mode == "authentication-failure" {
		_, _ = io.WriteString(os.Stderr, configuration.PrivateOutput)
		os.Exit(66)
	}
	credential := filepath.Join(os.Getenv("XDG_DATA_HOME"), "devin", "credentials.toml")
	if _, err := os.Stat(credential); err != nil {
		os.Exit(65)
	}
	writeFakeDevinMarker(filepath.Join(mustGetwd(), "preflight-authentication"))
	_, _ = io.WriteString(os.Stdout, "Logged in (fixture).\n")
}

func runFakeDevinInteractive() {
	configuration, err := readFakeDevinConfiguration()
	if err != nil {
		os.Exit(71)
	}
	workspace := mustGetwd()
	if configuration.Mode == "signal" || configuration.Mode == "resize" {
		runFakeDevinTerminalFixture(configuration.Mode, workspace)
		return
	}
	result := fakeDevinResult{
		PreflightSkills:           fakeDevinMarkerExists(filepath.Join(workspace, "preflight-skills")),
		PreflightAuthentication:   fakeDevinMarkerExists(filepath.Join(workspace, "preflight-authentication")),
		WorkspaceWritable:         writeFakeDevinMarker(filepath.Join(workspace, "workspace-write")),
		SessionWritable:           writeFakeDevinMarker(filepath.Join(os.Getenv("HOME"), "session-write")),
		TemporaryWritable:         writeFakeDevinMarker(filepath.Join(os.Getenv("TMPDIR"), "temporary-write")),
		HostFileReadable:          fakeDevinCanRead(configuration.HostSecret),
		SymlinkEscapeReadable:     fakeDevinCanRead(filepath.Join(workspace, "host-secret-link")),
		AllowedEnvironment:        fakeDevinAllowedEnvironment(),
		BlockedEnvironmentVisible: os.Getenv("ACS_NATIVE_CANDIDATE_SECRET") == configuration.EnvironmentSentinel,
		DescriptorLeaked:          fakeDevinDescriptorContains(configuration.DescriptorSentinel),
		HostSocketReachable:       fakeDevinCanDial("unix", configuration.HostSocket),
		OutboundIP:                fakeDevinCanDial("tcp", configuration.OutboundAddress),
	}
	result.DescendantStarted = startFakeDevinDescendant()
	writeFakeDevinMarker(filepath.Join(workspace, "interactive-started"))
	contents, err := json.Marshal(result)
	if err != nil {
		os.Exit(72)
	}
	if err := os.WriteFile(filepath.Join(workspace, fakeDevinResultName), contents, 0o600); err != nil {
		os.Exit(73)
	}
}

func runFakeDevinTerminalFixture(mode, workspace string) {
	ready := filepath.Join(workspace, "terminal-ready")
	if !writeFakeDevinMarker(ready) {
		os.Exit(74)
	}
	signals := make(chan os.Signal, 1)
	if mode == "signal" {
		signal.Notify(signals, syscall.SIGTERM)
		defer signal.Stop(signals)
		<-signals
		_ = os.WriteFile(filepath.Join(workspace, "signal-record"), []byte("SIGTERM\n"), 0o600)
		os.Exit(42)
	}
	signal.Notify(signals, syscall.SIGWINCH)
	defer signal.Stop(signals)
	<-signals
	width, height, err := term.GetSize(os.Stdin.Fd())
	if err != nil {
		os.Exit(75)
	}
	_ = os.WriteFile(filepath.Join(workspace, "resize-record"), []byte(strconv.Itoa(height)+" "+strconv.Itoa(width)+"\n"), 0o600)
}

func runFakeDevinDescendant() {
	workspace := mustGetwd()
	if !writeFakeDevinMarker(filepath.Join(workspace, "descendant-ready")) {
		os.Exit(76)
	}
	time.Sleep(500 * time.Millisecond)
	_ = writeFakeDevinMarker(filepath.Join(workspace, "descendant-survived"))
}

func startFakeDevinDescendant() bool {
	command := exec.Command(os.Args[0], "--acs-native-candidate-descendant")
	command.Dir = mustGetwd()
	command.Env = os.Environ()
	if err := command.Start(); err != nil {
		return false
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(mustGetwd(), "descendant-ready")); err == nil {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

func fakeDevinAllowedEnvironment() bool {
	home := os.Getenv("HOME")
	return home != "" &&
		os.Getenv("XDG_CONFIG_HOME") == filepath.Join(home, ".config") &&
		os.Getenv("XDG_DATA_HOME") == filepath.Join(home, ".local", "share") &&
		os.Getenv("XDG_CACHE_HOME") == filepath.Join(home, ".cache") &&
		os.Getenv("XDG_STATE_HOME") == filepath.Join(home, ".local", "state") &&
		strings.HasPrefix(os.Getenv("TMPDIR"), filepath.Dir(home)+string(filepath.Separator)) &&
		os.Getenv("TERM") == "xterm-256color"
}

func fakeDevinCanRead(path string) bool {
	if path == "" {
		return false
	}
	contents, err := os.ReadFile(path)
	return err == nil && len(contents) > 0
}

func fakeDevinDescriptorContains(want string) bool {
	if want == "" {
		return false
	}
	file := os.NewFile(uintptr(3), "candidate-host-descriptor")
	if file == nil {
		return false
	}
	contents, err := io.ReadAll(io.LimitReader(file, 512))
	return err == nil && strings.Contains(string(contents), want)
}

func fakeDevinCanDial(network, address string) bool {
	if address == "" {
		return false
	}
	connection, err := net.DialTimeout(network, address, 2*time.Second)
	if err != nil {
		return false
	}
	return connection.Close() == nil
}

func writeFakeDevinMarker(path string) bool {
	return os.WriteFile(path, []byte("ok\n"), 0o600) == nil
}

func fakeDevinMarkerExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func mustGetwd() string {
	directory, err := os.Getwd()
	if err != nil {
		os.Exit(70)
	}
	return directory
}

func nativeCandidateEnvironment(home, path string, overrides map[string]string) []string {
	values := map[string]string{
		"HOME":     home,
		"PATH":     path,
		"TERM":     "xterm-256color",
		"NO_COLOR": "1",
	}
	for key, value := range overrides {
		values[key] = value
	}
	environment := make([]string, 0, len(os.Environ())+len(values))
	for _, entry := range os.Environ() {
		key, _, found := strings.Cut(entry, "=")
		if found {
			if _, overridden := values[key]; overridden {
				continue
			}
		}
		environment = append(environment, entry)
	}
	for _, key := range []string{"HOME", "PATH", "TERM", "NO_COLOR", "ACS_NATIVE_CANDIDATE_SECRET"} {
		if value, ok := values[key]; ok {
			environment = append(environment, key+"="+value)
		}
	}
	return environment
}

func assertSafeCandidateFailure(t *testing.T, output []byte, category string, forbidden ...string) {
	t.Helper()
	text := string(output)
	if !strings.Contains(text, category) {
		t.Fatalf("candidate failure did not report the stable %s category", category)
	}
	if containsControlCharacter(text) {
		t.Fatal("candidate failure included terminal control characters")
	}
	for _, value := range forbidden {
		if value != "" && strings.Contains(text, value) {
			t.Fatal("candidate failure exposed private fixture detail")
		}
	}
}

func containsControlCharacter(value string) bool {
	for _, character := range value {
		if character < 0x20 && character != '\n' && character != '\r' && character != '\t' {
			return true
		}
	}
	return false
}

func assertMarkerExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatal("contained target did not create its allowed marker")
	}
}
