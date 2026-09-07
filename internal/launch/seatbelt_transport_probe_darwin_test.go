//go:build darwin

package launch

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	seatbeltTransportProbeEnvironment = "ACS_RUN_NATIVE_TRANSPORT_PROBE"
	seatbeltTransportEvidencePath     = "ACS_NATIVE_TRANSPORT_EVIDENCE"
	seatbeltTransportProbeDeadline    = 750 * time.Millisecond
	seatbeltTransportAbsenceDeadline  = 250 * time.Millisecond
	seatbeltTransportOutputLimit      = 64 * 1024
	seatbeltTransportProcessDeadline  = 12 * time.Second
)

type seatbeltTransportEvidence struct {
	Schema               string                              `json:"schema"`
	RecordedAt           string                              `json:"recorded_at"`
	SourceCommit         string                              `json:"source_commit"`
	SourceTree           string                              `json:"source_tree"`
	NativeJob            string                              `json:"native_job"`
	OSProductVersion     string                              `json:"os_product_version"`
	OSBuildVersion       string                              `json:"os_build_version"`
	Architecture         string                              `json:"architecture"`
	HelperSHA256         string                              `json:"helper_sha256"`
	FixtureReadiness     []string                            `json:"fixture_readiness"`
	FixtureEndpoints     []seatbeltTransportEndpoint         `json:"fixture_endpoints"`
	PositiveOperations   []seatbeltTransportResult           `json:"positive_control_operations"`
	PositiveControls     []seatbeltTransportReceipt          `json:"positive_controls"`
	Cases                []seatbeltTransportCaseEvidence     `json:"cases"`
	InheritedDescriptors seatbeltInheritedDescriptorEvidence `json:"inherited_connected_descriptors"`
	ResearchOutcome      string                              `json:"research_outcome"`
	FixtureCleanup       bool                                `json:"fixture_cleanup"`
	Demonstrated         []string                            `json:"demonstrated"`
	Unresolved           []string                            `json:"unresolved"`
}

type seatbeltTransportCaseEvidence struct {
	Name                 string                     `json:"name"`
	PolicyValidation     string                     `json:"policy_validation"`
	PolicyExample        string                     `json:"policy_example,omitempty"`
	DescendantExecution  bool                       `json:"descendant_execution"`
	ClientOperations     []seatbeltTransportResult  `json:"client_operations,omitempty"`
	ListenerReceipts     []seatbeltTransportReceipt `json:"listener_receipts,omitempty"`
	AuthenticatedCleanup bool                       `json:"authenticated_cleanup"`
	PhysicalRemoval      bool                       `json:"physical_session_removal"`
	Conclusion           string                     `json:"conclusion"`
}

type seatbeltTransportResult struct {
	Operation    string `json:"operation"`
	Marker       string `json:"marker,omitempty"`
	BytesWritten int    `json:"bytes_written"`
	Category     string `json:"category"`
}

type seatbeltTransportReceipt struct {
	Listener string `json:"listener"`
	Marker   string `json:"marker"`
}

type seatbeltTransportEndpoint struct {
	Listener  string `json:"listener"`
	Transport string `json:"transport"`
	Address   string `json:"address"`
}

type seatbeltInheritedDescriptorEvidence struct {
	TCPPositiveControl  bool   `json:"tcp_positive_control"`
	UDPPositiveControl  bool   `json:"udp_positive_control"`
	PreSealerTCPPresent bool   `json:"pre_sealer_tcp_descriptor_present"`
	PreSealerUDPPresent bool   `json:"pre_sealer_udp_descriptor_present"`
	TargetTCPResult     string `json:"target_tcp_result"`
	TargetUDPResult     string `json:"target_udp_result"`
	TCPInheritedReceipt bool   `json:"tcp_inherited_receipt"`
	UDPInheritedReceipt bool   `json:"udp_inherited_receipt"`
	SealerPID           int    `json:"sealer_pid"`
	TargetPID           int    `json:"target_pid"`
	ProcessCleanup      bool   `json:"process_cleanup"`
	Conclusion          string `json:"conclusion"`
}

type seatbeltTransportProbeConfig struct {
	Operations []seatbeltTransportProbeOperation `json:"operations"`
}

type seatbeltTransportProbeOperation struct {
	Name    string `json:"name"`
	Network string `json:"network"`
	Address string `json:"address"`
	Marker  string `json:"marker"`
}

type seatbeltTransportProbeOutput struct {
	ParentPID     int                       `json:"parent_pid"`
	DescendantPID int                       `json:"descendant_pid"`
	Results       []seatbeltTransportResult `json:"results"`
}

type seatbeltBoundedCapture struct {
	mutex    sync.Mutex
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (capture *seatbeltBoundedCapture) Write(contents []byte) (int, error) {
	capture.mutex.Lock()
	defer capture.mutex.Unlock()
	remaining := capture.limit - capture.buffer.Len()
	if remaining > 0 {
		_, _ = capture.buffer.Write(contents[:min(len(contents), remaining)])
	}
	if len(contents) > remaining {
		capture.exceeded = true
	}
	return len(contents), nil
}

func (capture *seatbeltBoundedCapture) Bytes() []byte {
	capture.mutex.Lock()
	defer capture.mutex.Unlock()
	return append([]byte(nil), capture.buffer.Bytes()...)
}

func (capture *seatbeltBoundedCapture) String() string { return string(capture.Bytes()) }

func (capture *seatbeltBoundedCapture) Exceeded() bool {
	capture.mutex.Lock()
	defer capture.mutex.Unlock()
	return capture.exceeded
}

func TestNativeSeatbeltTransportResearchMatrix(t *testing.T) {
	if os.Getenv(seatbeltTransportProbeEnvironment) != "1" {
		t.Skip("set ACS_RUN_NATIVE_TRANSPORT_PROBE=1 in the dedicated native research job")
	}
	if runtime.GOARCH != "arm64" {
		t.Fatalf("transport research requires darwin/arm64, got darwin/%s", runtime.GOARCH)
	}
	platform, err := CurrentPlatform()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePlatform(platform); err != nil {
		t.Fatal(err)
	}

	evidence := seatbeltNewTransportEvidence(t)
	evidencePath := os.Getenv(seatbeltTransportEvidencePath)
	if !filepath.IsAbs(evidencePath) {
		t.Fatal("ACS_NATIVE_TRANSPORT_EVIDENCE must be an absolute path")
	}
	defer func() {
		evidence.RecordedAt = time.Now().UTC().Format(time.RFC3339Nano)
		seatbeltWriteTransportEvidence(t, evidencePath, evidence)
	}()

	fixture := newSeatbeltTransportFixture(t)
	evidence.FixtureReadiness = fixture.readiness()
	evidence.FixtureEndpoints = fixture.endpoints()
	evidence.PositiveOperations, evidence.PositiveControls = fixture.positiveControls(t)

	coarse := fixture.runCase(t, "current_coarse_outbound", seatbeltTransportPolicyCoarse)
	evidence.Cases = append(evidence.Cases, coarse)
	denied := fixture.runCase(t, "denied_outbound", seatbeltTransportPolicyDenied)
	evidence.Cases = append(evidence.Cases, denied)

	exactIP := fixture.runExactIPCase(t)
	evidence.Cases = append(evidence.Cases, exactIP)
	exactUnix := fixture.runCase(t, "exact_unix_socket", seatbeltTransportPolicyExactUnix)
	evidence.Cases = append(evidence.Cases, exactUnix)

	evidence.InheritedDescriptors = fixture.runInheritedDescriptorCase(t)
	fixture.closeAndWait()
	evidence.FixtureCleanup = fixture.cleanupObserved()
	if !evidence.FixtureCleanup {
		t.Fatal("listener cleanup was not observed for every fixture")
	}
	evidence.ResearchOutcome = seatbeltTransportResearchOutcome(evidence.Cases, evidence.InheritedDescriptors)
	evidence.Demonstrated = seatbeltTransportDemonstrated(evidence)
	t.Logf("Seatbelt transport research result: %s (green verifies the bounded observation, not destination-filtering support)", evidence.ResearchOutcome)
}

func TestSeatbeltTransportProbeHelper(t *testing.T) {
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
	case "transport-parent":
		if len(arguments) != 2 {
			os.Exit(125)
		}
		command := exec.Command(os.Args[0], "-test.run=^TestSeatbeltTransportProbeHelper$", "--", "transport-child", arguments[1])
		command.Env = os.Environ()
		output := &seatbeltBoundedCapture{limit: seatbeltTransportOutputLimit}
		command.Stdout = output
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			os.Exit(124)
		}
		if output.Exceeded() {
			os.Exit(123)
		}
		var child seatbeltTransportProbeOutput
		if err := json.Unmarshal(output.Bytes(), &child); err != nil {
			os.Exit(123)
		}
		child.ParentPID = os.Getpid()
		if err := json.NewEncoder(os.Stdout).Encode(child); err != nil {
			os.Exit(122)
		}
		os.Exit(0)
	case "transport-child":
		if len(arguments) != 2 {
			os.Exit(121)
		}
		encoded, err := base64.RawURLEncoding.DecodeString(arguments[1])
		if err != nil {
			os.Exit(120)
		}
		var config seatbeltTransportProbeConfig
		if err := json.Unmarshal(encoded, &config); err != nil {
			os.Exit(119)
		}
		output := seatbeltTransportProbeOutput{DescendantPID: os.Getpid()}
		for _, operation := range config.Operations {
			output.Results = append(output.Results, seatbeltRunTransportOperation(operation))
		}
		if err := json.NewEncoder(os.Stdout).Encode(output); err != nil {
			os.Exit(118)
		}
		os.Exit(0)
	case "inherited-descriptors":
		if len(arguments) != 5 {
			os.Exit(117)
		}
		if err := json.NewEncoder(os.Stdout).Encode(seatbeltTransportResult{Operation: "target-pid", Category: strconv.Itoa(os.Getpid())}); err != nil {
			os.Exit(116)
		}
		for index, name := range []string{"inherited-tcp", "inherited-udp"} {
			fd, err := strconv.Atoi(arguments[index+1])
			if err != nil {
				os.Exit(116)
			}
			marker := arguments[index+3]
			if index == 0 {
				marker += "\n"
			}
			written, writeErr := unix.Write(fd, []byte(marker))
			result := seatbeltTransportResult{Operation: name, Marker: arguments[index+3], BytesWritten: written, Category: seatbeltTransportErrorCategory(writeErr)}
			if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
				os.Exit(115)
			}
		}
		os.Exit(0)
	case "descriptor-sealer":
		if len(arguments) != 5 {
			os.Exit(114)
		}
		api, err := loadSeatbeltProcAPI()
		if err != nil {
			os.Exit(113)
		}
		descriptors, err := api.descriptors(os.Getpid())
		if err != nil {
			os.Exit(112)
		}
		for index, name := range []string{"pre-sealer-tcp", "pre-sealer-udp"} {
			fd, parseErr := strconv.Atoi(arguments[index+1])
			if parseErr != nil {
				os.Exit(111)
			}
			category := "absent"
			if seatbeltContainsDescriptor(descriptors, fd) {
				category = "present"
			}
			if encodeErr := json.NewEncoder(os.Stdout).Encode(seatbeltTransportResult{Operation: name, Category: category}); encodeErr != nil {
				os.Exit(110)
			}
		}
		if err := sealSeatbeltTargetDescriptors(api); err != nil {
			os.Exit(109)
		}
		command := exec.Command(os.Args[0], "-test.run=^TestSeatbeltTransportProbeHelper$", "--", "inherited-descriptors", arguments[1], arguments[2], arguments[3], arguments[4])
		command.Env = os.Environ()
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			os.Exit(108)
		}
		os.Exit(0)
	}
}

func seatbeltRunTransportOperation(operation seatbeltTransportProbeOperation) seatbeltTransportResult {
	result := seatbeltTransportResult{Operation: operation.Name, Marker: operation.Marker}
	connection, err := net.DialTimeout(operation.Network, operation.Address, seatbeltTransportProbeDeadline)
	if err == nil {
		_ = connection.SetWriteDeadline(time.Now().Add(seatbeltTransportProbeDeadline))
		marker := operation.Marker
		if operation.Network != "udp4" && operation.Network != "udp6" {
			marker += "\n"
		}
		result.BytesWritten, err = io.WriteString(connection, marker)
		closeErr := connection.Close()
		if err == nil {
			err = closeErr
		}
	}
	result.Category = seatbeltTransportErrorCategory(err)
	return result
}

func seatbeltTransportErrorCategory(err error) string {
	switch {
	case err == nil:
		return "success"
	case errors.Is(err, syscall.EBADF):
		return "bad_descriptor"
	case isSeatbeltPermission(err):
		return "permission_denied"
	case errors.Is(err, os.ErrDeadlineExceeded):
		return "deadline_exceeded"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection_refused"
	case errors.Is(err, syscall.ENETUNREACH):
		return "network_unreachable"
	case errors.Is(err, syscall.EHOSTUNREACH):
		return "host_unreachable"
	case errors.Is(err, syscall.EADDRNOTAVAIL):
		return "address_not_available"
	case errors.Is(err, syscall.ENOTCONN):
		return "not_connected"
	case errors.Is(err, syscall.EPIPE):
		return "broken_pipe"
	case errors.Is(err, syscall.ECONNRESET):
		return "connection_reset"
	default:
		return "other_error"
	}
}

type seatbeltTransportPolicy int

const (
	seatbeltTransportPolicyCoarse seatbeltTransportPolicy = iota
	seatbeltTransportPolicyDenied
	seatbeltTransportPolicyExactUnix
)

const seatbeltTransportOutboundRule = `(allow network-outbound
  (remote ip)
  (literal "/private/var/run/mDNSResponder"))
`

type seatbeltTransportFixture struct {
	tcp4Allowed *seatbeltTCPRecorder
	tcp4Denied  *seatbeltTCPRecorder
	tcp6Allowed *seatbeltTCPRecorder
	tcp6Denied  *seatbeltTCPRecorder
	udp4Allowed *seatbeltUDPRecorder
	udp4Denied  *seatbeltUDPRecorder
	udp6Allowed *seatbeltUDPRecorder
	udp6Denied  *seatbeltUDPRecorder
	unixAllowed *seatbeltTCPRecorder
	unixDenied  *seatbeltTCPRecorder
	all         []seatbeltReceiptRecorder
}

type seatbeltReceiptRecorder interface {
	name() string
	address() string
	markers() []string
	closeAndWait()
	stopped() bool
}

func newSeatbeltTransportFixture(t *testing.T) *seatbeltTransportFixture {
	t.Helper()
	root := t.TempDir()
	fixture := &seatbeltTransportFixture{
		tcp4Allowed: newSeatbeltTCPRecorder(t, "tcp4-allowed", "tcp4", "127.0.0.1:0"),
		tcp4Denied:  newSeatbeltTCPRecorder(t, "tcp4-denied", "tcp4", "127.0.0.1:0"),
		tcp6Allowed: newSeatbeltTCPRecorder(t, "tcp6-allowed", "tcp6", "[::1]:0"),
		tcp6Denied:  newSeatbeltTCPRecorder(t, "tcp6-denied", "tcp6", "[::1]:0"),
		udp4Allowed: newSeatbeltUDPRecorder(t, "udp4-allowed", "udp4", "127.0.0.1:0"),
		udp4Denied:  newSeatbeltUDPRecorder(t, "udp4-denied", "udp4", "127.0.0.1:0"),
		udp6Allowed: newSeatbeltUDPRecorder(t, "udp6-allowed", "udp6", "[::1]:0"),
		udp6Denied:  newSeatbeltUDPRecorder(t, "udp6-denied", "udp6", "[::1]:0"),
		unixAllowed: newSeatbeltTCPRecorder(t, "unix-allowed", "unix", filepath.Join(root, "allowed.sock")),
		unixDenied:  newSeatbeltTCPRecorder(t, "unix-denied", "unix", filepath.Join(root, "denied.sock")),
	}
	fixture.all = []seatbeltReceiptRecorder{
		fixture.tcp4Allowed, fixture.tcp4Denied, fixture.tcp6Allowed, fixture.tcp6Denied,
		fixture.udp4Allowed, fixture.udp4Denied, fixture.udp6Allowed, fixture.udp6Denied,
		fixture.unixAllowed, fixture.unixDenied,
	}
	return fixture
}

func (fixture *seatbeltTransportFixture) readiness() []string {
	ready := make([]string, 0, len(fixture.all))
	for _, recorder := range fixture.all {
		ready = append(ready, recorder.name())
	}
	return ready
}

func (fixture *seatbeltTransportFixture) endpoints() []seatbeltTransportEndpoint {
	endpoints := make([]seatbeltTransportEndpoint, 0, len(fixture.all))
	for _, recorder := range fixture.all {
		address := recorder.address()
		if strings.HasPrefix(recorder.name(), "unix-") {
			address = "<DISPOSABLE_FIXTURE>/" + strings.TrimPrefix(recorder.name(), "unix-") + ".sock"
		}
		endpoints = append(endpoints, seatbeltTransportEndpoint{
			Listener: recorder.name(), Transport: seatbeltRecorderNetwork(recorder), Address: address,
		})
	}
	return endpoints
}

func (fixture *seatbeltTransportFixture) closeAndWait() {
	for _, recorder := range fixture.all {
		recorder.closeAndWait()
	}
}

func (fixture *seatbeltTransportFixture) cleanupObserved() bool {
	for _, recorder := range fixture.all {
		if !recorder.stopped() {
			return false
		}
	}
	return true
}

func (fixture *seatbeltTransportFixture) positiveControls(t *testing.T) ([]seatbeltTransportResult, []seatbeltTransportReceipt) {
	t.Helper()
	before := fixture.snapshot()
	operations := fixture.operations("positive")
	results := make([]seatbeltTransportResult, 0, len(operations))
	for _, operation := range operations {
		result := seatbeltRunTransportOperation(operation)
		results = append(results, result)
		if result.Category != "success" {
			t.Fatalf("positive control %s = %s", operation.Name, result.Category)
		}
	}
	if !seatbeltCompleteTransportResults(operations, results) {
		t.Fatal("positive control client operations were incomplete")
	}
	receipts := fixture.waitForNewReceipts(t, before, len(fixture.all))
	if _, correlated := seatbeltCorrelateTransportReceipts(operations, receipts); !correlated {
		t.Fatal("positive control receipts were not exactly correlated")
	}
	if len(receipts) != len(fixture.all) {
		t.Fatalf("positive control receipts = %d, want %d", len(receipts), len(fixture.all))
	}
	return results, receipts
}

func (fixture *seatbeltTransportFixture) operations(prefix string) []seatbeltTransportProbeOperation {
	operations := make([]seatbeltTransportProbeOperation, 0, len(fixture.all))
	for _, recorder := range fixture.all {
		operations = append(operations, seatbeltTransportProbeOperation{
			Name: recorder.name(), Network: seatbeltRecorderNetwork(recorder), Address: recorder.address(),
			Marker: prefix + "-" + recorder.name() + "-" + seatbeltRandomTransportMarker(),
		})
	}
	return operations
}

func seatbeltRecorderNetwork(recorder seatbeltReceiptRecorder) string {
	switch recorder.(type) {
	case *seatbeltUDPRecorder:
		if strings.HasPrefix(recorder.name(), "udp4") {
			return "udp4"
		}
		return "udp6"
	case *seatbeltTCPRecorder:
		if strings.HasPrefix(recorder.name(), "tcp4") {
			return "tcp4"
		}
		if strings.HasPrefix(recorder.name(), "tcp6") {
			return "tcp6"
		}
		return "unix"
	default:
		panic("unknown transport recorder")
	}
}

func (fixture *seatbeltTransportFixture) runCase(t *testing.T, name string, policyKind seatbeltTransportPolicy) seatbeltTransportCaseEvidence {
	t.Helper()
	operations := fixture.operations(name)
	policyExample := ""
	if policyKind == seatbeltTransportPolicyExactUnix {
		policyExample = "(allow network-outbound (literal (param \"TRANSPORT_SOCKET\")))\n-DTRANSPORT_SOCKET=<DISPOSABLE_SOCKET>"
	}
	policy := func(request validatedProcessRequest) (string, []string, error) {
		generated, definitions, err := buildSeatbeltPolicy(request)
		if err != nil {
			return "", nil, err
		}
		if policyKind == seatbeltTransportPolicyCoarse {
			return generated, definitions, nil
		}
		generated, err = seatbeltRemovePolicyTextExactlyOnce(generated, seatbeltTransportOutboundRule, "transport outbound rule")
		if err != nil {
			return "", nil, err
		}
		if policyKind == seatbeltTransportPolicyExactUnix {
			definitions = append(definitions, "-DTRANSPORT_SOCKET="+fixture.unixAllowed.address())
			generated += "\n(allow network-outbound (literal (param \"TRANSPORT_SOCKET\")))\n"
		}
		return generated, definitions, nil
	}
	return fixture.executeCase(t, name, operations, policy, policyExample)
}

func (fixture *seatbeltTransportFixture) runExactIPCase(t *testing.T) seatbeltTransportCaseEvidence {
	t.Helper()
	minimalRule := seatbeltExactIPRule("127.0.0.1", seatbeltPort(fixture.tcp4Allowed.address()))
	minimal := "(allow network-outbound " + minimalRule + ")"
	minimalRequest := seatbeltTestRequest(t)
	minimalPolicy, minimalDefinitions, err := seatbeltTransportBaseWithoutOutbound(minimalRequest)
	if err != nil {
		t.Fatal(err)
	}
	minimalPolicy += "\n" + minimal + "\n"
	backend := newSeatbeltBackend(seatbeltExecutable)
	validationContext, cancelValidation := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelValidation()
	if err := backend.validateGeneratedPolicy(validationContext, minimalRequest, minimalPolicy, minimalDefinitions); err != nil {
		validation := string(SandboxPolicyRejected)
		conclusion := "policy_rejected"
		var exitError *exec.ExitError
		if validationContext.Err() != nil {
			validation = "validation_deadline_exceeded"
			conclusion = "inconclusive_minimal_policy_validation"
		} else if !errors.As(err, &exitError) {
			validation = "validation_execution_error"
			conclusion = "inconclusive_minimal_policy_validation"
		}
		evidence := seatbeltTransportCaseEvidence{
			Name: "exact_numeric_ip_endpoint", PolicyValidation: validation,
			PolicyExample: minimal, Conclusion: conclusion,
		}
		if removeErr := os.RemoveAll(minimalRequest.sessionDirectory); removeErr != nil {
			t.Fatal(removeErr)
		}
		_, statErr := os.Stat(minimalRequest.sessionDirectory)
		evidence.PhysicalRemoval = errors.Is(statErr, os.ErrNotExist)
		return evidence
	}
	if err := os.RemoveAll(minimalRequest.sessionDirectory); err != nil {
		t.Fatal(err)
	}
	rules := []string{
		minimalRule,
		seatbeltExactIPRule("127.0.0.1", seatbeltPort(fixture.udp4Allowed.address())),
		seatbeltExactIPRule("::1", seatbeltPort(fixture.tcp6Allowed.address())),
		seatbeltExactIPRule("::1", seatbeltPort(fixture.udp6Allowed.address())),
	}
	policy := func(request validatedProcessRequest) (string, []string, error) {
		generated, definitions, err := seatbeltTransportBaseWithoutOutbound(request)
		if err != nil {
			return "", nil, err
		}
		return generated + "\n(allow network-outbound\n  " + strings.Join(rules, "\n  ") + ")\n", definitions, nil
	}
	return fixture.executeCase(t, "exact_numeric_ip_endpoint", fixture.operations("exact-ip"), policy, minimal)
}

func seatbeltTransportBaseWithoutOutbound(request validatedProcessRequest) (string, []string, error) {
	generated, definitions, err := buildSeatbeltPolicy(request)
	if err != nil {
		return "", nil, err
	}
	generated, err = seatbeltRemovePolicyTextExactlyOnce(generated, seatbeltTransportOutboundRule, "transport outbound rule")
	return generated, definitions, err
}

func seatbeltExactIPRule(host string, port int) string {
	return fmt.Sprintf("(remote ip %q)", net.JoinHostPort(host, strconv.Itoa(port)))
}

func seatbeltPort(address string) int {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		panic(err)
	}
	value, err := strconv.Atoi(port)
	if err != nil {
		panic(err)
	}
	return value
}

func (fixture *seatbeltTransportFixture) executeCase(
	t *testing.T,
	name string,
	operations []seatbeltTransportProbeOperation,
	policy seatbeltPolicyBuilder,
	policyExample string,
) seatbeltTransportCaseEvidence {
	t.Helper()
	evidence := seatbeltTransportCaseEvidence{Name: name, PolicyExample: policyExample}
	request := seatbeltTestRequest(t)
	request.recoveryProofChallenge = make([]byte, RecoveryProofChallengeSize)
	if _, err := io.ReadFull(rand.Reader, request.recoveryProofChallenge); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(seatbeltTransportProbeConfig{Operations: operations})
	if err != nil {
		t.Fatal(err)
	}
	request.arguments = []string{
		"-test.run=^TestSeatbeltTransportProbeHelper$", "--", "transport-parent",
		base64.RawURLEncoding.EncodeToString(config),
	}
	output := &seatbeltBoundedCapture{limit: seatbeltTransportOutputLimit}
	errorOutput := &seatbeltBoundedCapture{limit: seatbeltTransportOutputLimit}
	request.terminal = Terminal{Output: output, ErrorOutput: errorOutput}
	backend := newSeatbeltBackend(seatbeltExecutable)
	backend.policy = policy
	before := fixture.snapshot()
	processContext, cancelProcess := context.WithTimeout(context.Background(), seatbeltTransportProcessDeadline)
	defer cancelProcess()
	process, err := backend.prepare(processContext, request)
	if err != nil {
		evidence.PolicyValidation = seatbeltSandboxErrorCategory(err)
		if processContext.Err() != nil {
			evidence.PolicyValidation = "setup_deadline_exceeded"
			evidence.Conclusion = "sandbox_setup_error_setup_deadline_exceeded"
		} else if evidence.PolicyValidation == string(SandboxPolicyRejected) {
			evidence.Conclusion = "policy_rejected"
		} else {
			evidence.Conclusion = "sandbox_setup_error_" + evidence.PolicyValidation
		}
		if removeErr := os.RemoveAll(request.sessionDirectory); removeErr != nil {
			t.Fatalf("%s remove unused Session after policy rejection: %v", name, removeErr)
		}
		_, statErr := os.Stat(request.sessionDirectory)
		evidence.PhysicalRemoval = errors.Is(statErr, os.ErrNotExist)
		if !evidence.PhysicalRemoval {
			t.Fatalf("%s rejected-policy Session physical removal was not observed: %v", name, statErr)
		}
		return evidence
	}
	evidence.PolicyValidation = "accepted_and_applied_before_target_start"
	if err := process.Start(); err != nil {
		seatbeltAwaitCleanupAfterFailure(t, process, name+" start")
		t.Fatalf("%s process start: %v", name, err)
	}
	waitErr := seatbeltBoundedTransportWait(t, process, name)
	if waitErr != nil {
		t.Fatalf("%s process wait: %v; stderr category=%s", name, waitErr, seatbeltBoundedOutputCategory(errorOutput.String()))
	}
	if output.Exceeded() || errorOutput.Exceeded() {
		t.Fatalf("%s helper output exceeded %d bytes", name, seatbeltTransportOutputLimit)
	}
	var probeOutput seatbeltTransportProbeOutput
	if err := json.Unmarshal(output.Bytes(), &probeOutput); err != nil {
		t.Fatalf("%s decode helper output: %v; output category=%s", name, err, seatbeltBoundedOutputCategory(output.String()))
	}
	evidence.DescendantExecution = probeOutput.ParentPID > 0 && probeOutput.DescendantPID > 0 && probeOutput.ParentPID != probeOutput.DescendantPID
	evidence.ClientOperations = probeOutput.Results
	time.Sleep(seatbeltTransportAbsenceDeadline)
	evidence.ListenerReceipts = fixture.receiptsSince(before)
	evidence.AuthenticatedCleanup, err = VerifySessionCleanupProof(request.sessionDirectory, request.recoveryProofChallenge)
	if err != nil || !evidence.AuthenticatedCleanup {
		t.Fatalf("%s authenticated cleanup = (%v, %v)", name, evidence.AuthenticatedCleanup, err)
	}
	if err := os.RemoveAll(request.sessionDirectory); err != nil {
		t.Fatalf("%s remove settled Session: %v", name, err)
	}
	_, err = os.Stat(request.sessionDirectory)
	evidence.PhysicalRemoval = errors.Is(err, os.ErrNotExist)
	if !evidence.PhysicalRemoval {
		t.Fatalf("%s Session physical removal was not observed: %v", name, err)
	}
	if !evidence.DescendantExecution || !seatbeltCompleteTransportResults(operations, evidence.ClientOperations) {
		evidence.Conclusion = "incomplete_descendant_operation_evidence"
	} else {
		evidence.Conclusion = seatbeltClassifyTransportCase(name, operations, evidence.ClientOperations, evidence.ListenerReceipts)
	}
	return evidence
}

func seatbeltSandboxErrorCategory(err error) string {
	var sandboxErr *SandboxError
	if errors.As(err, &sandboxErr) {
		return string(sandboxErr.Category)
	}
	return "unexpected_error"
}

func seatbeltBoundedOutputCategory(output string) string {
	if output == "" {
		return "empty"
	}
	return "nonempty_" + strconv.Itoa(min(len(output), 4096)) + "_bytes"
}

func seatbeltBoundedTransportWait(t *testing.T, process Process, name string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- process.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(seatbeltTransportProcessDeadline + 2*time.Second):
		_ = process.Signal(syscall.SIGKILL)
	}
	select {
	case err := <-done:
		return errors.Join(fmt.Errorf("%s exceeded bounded wait", name), err)
	case <-time.After(3 * time.Second):
		t.Errorf("%s did not settle after bounded cancellation", name)
		return context.DeadlineExceeded
	}
}

func seatbeltAwaitCleanupAfterFailure(t *testing.T, process Process, name string) {
	t.Helper()
	cleanup, ok := process.(ProcessCleanup)
	if !ok || cleanup.CleanupDone() == nil {
		t.Errorf("%s process does not expose bounded cleanup", name)
		return
	}
	select {
	case <-cleanup.CleanupDone():
	case <-time.After(3 * time.Second):
		t.Errorf("%s cleanup did not complete within its bound", name)
	}
}

func seatbeltClassifyTransportCase(name string, operations []seatbeltTransportProbeOperation, results []seatbeltTransportResult, receipts []seatbeltTransportReceipt) string {
	if !seatbeltCompleteTransportResults(operations, results) {
		return "inconclusive_missing_operation"
	}
	categories := make(map[string]string)
	for _, result := range results {
		categories[result.Operation] = result.Category
	}
	received, correlated := seatbeltCorrelateTransportReceipts(operations, receipts)
	if !correlated {
		return "uncorrelated_listener_receipt"
	}
	switch name {
	case "current_coarse_outbound":
		for _, operation := range []string{"tcp4-allowed", "tcp4-denied", "tcp6-allowed", "tcp6-denied", "udp4-allowed", "udp4-denied", "udp6-allowed", "udp6-denied"} {
			if categories[operation] != "success" || !received[operation] {
				return "coarse_ip_positive_control_incomplete"
			}
		}
		if received["unix-allowed"] || received["unix-denied"] {
			return "unexpected_custom_unix_bypass"
		}
		if categories["unix-allowed"] != "permission_denied" || categories["unix-denied"] != "permission_denied" {
			return "custom_unix_denial_inconclusive"
		}
		return "coarse_ip_outbound_observed_custom_unix_denied"
	case "denied_outbound":
		if len(receipts) != 0 {
			return "unsafe_denied_outbound_bypass"
		}
		for _, operation := range operations {
			if categories[operation.Name] != "permission_denied" {
				return "denied_outbound_inconclusive"
			}
		}
		return "all_probed_outbound_denied"
	case "exact_unix_socket":
		if categories["unix-allowed"] != "success" || !received["unix-allowed"] {
			return "exact_unix_allowance_ineffective"
		}
		if received["unix-denied"] || len(receipts) != 1 {
			return "unsafe_exact_unix_bypass"
		}
		for operation, category := range categories {
			if operation != "unix-allowed" && category != "permission_denied" {
				return "exact_unix_denial_inconclusive"
			}
		}
		return "exact_unix_path_observed"
	case "exact_numeric_ip_endpoint":
		for _, denied := range []string{"tcp4-denied", "tcp6-denied", "udp4-denied", "udp6-denied", "unix-allowed", "unix-denied"} {
			if received[denied] {
				return "unsafe_exact_ip_bypass"
			}
			if categories[denied] != "permission_denied" {
				return "exact_ip_denial_inconclusive"
			}
		}
		for _, allowed := range []string{"tcp4-allowed", "tcp6-allowed", "udp4-allowed", "udp6-allowed"} {
			if categories[allowed] != "success" || !received[allowed] {
				return "exact_ip_allowance_ineffective"
			}
		}
		return "exact_numeric_ip_endpoints_observed"
	default:
		return "unclassified"
	}
}

func seatbeltCorrelateTransportReceipts(operations []seatbeltTransportProbeOperation, receipts []seatbeltTransportReceipt) (map[string]bool, bool) {
	expected := make(map[string]string, len(operations))
	byMarker := make(map[string]string, len(operations))
	for _, operation := range operations {
		if _, duplicate := expected[operation.Name]; duplicate {
			return nil, false
		}
		if operation.Marker == "" {
			return nil, false
		}
		expected[operation.Name] = operation.Marker
		if _, duplicate := byMarker[operation.Marker]; duplicate {
			return nil, false
		}
		byMarker[operation.Marker] = operation.Name
	}
	received := make(map[string]bool, len(receipts))
	for _, receipt := range receipts {
		operation, exists := byMarker[receipt.Marker]
		if !exists || receipt.Listener != operation || received[operation] {
			return nil, false
		}
		received[operation] = true
	}
	return received, true
}

func seatbeltCompleteTransportResults(operations []seatbeltTransportProbeOperation, results []seatbeltTransportResult) bool {
	if len(operations) != len(results) {
		return false
	}
	want := make(map[string]string, len(operations))
	for _, operation := range operations {
		if operation.Name == "" || operation.Marker == "" {
			return false
		}
		if _, duplicate := want[operation.Name]; duplicate {
			return false
		}
		want[operation.Name] = operation.Marker
	}
	for _, result := range results {
		marker, exists := want[result.Operation]
		if !exists || result.Marker != marker {
			return false
		}
		if result.Category == "success" {
			expectedBytes := len(marker)
			for _, operation := range operations {
				if operation.Name == result.Operation && operation.Network != "udp4" && operation.Network != "udp6" {
					expectedBytes++
					break
				}
			}
			if result.BytesWritten != expectedBytes {
				return false
			}
		}
		delete(want, result.Operation)
	}
	return len(want) == 0
}

func (fixture *seatbeltTransportFixture) snapshot() map[string]int {
	snapshot := make(map[string]int, len(fixture.all))
	for _, recorder := range fixture.all {
		snapshot[recorder.name()] = len(recorder.markers())
	}
	return snapshot
}

func (fixture *seatbeltTransportFixture) receiptsSince(before map[string]int) []seatbeltTransportReceipt {
	var receipts []seatbeltTransportReceipt
	for _, recorder := range fixture.all {
		markers := recorder.markers()
		for _, marker := range markers[before[recorder.name()]:] {
			receipts = append(receipts, seatbeltTransportReceipt{Listener: recorder.name(), Marker: marker})
		}
	}
	sort.Slice(receipts, func(i, j int) bool {
		if receipts[i].Listener != receipts[j].Listener {
			return receipts[i].Listener < receipts[j].Listener
		}
		return receipts[i].Marker < receipts[j].Marker
	})
	return receipts
}

func (fixture *seatbeltTransportFixture) waitForNewReceipts(t *testing.T, before map[string]int, want int) []seatbeltTransportReceipt {
	t.Helper()
	deadline := time.Now().Add(seatbeltTransportProbeDeadline)
	for {
		receipts := fixture.receiptsSince(before)
		if len(receipts) >= want {
			return receipts
		}
		if time.Now().After(deadline) {
			return receipts
		}
		time.Sleep(time.Millisecond)
	}
}

type seatbeltTCPRecorder struct {
	label    string
	listener net.Listener
	mutex    sync.Mutex
	received []string
	done     chan struct{}
	once     sync.Once
	readers  sync.WaitGroup
}

func newSeatbeltTCPRecorder(t *testing.T, label, network, address string) *seatbeltTCPRecorder {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatalf("listen %s: %v", label, err)
	}
	recorder := &seatbeltTCPRecorder{label: label, listener: listener, done: make(chan struct{})}
	t.Cleanup(recorder.closeAndWait)
	go recorder.serve()
	return recorder
}

func (recorder *seatbeltTCPRecorder) serve() {
	defer close(recorder.done)
	for {
		connection, err := recorder.listener.Accept()
		if err != nil {
			recorder.readers.Wait()
			return
		}
		recorder.readers.Add(1)
		go recorder.read(connection)
	}
}

func (recorder *seatbeltTCPRecorder) read(connection net.Conn) {
	defer recorder.readers.Done()
	defer connection.Close()
	_ = connection.SetReadDeadline(time.Now().Add(2 * seatbeltTransportProbeDeadline))
	scanner := bufio.NewScanner(io.LimitReader(connection, 4096))
	for scanner.Scan() {
		recorder.mutex.Lock()
		recorder.received = append(recorder.received, scanner.Text())
		recorder.mutex.Unlock()
	}
}

func (recorder *seatbeltTCPRecorder) name() string    { return recorder.label }
func (recorder *seatbeltTCPRecorder) address() string { return recorder.listener.Addr().String() }
func (recorder *seatbeltTCPRecorder) markers() []string {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	return append([]string(nil), recorder.received...)
}
func (recorder *seatbeltTCPRecorder) closeAndWait() {
	recorder.once.Do(func() {
		_ = recorder.listener.Close()
		<-recorder.done
	})
}
func (recorder *seatbeltTCPRecorder) stopped() bool {
	select {
	case <-recorder.done:
		return true
	default:
		return false
	}
}

type seatbeltUDPRecorder struct {
	label      string
	connection *net.UDPConn
	mutex      sync.Mutex
	received   []string
	done       chan struct{}
	once       sync.Once
}

func newSeatbeltUDPRecorder(t *testing.T, label, network, address string) *seatbeltUDPRecorder {
	t.Helper()
	resolved, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		t.Fatalf("resolve %s: %v", label, err)
	}
	connection, err := net.ListenUDP(network, resolved)
	if err != nil {
		t.Fatalf("listen %s: %v", label, err)
	}
	recorder := &seatbeltUDPRecorder{label: label, connection: connection, done: make(chan struct{})}
	t.Cleanup(recorder.closeAndWait)
	go recorder.serve()
	return recorder
}

func (recorder *seatbeltUDPRecorder) serve() {
	defer close(recorder.done)
	buffer := make([]byte, 512)
	for {
		count, _, err := recorder.connection.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		if count > 0 {
			recorder.mutex.Lock()
			recorder.received = append(recorder.received, string(buffer[:count]))
			recorder.mutex.Unlock()
		}
	}
}

func (recorder *seatbeltUDPRecorder) name() string { return recorder.label }
func (recorder *seatbeltUDPRecorder) address() string {
	return recorder.connection.LocalAddr().String()
}
func (recorder *seatbeltUDPRecorder) markers() []string {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()
	return append([]string(nil), recorder.received...)
}
func (recorder *seatbeltUDPRecorder) closeAndWait() {
	recorder.once.Do(func() {
		_ = recorder.connection.Close()
		<-recorder.done
	})
}
func (recorder *seatbeltUDPRecorder) stopped() bool {
	select {
	case <-recorder.done:
		return true
	default:
		return false
	}
}

func (fixture *seatbeltTransportFixture) runInheritedDescriptorCase(t *testing.T) seatbeltInheritedDescriptorEvidence {
	t.Helper()
	evidence := seatbeltInheritedDescriptorEvidence{}
	tcpConnection, err := net.DialTimeout("tcp4", fixture.tcp4Allowed.address(), seatbeltTransportProbeDeadline)
	if err != nil {
		t.Fatal(err)
	}
	defer tcpConnection.Close()
	tcpFile, err := tcpConnection.(*net.TCPConn).File()
	if err != nil {
		t.Fatal(err)
	}
	defer tcpFile.Close()
	udpConnection, err := net.DialTimeout("udp4", fixture.udp4Allowed.address(), seatbeltTransportProbeDeadline)
	if err != nil {
		t.Fatal(err)
	}
	defer udpConnection.Close()
	udpFile, err := udpConnection.(*net.UDPConn).File()
	if err != nil {
		t.Fatal(err)
	}
	defer udpFile.Close()

	tcpPositive := "inherited-tcp-positive-" + seatbeltRandomTransportMarker()
	udpPositive := "inherited-udp-positive-" + seatbeltRandomTransportMarker()
	before := fixture.snapshot()
	if _, err := tcpFile.Write([]byte(tcpPositive + "\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := udpFile.Write([]byte(udpPositive)); err != nil {
		t.Fatal(err)
	}
	receipts := fixture.waitForNewReceipts(t, before, 2)
	evidence.TCPPositiveControl = seatbeltHasMarker(receipts, tcpPositive)
	evidence.UDPPositiveControl = seatbeltHasMarker(receipts, udpPositive)
	if !evidence.TCPPositiveControl || !evidence.UDPPositiveControl {
		t.Fatal("inherited descriptor positive controls did not reach both listeners")
	}

	tcpAttempt := "inherited-tcp-attempt-" + seatbeltRandomTransportMarker()
	udpAttempt := "inherited-udp-attempt-" + seatbeltRandomTransportMarker()
	output := &seatbeltBoundedCapture{limit: seatbeltTransportOutputLimit}
	errorOutput := &seatbeltBoundedCapture{limit: seatbeltTransportOutputLimit}
	command := exec.Command(os.Args[0], "-test.run=^TestSeatbeltTransportProbeHelper$", "--", "descriptor-sealer", "3", "4", tcpAttempt, udpAttempt)
	command.Env = os.Environ()
	command.Stdout = output
	command.Stderr = errorOutput
	command.ExtraFiles = []*os.File{tcpFile, udpFile}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	before = fixture.snapshot()
	if err := command.Start(); err != nil {
		t.Fatalf("start inherited descriptor sealer: %v", err)
	}
	evidence.SealerPID = command.Process.Pid
	if err := seatbeltBoundedCommandWait(command, 8*time.Second); err != nil {
		t.Fatalf("inherited descriptor sealer: %v; stderr category=%s", err, seatbeltBoundedOutputCategory(errorOutput.String()))
	}
	if output.Exceeded() || errorOutput.Exceeded() {
		t.Fatalf("inherited descriptor helper output exceeded %d bytes", seatbeltTransportOutputLimit)
	}
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	var results []seatbeltTransportResult
	for {
		var result seatbeltTransportResult
		decodeErr := decoder.Decode(&result)
		if errors.Is(decodeErr, io.EOF) {
			break
		}
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		results = append(results, result)
	}
	for _, result := range results {
		switch result.Operation {
		case "pre-sealer-tcp":
			evidence.PreSealerTCPPresent = result.Category == "present"
		case "pre-sealer-udp":
			evidence.PreSealerUDPPresent = result.Category == "present"
		case "target-pid":
			evidence.TargetPID, err = strconv.Atoi(result.Category)
			if err != nil {
				t.Fatalf("decode inherited descriptor target pid: %v", err)
			}
		case "inherited-tcp":
			evidence.TargetTCPResult = result.Category
		case "inherited-udp":
			evidence.TargetUDPResult = result.Category
		}
	}
	time.Sleep(seatbeltTransportAbsenceDeadline)
	receipts = fixture.receiptsSince(before)
	evidence.TCPInheritedReceipt = seatbeltHasMarker(receipts, tcpAttempt)
	evidence.UDPInheritedReceipt = seatbeltHasMarker(receipts, udpAttempt)
	evidence.ProcessCleanup = seatbeltTransportProcessGone(evidence.SealerPID) && seatbeltTransportProcessGone(evidence.TargetPID)
	if evidence.PreSealerTCPPresent && evidence.PreSealerUDPPresent &&
		evidence.TargetTCPResult == "bad_descriptor" && evidence.TargetUDPResult == "bad_descriptor" &&
		!evidence.TCPInheritedReceipt && !evidence.UDPInheritedReceipt && evidence.ProcessCleanup {
		evidence.Conclusion = "connected_descriptors_sealed_before_target_exec"
	} else {
		evidence.Conclusion = "unsafe_inherited_descriptor_observation"
	}
	return evidence
}

func seatbeltBoundedCommandWait(command *exec.Cmd, deadline time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(deadline):
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	}
	select {
	case err := <-done:
		return errors.Join(context.DeadlineExceeded, err)
	case <-time.After(3 * time.Second):
		return errors.New("process group did not settle after bounded cancellation")
	}
}

func seatbeltTransportProcessGone(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := unix.Kill(pid, 0)
	return errors.Is(err, syscall.ESRCH)
}

func seatbeltContainsDescriptor(descriptors []int, wanted int) bool {
	for _, descriptor := range descriptors {
		if descriptor == wanted {
			return true
		}
	}
	return false
}

func seatbeltHasMarker(receipts []seatbeltTransportReceipt, marker string) bool {
	for _, receipt := range receipts {
		if receipt.Marker == marker {
			return true
		}
	}
	return false
}

func seatbeltRandomTransportMarker() string {
	contents := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, contents); err != nil {
		panic(err)
	}
	return hex.EncodeToString(contents)
}

func seatbeltNewTransportEvidence(t *testing.T) *seatbeltTransportEvidence {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(contents)
	return &seatbeltTransportEvidence{
		Schema:           "acs.native-seatbelt-transport-research.v1",
		SourceCommit:     seatbeltGitIdentity(t, "HEAD^{commit}"),
		SourceTree:       seatbeltGitIdentity(t, "HEAD^{tree}"),
		NativeJob:        os.Getenv("ACS_NATIVE_TRANSPORT_JOB"),
		OSProductVersion: seatbeltCommandOutput(t, "/usr/bin/sw_vers", "-productVersion"),
		OSBuildVersion:   seatbeltCommandOutput(t, "/usr/bin/sw_vers", "-buildVersion"),
		Architecture:     runtime.GOOS + "/" + runtime.GOARCH,
		HelperSHA256:     hex.EncodeToString(digest[:]),
		Unresolved: []string{
			"Network Extension activation, ordering, provider admission, and standalone Session attribution",
			"real QUIC, DNS hostname and rebinding semantics, redirects, proxy compatibility, and target compatibility",
			"fail-closed mediator lifecycle and comprehensive outbound destination enforcement",
		},
	}
}

func seatbeltGitIdentity(t *testing.T, revision string) string {
	t.Helper()
	return seatbeltCommandOutput(t, "git", "rev-parse", revision)
}

func seatbeltCommandOutput(t *testing.T, name string, arguments ...string) string {
	t.Helper()
	commandContext, cancelCommand := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelCommand()
	command := exec.CommandContext(commandContext, name, arguments...)
	output := &seatbeltBoundedCapture{limit: 4096}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if err != nil {
		t.Fatalf("read bounded native identity %s: %v", filepath.Base(name), err)
	}
	if output.Exceeded() {
		t.Fatalf("read bounded native identity %s: output exceeded 4096 bytes", filepath.Base(name))
	}
	return strings.TrimSpace(output.String())
}

func seatbeltWriteTransportEvidence(t *testing.T, path string, evidence *seatbeltTransportEvidence) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Errorf("create transport evidence directory: %v", err)
		return
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Errorf("create no-overwrite transport evidence: %v", err)
		return
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	encodeErr := encoder.Encode(evidence)
	closeErr := file.Close()
	if encodeErr != nil || closeErr != nil {
		t.Errorf("write transport evidence: %v", errors.Join(encodeErr, closeErr))
	}
}

func seatbeltTransportResearchOutcome(cases []seatbeltTransportCaseEvidence, inherited seatbeltInheritedDescriptorEvidence) string {
	for _, probe := range cases {
		if strings.HasPrefix(probe.Conclusion, "unsafe_") {
			return probe.Conclusion
		}
	}
	if strings.HasPrefix(inherited.Conclusion, "unsafe_") {
		return inherited.Conclusion
	}
	for _, probe := range cases {
		if probe.Conclusion == "policy_rejected" {
			return probe.Name + "_policy_rejected"
		}
		if strings.Contains(probe.Conclusion, "inconclusive") || strings.Contains(probe.Conclusion, "ineffective") ||
			strings.HasPrefix(probe.Conclusion, "unexpected_") || strings.HasPrefix(probe.Conclusion, "sandbox_setup_error_") ||
			probe.Conclusion == "unclassified" {
			return "inconclusive_" + probe.Name + "_" + probe.Conclusion
		}
	}
	if inherited.Conclusion != "connected_descriptors_sealed_before_target_exec" {
		return "inconclusive_inherited_connected_descriptors"
	}
	return "bounded_transport_matrix_observed_no_full_network_decision"
}

func seatbeltTransportDemonstrated(evidence *seatbeltTransportEvidence) []string {
	demonstrated := []string{
		"all disposable TCP, UDP, and Unix listeners were ready, independently reached by exact-marker positive controls, and stopped",
	}
	for _, probe := range evidence.Cases {
		switch probe.Conclusion {
		case "coarse_ip_outbound_observed_custom_unix_denied":
			demonstrated = append(demonstrated, "current coarse Seatbelt outbound behavior for numeric loopback IPv4 and IPv6 TCP and UDP")
		case "all_probed_outbound_denied":
			demonstrated = append(demonstrated, "permission-denied client results plus exact-marker absence under the disposable denied-outbound policy")
		case "exact_unix_path_observed":
			demonstrated = append(demonstrated, "exact disposable Unix-socket path selection with the nonselected path denied")
		case "exact_numeric_ip_endpoints_observed":
			demonstrated = append(demonstrated, "exact numeric loopback IPv4 and IPv6 TCP and UDP endpoint selection")
		case "policy_rejected":
			if probe.Name == "exact_numeric_ip_endpoint" {
				demonstrated = append(demonstrated, "rejection of the recorded minimal numeric-IP endpoint policy by the native policy compiler")
			}
		}
	}
	if evidence.InheritedDescriptors.Conclusion == "connected_descriptors_sealed_before_target_exec" {
		demonstrated = append(demonstrated, "connected TCP and UDP descriptors survived to the contained supervisor and were sealed before target exec")
	}
	return demonstrated
}

func TestSeatbeltTransportClassifierRequiresDeniedOperationEvidence(t *testing.T) {
	names := []string{
		"tcp4-allowed", "tcp4-denied", "tcp6-allowed", "tcp6-denied",
		"udp4-allowed", "udp4-denied", "udp6-allowed", "udp6-denied",
		"unix-allowed", "unix-denied",
	}
	operations := make([]seatbeltTransportProbeOperation, 0, len(names))
	results := make([]seatbeltTransportResult, 0, len(names))
	var receipts []seatbeltTransportReceipt
	for _, name := range names {
		marker := "marker-" + name
		network := "tcp4"
		if strings.HasPrefix(name, "udp") {
			network = "udp4"
		}
		operations = append(operations, seatbeltTransportProbeOperation{Name: name, Network: network, Marker: marker})
		category := "permission_denied"
		written := 0
		if strings.HasSuffix(name, "-allowed") && !strings.HasPrefix(name, "unix") {
			category = "success"
			written = len(marker)
			if network == "tcp4" {
				written++
			}
			receipts = append(receipts, seatbeltTransportReceipt{Listener: name, Marker: marker})
		}
		results = append(results, seatbeltTransportResult{Operation: name, Marker: marker, BytesWritten: written, Category: category})
	}
	if got := seatbeltClassifyTransportCase("exact_numeric_ip_endpoint", operations, results, receipts); got != "exact_numeric_ip_endpoints_observed" {
		t.Fatalf("complete exact endpoint evidence = %q", got)
	}
	for index := range results {
		if results[index].Operation == "tcp4-denied" {
			results[index].Category = "connection_refused"
		}
	}
	if got := seatbeltClassifyTransportCase("exact_numeric_ip_endpoint", operations, results, receipts); got != "exact_ip_denial_inconclusive" {
		t.Fatalf("non-enforcement denied result = %q", got)
	}
}

func TestSeatbeltTransportCorrelationRejectsSwappedPayload(t *testing.T) {
	operations := []seatbeltTransportProbeOperation{
		{Name: "one", Marker: "marker-one"},
		{Name: "two", Marker: "marker-two"},
	}
	receipts := []seatbeltTransportReceipt{
		{Listener: "one", Marker: "marker-two"},
		{Listener: "two", Marker: "marker-one"},
	}
	if _, correlated := seatbeltCorrelateTransportReceipts(operations, receipts); correlated {
		t.Fatal("swapped listener payloads were accepted")
	}
	results := []seatbeltTransportResult{
		{Operation: "one", Marker: "marker-two", Category: "success"},
		{Operation: "two", Marker: "marker-one", Category: "success"},
	}
	if seatbeltCompleteTransportResults(operations, results) {
		t.Fatal("swapped client payloads were accepted")
	}
}

func TestSeatbeltTransportErrorCategoriesRemainDistinct(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("wrapped: %w", syscall.EPERM), "permission_denied"},
		{fmt.Errorf("wrapped: %w", os.ErrDeadlineExceeded), "deadline_exceeded"},
		{fmt.Errorf("wrapped: %w", syscall.ECONNREFUSED), "connection_refused"},
		{fmt.Errorf("wrapped: %w", syscall.ENETUNREACH), "network_unreachable"},
	} {
		if got := seatbeltTransportErrorCategory(test.err); got != test.want {
			t.Errorf("category(%v) = %q, want %q", test.err, got, test.want)
		}
	}
}
