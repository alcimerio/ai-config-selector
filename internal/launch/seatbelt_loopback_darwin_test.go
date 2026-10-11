//go:build darwin

package launch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const seatbeltLoopbackProbeRun = "-test.run=^TestSeatbeltLoopbackProbeHelper$"

func TestSeatbeltLoopbackPolicyOrdersDenialAndExceptions(t *testing.T) {
	request := seatbeltTestRequest(t)
	request.runtimeAuthority = DefaultRuntimeAuthority()
	request.runtimeAuthority.LoopbackPorts = []int{8080, 1455}
	policy, _, err := buildSeatbeltPolicy(request)
	if err != nil {
		t.Fatal(err)
	}
	general := strings.Index(policy, "(allow network-outbound\n  (remote ip)")
	deny := strings.Index(policy, `(deny network-outbound (remote ip "localhost:*"))`)
	first := strings.Index(policy, `(allow network-outbound (remote ip "localhost:1455"))`)
	second := strings.Index(policy, `(allow network-outbound (remote ip "localhost:8080"))`)
	if general < 0 || deny <= general || first <= deny || second <= first {
		t.Fatalf("network rule order incorrect: %s", policy)
	}
	if !strings.Contains(policy, `(literal "/private/var/run/mDNSResponder")`) || strings.Contains(policy, "(allow network-inbound") {
		t.Fatal("ordinary policy changed DNS or inbound authority")
	}
	request.runtimeAuthority.LoopbackPorts = nil
	policy, _, err = buildSeatbeltPolicy(request)
	if err != nil || strings.Contains(policy, `(allow network-outbound (remote ip "localhost:`) {
		t.Fatalf("default includes loopback exceptions: %v", err)
	}
	request.runtimeAuthority.LoopbackPorts = []int{1455}
	request.runtimeAuthority.CodexLoginCallback = true
	policy, _, err = buildSeatbeltPolicy(request)
	if err != nil || !strings.Contains(policy, `(allow network-inbound (local ip "localhost:1455"))`) {
		t.Fatalf("missing scoped login callback: %v", err)
	}
}

// Host positive controls distinguish real policy denial from an unavailable
// listener. EPERM/EACCES are required; timeout/refusal is not denial evidence.
func TestSeatbeltDeniesLoopbackExceptSelectedPort(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	for _, endpoint := range []struct{ network, host string }{
		{"tcp4", "127.0.0.1"}, {"tcp6", "::1"}, {"tcp4", "localhost"},
	} {
		t.Run(endpoint.host, func(t *testing.T) {
			first, err := net.Listen(endpoint.network, net.JoinHostPort(endpoint.host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer first.Close()
			other, err := net.Listen(endpoint.network, net.JoinHostPort(endpoint.host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			for _, listener := range []net.Listener{first, other} {
				connection, err := net.DialTimeout(endpoint.network, listener.Addr().String(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				_ = connection.Close()
			}
			port := first.Addr().(*net.TCPAddr).Port
			for _, test := range []struct {
				name          string
				ports         []int
				address, want string
			}{
				{"default-first", nil, net.JoinHostPort(endpoint.host, strconv.Itoa(port)), "denied"},
				{"default-other", nil, net.JoinHostPort(endpoint.host, strconv.Itoa(other.Addr().(*net.TCPAddr).Port)), "denied"},
				{"selected", []int{port}, net.JoinHostPort(endpoint.host, strconv.Itoa(port)), "allowed"},
				{"unlisted", []int{port}, net.JoinHostPort(endpoint.host, strconv.Itoa(other.Addr().(*net.TCPAddr).Port)), "denied"},
			} {
				t.Run(test.name, func(t *testing.T) {
					assertSeatbeltLoopbackDial(t, endpoint.network, test.address, test.ports, test.want)
				})
			}
		})
	}
	t.Run("127.0.0.2", func(t *testing.T) {
		// macOS lo0 need not have this address configured. Reserve ports on
		// 127.0.0.1, but never require a listener or a successful dial on .2.
		first, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer first.Close()
		other, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		address := net.JoinHostPort("127.0.0.2", strconv.Itoa(first.Addr().(*net.TCPAddr).Port))
		connection, err := net.DialTimeout("tcp4", address, time.Second)
		if err == nil {
			_ = connection.Close()
			t.Fatal("unconfigured host control unexpectedly connected")
		}
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			t.Fatalf("host control already denied by policy: %v", err)
		}
		seatbeltDenialEvidence(t, "host control address=%s outcome=%v", address, err)
		t.Run("default", func(t *testing.T) {
			assertSeatbeltLoopbackDial(t, "tcp4", address, nil, "denied")
		})
		t.Run("unlisted", func(t *testing.T) {
			assertSeatbeltLoopbackDial(t, "tcp4", address, []int{other.Addr().(*net.TCPAddr).Port}, "denied")
		})
	})
}

func assertSeatbeltLoopbackDial(t *testing.T, network, address string, ports []int, want string) {
	t.Helper()
	request := seatbeltTestRequest(t)
	request.runtimeAuthority = DefaultRuntimeAuthority()
	request.runtimeAuthority.LoopbackPorts = ports
	result := filepath.Join(request.sessionDirectory, "loopback-result")
	request.arguments = []string{seatbeltLoopbackProbeRun, "--", "dial", result, network, address}
	settled, err := seatbeltTerminalNativeRun(request)
	if !settled || err != nil {
		t.Fatalf("probe failed or cleanup unproven: %v", err)
	}
	contents, err := os.ReadFile(result)
	if err != nil {
		t.Fatal(err)
	}
	seatbeltDenialEvidence(t, "address=%s ports=%v outcome=%s", address, ports, contents)
	if string(contents) != want {
		t.Fatalf("dial outcome %q, want %q", contents, want)
	}
}

func TestSeatbeltManagedCodexCallbackAcceptsLocalhost1455(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	control, err := net.Listen("tcp4", "127.0.0.1:1455")
	if err != nil {
		t.Skipf("callback port unavailable on host: %v", err)
	}
	_ = control.Close()
	request := seatbeltTestRequest(t)
	request.runtimeAuthority = DefaultRuntimeAuthority()
	request.runtimeAuthority.LoopbackPorts = []int{1455}
	request.runtimeAuthority.CodexLoginCallback = true
	ready := filepath.Join(request.sessionDirectory, "callback-ready")
	result := filepath.Join(request.sessionDirectory, "callback-result")
	request.arguments = []string{seatbeltLoopbackProbeRun, "--", "callback", ready, result}
	outcome := make(chan error, 1)
	go func() {
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(ready); err == nil {
				connection, err := net.DialTimeout("tcp4", "127.0.0.1:1455", time.Second)
				if err == nil {
					_ = connection.Close()
				}
				outcome <- err
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		outcome <- context.DeadlineExceeded
	}()
	settled, err := seatbeltTerminalNativeRun(request)
	dialErr := <-outcome
	contents, readErr := os.ReadFile(result)
	if !settled || err != nil || dialErr != nil || readErr != nil || string(contents) != "accepted" {
		t.Fatalf("callback outcome=%q settled=%v run=%v dial=%v read=%v", contents, settled, err, dialErr, readErr)
	}
	seatbeltDenialEvidence(t, "managed Codex localhost:1455 callback accepted; cleanup proven")
}

func TestSeatbeltLoopbackProbeHelper(t *testing.T) {
	var args []string
	for i, arg := range os.Args {
		if arg == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	if len(args) == 0 {
		return
	}
	if len(args) == 4 && args[0] == "dial" {
		connection, err := net.DialTimeout(args[2], args[3], time.Second)
		result := "allowed"
		if err == nil {
			_ = connection.Close()
		} else if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			result = "denied"
		} else {
			result = fmt.Sprintf("inconclusive: %v", err)
		}
		if err := os.WriteFile(args[1], []byte(result), 0600); err != nil {
			os.Exit(91)
		}
		os.Exit(0)
	}
	if len(args) == 3 && args[0] == "callback" {
		listener, err := net.Listen("tcp4", "127.0.0.1:1455")
		if err != nil {
			_ = os.WriteFile(args[2], []byte(err.Error()), 0600)
			os.Exit(92)
		}
		_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
		if err := os.WriteFile(args[1], []byte("ready"), 0600); err != nil {
			os.Exit(93)
		}
		connection, err := listener.Accept()
		if err != nil {
			_ = os.WriteFile(args[2], []byte(err.Error()), 0600)
			os.Exit(94)
		}
		_ = connection.Close()
		_ = listener.Close()
		if err := os.WriteFile(args[2], []byte("accepted"), 0600); err != nil {
			os.Exit(95)
		}
		os.Exit(0)
	}
	os.Exit(125)
}
