//go:build darwin

package launch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Exercise the real sandbox_check ABI from an unsandboxed parent, independently
// of the supervisor handshake. This also runs under -race: the contained probe
// is the system shell, not a Go binary requiring ThreadSanitizer permissions.
func TestSeatbeltSessionPolicyIdentityNative(t *testing.T) {
	first, firstPolicy, err := newSeatbeltSessionProcesses()
	if err != nil {
		t.Fatal(err)
	}
	second, secondPolicy, err := newSeatbeltSessionProcesses()
	if err != nil {
		t.Fatal(err)
	}
	if firstPolicy == secondPolicy {
		t.Fatal("separate Sessions received the same policy identity")
	}
	for _, processes := range []*seatbeltSessionProcesses{first, second} {
		if matched, err := processes.member(os.Getpid()); err != nil || matched {
			t.Fatalf("unsandboxed parent membership = %v, %v", matched, err)
		}
	}
	const basePolicy = `(version 1)
(deny default)
(allow process-exec)
(allow file-read*)
(allow sysctl-read)
`
	for _, test := range []struct {
		name   string
		policy string
		first  bool
		second bool
	}{
		{name: "first Session", policy: basePolicy + firstPolicy, first: true},
		{name: "second Session", policy: basePolicy + secondPolicy, second: true},
		{name: "neither name allowed", policy: basePolicy},
		{name: "both name and control allowed", policy: `(version 1)(allow default)`},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, seatbeltExecutable, "-p", test.policy, "--", "/bin/sh", "-c", "printf ready; read -r line")
			command.Env = []string{"PATH=" + safeProcessPath}
			command.WaitDelay = time.Second
			input, err := command.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			output, err := command.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var diagnostics bytes.Buffer
			command.Stderr = &diagnostics
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = command.Process.Kill()
				_ = command.Wait()
			}()
			ready := make([]byte, len("ready"))
			if _, err := io.ReadFull(output, ready); err != nil || string(ready) != "ready" {
				_ = command.Process.Kill()
				_ = command.Wait()
				t.Fatalf("policy probe readiness = %q, %v; diagnostics=%q", ready, err, diagnostics.String())
			}
			for _, query := range []struct {
				name      string
				processes *seatbeltSessionProcesses
				want      bool
			}{{"first", first, test.first}, {"second", second, test.second}} {
				if matched, err := query.processes.member(command.Process.Pid); err != nil || matched != query.want {
					t.Errorf("%s Session membership = %v, %v; want %v", query.name, matched, err, query.want)
				}
			}
		})
	}
}

func TestSeatbeltSessionIdentityGatesSupervisorStart(t *testing.T) {
	const proxyPID = 700
	identity := seatbeltBSDInfo{
		PID: 42, PPID: proxyPID, Status: 2, StartSecond: 123,
		UID: uint32(os.Geteuid()), RUID: uint32(os.Geteuid()), SVUID: uint32(os.Geteuid()),
		GID: uint32(os.Getegid()), RGID: uint32(os.Getegid()), SVGID: uint32(os.Getegid()),
	}
	for _, mode := range []string{"verified", "wrong policy", "query failure", "wrong parent", "wrong credentials", "unstable identity"} {
		t.Run(mode, func(t *testing.T) {
			base := &seatbeltSessionIdentityFixture{infoValue: identity}
			switch mode {
			case "wrong parent":
				base.infoValue.PPID++
			case "wrong credentials":
				base.infoValue.SVUID++
			}
			processes := &seatbeltSessionProcesses{
				seatbeltProcessEnumerator: base,
				member: func(int) (bool, error) {
					switch mode {
					case "wrong policy":
						return false, nil
					case "query failure":
						return false, syscall.EINVAL
					case "unstable identity":
						base.infoValue.StartMicrosecond++
					}
					return true, nil
				},
			}
			control, peer := net.Pipe()
			defer control.Close()
			defer peer.Close()
			if err := peer.SetDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			challenge := bytes.Repeat([]byte{0x2a}, seatbeltChallengeSize)
			process := &seatbeltProcess{
				command: &exec.Cmd{Process: &os.Process{Pid: proxyPID}}, control: control,
				challenge: challenge, sessionProcesses: processes, startupDeadline: time.Second,
			}
			type observation struct {
				data []byte
				err  error
			}
			observed := make(chan observation, 1)
			go func() {
				got := make([]byte, len(challenge))
				if _, err := io.ReadFull(peer, got); err != nil || !bytes.Equal(got, challenge) {
					observed <- observation{err: errors.New("invalid challenge")}
					return
				}
				if _, err := peer.Write([]byte{seatbeltSupervisorReady}); err != nil {
					observed <- observation{err: err}
					return
				}
				data, err := io.ReadAll(peer)
				observed <- observation{data: data, err: err}
			}()
			err := process.startSupervisor()
			_ = control.Close()
			got := <-observed
			if got.err != nil {
				t.Fatal(got.err)
			}
			if mode == "verified" {
				if err != nil || !process.sessionIdentityVerified || !bytes.Equal(got.data, []byte{seatbeltSupervisorNoEnvironment, seatbeltSupervisorStart}) {
					t.Fatalf("verified start = %v, identity=%v, protocol=%v", err, process.sessionIdentityVerified, got.data)
				}
			} else if err == nil || process.sessionIdentityVerified || len(got.data) != 0 {
				t.Fatalf("unverified start = %v, identity=%v, protocol=%v", err, process.sessionIdentityVerified, got.data)
			}
		})
	}
}

func TestSeatbeltSessionEnumerationFiltersAndFailsClosed(t *testing.T) {
	failure := errors.New("policy query unavailable")
	for _, queryError := range []error{nil, syscall.ESRCH, failure} {
		base := &seatbeltTestEnumerator{pids: []int{42, 43}}
		processes := &seatbeltSessionProcesses{
			seatbeltProcessEnumerator: base,
			member: func(pid int) (bool, error) {
				if pid == 42 {
					return true, nil
				}
				return false, queryError
			},
		}
		if got, err := processes.allPIDs(); err != nil || !reflect.DeepEqual(got, []int{42}) {
			t.Fatalf("identified members = %v, %v", got, err)
		}
		base.pids = []int{43}
		got, err := processes.allPIDs()
		if len(got) != 0 {
			t.Fatalf("unexpected members: %v", got)
		}
		if queryError == failure && !errors.Is(err, failure) {
			t.Fatalf("inconclusive snapshot proved cleanup: %v", err)
		}
		if queryError != failure && err != nil {
			t.Fatal(err)
		}
	}
}

func TestSeatbeltSessionIdentityRecheckedBeforeSignaling(t *testing.T) {
	original := seatbeltBSDInfo{PID: 42, Status: 2, StartSecond: 123, StartMicrosecond: 456}
	for _, change := range []string{"policy", "pid reuse", "query failure"} {
		t.Run(change, func(t *testing.T) {
			base := &seatbeltSessionIdentityFixture{infoValue: original}
			processes := &seatbeltSessionProcesses{
				seatbeltProcessEnumerator: base,
				member: func(int) (bool, error) {
					switch change {
					case "policy":
						return false, nil
					case "pid reuse":
						base.infoValue.StartMicrosecond++
					case "query failure":
						return false, errors.New("unavailable")
					}
					return true, nil
				},
			}
			if _, err := processes.info(42); err == nil {
				t.Fatal("changed process identity authorized")
			}
		})
	}
}

func TestSeatbeltSessionTracksMembersBeforeProcessInspection(t *testing.T) {
	ledger := newSeatbeltIdentityLedger()
	processes := &seatbeltSessionProcesses{
		seatbeltProcessEnumerator: seatbeltTestEnumerator{pids: []int{42}},
		member:                    func(int) (bool, error) { return true, nil },
		ledger:                    ledger,
	}
	if _, err := processes.allPIDs(); err != nil {
		t.Fatal(err)
	}
	if _, err := processes.info(42); err == nil {
		t.Fatal("unreadable member unexpectedly had a process identity")
	}
	if !ledger.containsPID(42) {
		t.Fatal("unreadable Session member was not retained for fail-closed cleanup")
	}
}

type seatbeltSessionIdentityFixture struct{ infoValue seatbeltBSDInfo }

func (fixture *seatbeltSessionIdentityFixture) allPIDs() ([]int, error) { return []int{42}, nil }
func (fixture *seatbeltSessionIdentityFixture) info(int) (seatbeltBSDInfo, error) {
	return fixture.infoValue, nil
}

func TestSeatbeltParentCleanupAfterMissingProof(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "unproven"}[fail], func(t *testing.T) {
			parent, peer := seatbeltTestDeadlineSocketPair(t)
			_ = peer.Close()
			command := exec.Command("/usr/bin/true")
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			enumerator := seatbeltTestEnumerator{}
			if fail {
				enumerator.allErr = errors.New("enumeration unavailable")
			}
			process := &seatbeltProcess{
				command: command, supervised: true, control: parent,
				challenge:   bytes.Repeat([]byte{0x71}, seatbeltChallengeSize),
				cleanupDone: make(chan struct{}), cleanupUnproven: make(chan struct{}),
				sessionIdentityVerified: true,
				sessionProcesses:        &seatbeltSessionProcesses{seatbeltProcessEnumerator: enumerator},
				recoveryRoot:            filepath.Join(t.TempDir(), "session"),
			}
			if err := os.Mkdir(process.recoveryRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := PrepareSessionCleanupProof(process.recoveryRoot, process.challenge); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				seatbeltCleanupQuarantine.Lock()
				delete(seatbeltCleanupQuarantine.processes, process)
				seatbeltCleanupQuarantine.Unlock()
			})
			err := process.Wait()
			want := errSandboxSessionCleanupRecovered
			if fail {
				want = errSandboxSessionCleanupUnproven
			}
			if err == nil || !strings.Contains(err.Error(), want.Error()) {
				t.Fatalf("cleanup report = %v, want %v", err, want)
			}
			select {
			case <-process.CleanupDone():
				if fail {
					t.Fatal("unverified cleanup released Session")
				}
			default:
				if !fail {
					t.Fatal("verified cleanup retained Session")
				}
			}
			if proven, err := VerifySessionCleanupProof(process.recoveryRoot, process.challenge); err != nil || proven == fail {
				t.Fatalf("durable cleanup proof = %v, %v", proven, err)
			}
		})
	}
}

func TestSeatbeltSessionPolicyIdentityIsRetained(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	request := seatbeltTestRequest(t)
	request.arguments = []string{"-test.run=TestSeatbeltHelperProcess", "--", "verify-policy-retained"}
	settled, err := seatbeltTerminalNativeRun(request)
	if err != nil || !settled {
		t.Fatalf("Session policy retention = %v, %v", settled, err)
	}
}
