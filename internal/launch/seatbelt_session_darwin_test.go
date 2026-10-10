//go:build darwin

package launch

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

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
