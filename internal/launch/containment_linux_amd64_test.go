package launch

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func linuxTestSocketpair(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	a, b := os.NewFile(uintptr(pair[0]), "control"), os.NewFile(uintptr(pair[1]), "peer")
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	_ = a.SetDeadline(time.Now().Add(3 * time.Second))
	_ = b.SetDeadline(time.Now().Add(3 * time.Second))
	return a, b
}

func linuxTestByte(t *testing.T, f *os.File, want byte, diagnostics ...func() string) {
	t.Helper()
	if err := linuxReadTestByte(f, want, diagnostics...); err != nil {
		t.Fatal(err)
	}
}

func linuxReadTestByte(reader io.Reader, want byte, diagnostics ...func() string) error {
	var b [1]byte
	if _, err := io.ReadFull(reader, b[:]); err != nil || b[0] != want {
		message := fmt.Sprintf("protocol byte: %q, %v; want %q", b, err, want)
		for _, diagnostic := range diagnostics {
			message += "\n" + diagnostic()
		}
		return errors.New(message)
	}
	return nil
}

func linuxTestWrite(t *testing.T, f *os.File, data ...byte) {
	t.Helper()
	if _, err := f.Write(data); err != nil {
		t.Fatal(err)
	}
}

func linuxTestExitFrame(status unix.WaitStatus) []byte {
	frame := make([]byte, 5)
	frame[0] = 'X'
	binary.LittleEndian.PutUint32(frame[1:], uint32(status))
	return frame
}

func TestLinuxSessionProtocolGatesAndPreservesStatus(t *testing.T) {
	for _, status := range []unix.WaitStatus{0, 42 << 8, unix.WaitStatus(unix.SIGTERM), unix.WaitStatus(unix.SIGQUIT) | 0x80} {
		t.Run(statusString(status), func(t *testing.T) {
			owner, client := linuxTestSocketpair(t)
			report, helper := linuxTestSocketpair(t)
			control, receiver := linuxTestSocketpair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			type outcome struct {
				status unix.WaitStatus
				err    error
			}
			done := make(chan outcome, 1)
			checked := false
			go func() {
				s, err := linuxSessionProtocol(ctx, owner, report, control, func() error { checked = true; return nil })
				done <- outcome{s, err}
			}()
			linuxTestWrite(t, helper, 'R')
			linuxTestByte(t, client, 'R')
			linuxTestWrite(t, client, 'S')
			linuxTestByte(t, receiver, 'S')
			linuxTestWrite(t, helper, 'E')
			linuxTestByte(t, client, 'E')
			linuxTestWrite(t, client, byte(unix.SIGINT))
			linuxTestByte(t, receiver, byte(unix.SIGINT))
			linuxTestWrite(t, helper, linuxTestExitFrame(status)...)
			got := <-done
			if got.err != nil || got.status != status || !checked {
				t.Fatalf("status=%v err=%v membership=%t", got.status, got.err, checked)
			}
		})
	}
}

func statusString(status unix.WaitStatus) string { return strconv.FormatUint(uint64(status), 10) }

func TestLinuxSessionReportsExitOnlyAfterProvenCleanup(t *testing.T) {
	for _, failure := range []string{"", "no-target", "protocol", "unsettled", "terminal", "proof", "owner"} {
		t.Run(failure, func(t *testing.T) {
			cleanup := linuxCleanupFixture(t)
			challenge := append([]byte(nil), cleanup.challenge...)
			owner, client := linuxTestSocketpair(t)
			result := linuxSessionResult{Status: 42 << 8, Exited: true, Settled: true}
			var runErr error
			switch failure {
			case "no-target":
				result.Exited = false
			case "protocol":
				runErr = errLinuxContainment
			case "unsettled":
				result.Settled = false
			case "terminal":
				file, err := os.Open("/dev/null")
				if err != nil {
					t.Fatal(err)
				}
				cleanup.terminal = &linuxTerminalState{file: file, group: unix.Getpgrp()}
			case "proof":
				if err := os.Mkdir(filepath.Join(cleanup.lease.RootDir, sessionCleanupProofFile), 0700); err != nil {
					t.Fatal(err)
				}
			case "owner":
				_ = client.Close()
			}
			type outcome struct {
				result linuxSessionResult
				err    error
			}
			done := make(chan outcome, 1)
			go func() {
				result, err := linuxFinishSession(owner, cleanup, result, runErr)
				done <- outcome{result, err}
			}()
			if failure != "owner" {
				data, err := io.ReadAll(client)
				if err != nil {
					t.Fatal(err)
				}
				if failure == "" {
					if string(data) != "X" {
						t.Fatalf("missing final settlement report: %q", data)
					}
					if proven, err := VerifySessionCleanupProof(cleanup.lease.RootDir, challenge); err != nil || !proven {
						t.Fatalf("owner received completion before durable proof: %t %v", proven, err)
					}
				} else if len(data) != 0 {
					t.Fatalf("failed or unexecuted Session reported completion: %q", data)
				}
			}
			got := <-done
			if got.result.Status != result.Status || got.result.Exited != result.Exited {
				t.Fatalf("target result changed: %+v", got.result)
			}
			wantSettled := failure != "unsettled" && failure != "terminal" && failure != "proof"
			if got.result.Settled != wantSettled || (got.err == nil) != (failure == "" || failure == "no-target") {
				t.Fatalf("cleanup result: %+v %v", got.result, got.err)
			}
		})
	}
}

func TestLinuxSessionRejectsNonCgroupDelegationWithoutArtifacts(t *testing.T) {
	base := t.TempDir()
	parent, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	if g, err := linuxCreateSessionCgroup(parent); g != nil || !errors.Is(err, errLinuxContainment) {
		t.Fatal("ordinary directory accepted as a delegated cgroup")
	}
	if _, err := parent.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("delegation FD leaked: %v", err)
	}
	entries, err := os.ReadDir(base)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed allocation left an artifact")
	}
}

func TestLinuxSessionProtocolRejectsLostOwnerAndInvalidTransitions(t *testing.T) {
	for _, scenario := range []string{"owner-before-ready", "owner-before-start", "owner-running", "helper-loss", "missing-membership", "early-exec", "early-result", "repeat-start", "bad-signal", "stopped-status", "truncated-result", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			owner, client := linuxTestSocketpair(t)
			report, helper := linuxTestSocketpair(t)
			control, receiver := linuxTestSocketpair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := linuxSessionProtocol(ctx, owner, report, control, func() error {
					if scenario == "missing-membership" {
						return errLinuxContainment
					}
					return nil
				})
				done <- err
			}()
			switch scenario {
			case "owner-before-ready":
				_ = client.Close()
			case "helper-loss":
				_ = helper.Close()
			case "missing-membership":
				linuxTestWrite(t, helper, 'R')
			case "early-exec":
				linuxTestWrite(t, helper, 'E')
			case "early-result":
				linuxTestWrite(t, helper, linuxTestExitFrame(0)...)
			case "cancel":
				cancel()
			default:
				linuxTestWrite(t, helper, 'R')
				linuxTestByte(t, client, 'R')
				if scenario == "owner-before-start" {
					_ = client.Close()
					break
				}
				linuxTestWrite(t, client, 'S')
				linuxTestByte(t, receiver, 'S')
				linuxTestWrite(t, helper, 'E')
				linuxTestByte(t, client, 'E')
				switch scenario {
				case "owner-running":
					_ = client.Close()
				case "repeat-start":
					linuxTestWrite(t, client, 'S')
				case "bad-signal":
					linuxTestWrite(t, client, 0xff)
				case "stopped-status":
					linuxTestWrite(t, helper, linuxTestExitFrame(0x137f)...)
				case "truncated-result":
					linuxTestWrite(t, helper, 'X', 0)
					_ = helper.Close()
				}
			}
			if err := <-done; !errors.Is(err, errLinuxContainment) {
				t.Fatalf("unsafe transition accepted: %v", err)
			}
		})
	}
}

func TestLinuxSettlementRequiresEveryIndependentFact(t *testing.T) {
	for _, failure := range []string{"", "kill", "wait", "pidfd", "live-leader", "reap", "live-child", "events", "populated", "remove"} {
		t.Run(failure, func(t *testing.T) {
			cleanup := linuxCleanupFixture(t)
			if err := cleanup.lease.Remove(); err != nil {
				t.Fatal(err)
			}
			waited := make(chan struct{})
			if failure != "wait" {
				close(waited)
			}
			removed := false
			ops := linuxSettlementOps{
				kill: func() error {
					if failure == "kill" {
						return unix.EACCES
					}
					return nil
				},
				leaderDead: func() (bool, error) {
					if failure == "pidfd" {
						return false, unix.EBADF
					}
					return failure != "live-leader", nil
				},
				reap: func() (bool, error) {
					if failure == "reap" {
						return false, unix.ECHILD
					}
					return failure != "live-child", nil
				},
				empty: func() (bool, error) {
					if failure == "events" {
						return false, unix.ENOENT
					}
					return failure != "populated", nil
				},
				remove: func() error {
					if _, err := os.Stat(cleanup.lease.RootDir); err != nil {
						t.Fatal("Session deleted before cgroup settlement")
					}
					if proven, err := VerifySessionCleanupProof(cleanup.lease.RootDir, cleanup.challenge); err != nil || proven {
						t.Fatal("proof published before cgroup removal")
					}
					if failure == "remove" {
						return unix.EBUSY
					}
					removed = true
					return nil
				},
			}
			err := linuxSettleSession(ops, waited, time.Now().Add(-time.Second))
			if (err == nil) != (failure == "") || removed != (failure == "") {
				t.Fatalf("cleanup err=%v removed=%t", err, removed)
			}
			finishErr := cleanup.finish(err == nil)
			if failure == "" {
				if finishErr != nil {
					t.Fatal(finishErr)
				}
				if _, err := os.Stat(cleanup.lease.RootDir); !os.IsNotExist(err) {
					t.Fatal("settled Session was not deleted")
				}
			} else if !errors.Is(finishErr, errLinuxSettlement) {
				t.Fatal("failed settlement released Session")
			} else if _, err := os.Stat(cleanup.lease.RootDir); err != nil {
				t.Fatal("failed settlement deleted Session")
			}
		})
	}
}

func TestLinuxTerminalStatusRejectsMalformedWaitWords(t *testing.T) {
	for _, status := range []unix.WaitStatus{0x80, 0x100f, 0x10000, 0xffff, 0x137f, 65} {
		if linuxTerminalStatus(status) {
			t.Errorf("invalid terminal status accepted: %#x", status)
		}
	}
}

func TestLinuxSettlementWaitsForReapingAndEmptyMembership(t *testing.T) {
	waited := make(chan struct{})
	checks, removed := 0, false
	err := linuxSettleSession(linuxSettlementOps{
		kill:       func() error { close(waited); return nil },
		leaderDead: func() (bool, error) { return true, nil },
		reap:       func() (bool, error) { checks++; return checks > 1, nil },
		empty:      func() (bool, error) { return checks > 2, nil },
		remove: func() error {
			if checks < 3 {
				t.Fatal("removed before adopted children and membership settled")
			}
			removed = true
			return nil
		},
	}, waited, time.Now().Add(time.Second))
	if err != nil || !removed {
		t.Fatalf("deferred settlement: removed=%t err=%v", removed, err)
	}
}

func TestLinuxCgroupEmptyEvidenceFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		events, procs string
		empty, valid  bool
	}{
		{"populated 0\nfrozen 0\n", "", true, true},
		{"populated 1\n", "12\n", false, true},
		{"populated 0\n", "12\n", false, true},
		{"", "", false, false},
		{"populated 2\n", "", false, false},
		{"populated 0\npopulated 1\n", "", false, false},
		{"populated 0 garbage\n", "", false, false},
	} {
		empty, err := linuxCgroupUnpopulated(tc.events, tc.procs)
		if empty != tc.empty || (err == nil) != tc.valid {
			t.Fatalf("%+v: %t %v", tc, empty, err)
		}
	}
}

func TestLinuxCgroupReplacementCannotKillUnrelatedGroup(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "session")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	kill, err := os.OpenFile(filepath.Join(path, "cgroup.kill"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	var s unix.Stat_t
	if err := unix.Fstat(int(dir.Fd()), &s); err != nil {
		t.Fatal(err)
	}
	g := &linuxSessionCgroup{parent: parent, directory: dir, kill: kill, name: "session", device: uint64(s.Dev), inode: s.Ino}
	defer g.close()
	if err := os.Rename(path, path+"-old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(path, "cgroup.kill")
	if err := os.WriteFile(canary, []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := g.terminate(); !errors.Is(err, errLinuxSettlement) {
		t.Fatalf("replacement accepted: %v", err)
	}
	if err := g.remove(); !errors.Is(err, errLinuxSettlement) {
		t.Fatalf("replacement removed: %v", err)
	}
	data, err := os.ReadFile(canary)
	if err != nil || string(data) != "unrelated" {
		t.Fatal("unrelated cgroup was touched")
	}
	if err := os.RemoveAll(path); err != nil {
		t.Fatal(err)
	}
	if err := g.terminate(); !errors.Is(err, errLinuxSettlement) {
		t.Fatal("missing cgroup counted as settled")
	}
}
