package launch

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Runs only in the trusted helper beneath Bubblewrap's PID-namespace init.
// Bubblewrap supplies PID 1 and namespace teardown; this subreaper owns the raw
// restricted child and keeps all signal/status controls outside its FD table.
// The outer supervisor still owns cgroup.kill and the final settlement check.
func linuxRunContainedInit(w linuxLaunchWire, env []string, status, control *os.File) (resultErr error) {
	defer status.Close()
	defer control.Close()
	if w.validate() != nil || status.Fd() < 3 || control.Fd() < 3 || status.Fd() == control.Fd() ||
		linuxBecomeSubreaper() != nil || unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) != nil {
		return errLinuxContainment
	}
	unix.CloseOnExec(int(status.Fd()))
	unix.CloseOnExec(int(control.Fd()))
	ready, report, err := os.Pipe()
	if err != nil {
		return errLinuxContainment
	}
	defer ready.Close()
	defer report.Close()
	gate, start, err := os.Pipe()
	if err != nil {
		return errLinuxContainment
	}
	defer gate.Close()
	defer start.Close()
	rules := make([]linuxLandlockRule, len(w.Rules))
	for i, rule := range w.Rules {
		rules[i] = linuxLandlockRule{rule.Path, rule.Access}
	}
	pid, err := linuxStartRestricted(rules, w.Executable, w.Argv, env, int(report.Fd()), int(gate.Fd()))
	if err != nil {
		return err
	}
	_ = report.Close()
	_ = gate.Close()
	// The child cannot pass the gate, and has not been reaped. Its PID cannot
	// be recycled while pidfd_open binds our stable signal reference.
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		_ = start.Close() // EOF aborts the raw boundary, without numeric-PID kills.
		_, _ = linuxWaitRestricted(pid)
		return errLinuxContainment
	}
	defer unix.Close(pidfd)
	done := make(chan struct{})
	var waitStatus unix.WaitStatus
	var waitErr error
	go func() {
		waitStatus, waitErr = linuxWaitRestricted(pid)
		close(done)
	}()
	defer func() {
		_ = start.Close()
		_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
		select {
		case <-done:
		case <-time.After(linuxContainmentTimeout):
			resultErr = errLinuxContainment
		}
	}()
	_ = ready.SetReadDeadline(time.Now().Add(linuxContainmentTimeout))
	var receipt [1]byte
	if _, err := io.ReadFull(ready, receipt[:]); err != nil || receipt[0] != 'R' {
		return errLinuxContainment
	}
	if _, err := status.Write([]byte{'R'}); err != nil {
		return errLinuxContainment
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	requests := linuxProtocolReader(ctx, control, false)
	timer := time.NewTimer(linuxContainmentTimeout)
	defer timer.Stop()
	select {
	case request := <-requests:
		if request.err != nil || request.code != 'S' {
			return errLinuxContainment
		}
	case <-done:
		return errLinuxContainment
	case <-timer.C:
		return errLinuxContainment
	}
	if _, err := start.Write([]byte{'S'}); err != nil {
		return errLinuxContainment
	}
	_ = start.Close()
	_ = ready.SetReadDeadline(time.Now().Add(linuxContainmentTimeout))
	// CLOEXEC status EOF is the restricted boundary's successful exec receipt.
	if n, err := ready.Read(receipt[:]); n != 0 || err != io.EOF {
		return errLinuxContainment
	}
	if _, err := status.Write([]byte{'E'}); err != nil {
		return errLinuxContainment
	}
	for {
		select {
		case request := <-requests:
			sig, ok := linuxForwardedSignal(request.code)
			if request.err != nil || !ok {
				return errLinuxContainment
			}
			if err := unix.PidfdSendSignal(pidfd, sig, nil, 0); err != nil && err != unix.ESRCH {
				return errLinuxContainment
			}
		case <-done:
			if waitErr != nil || !linuxTerminalStatus(waitStatus) {
				return errLinuxContainment
			}
			var frame [5]byte
			frame[0] = 'X'
			binary.LittleEndian.PutUint32(frame[1:], uint32(waitStatus))
			if _, err := status.Write(frame[:]); err != nil {
				return errLinuxContainment
			}
			return nil
		}
	}
}

func linuxWaitRestricted(pid int) (unix.WaitStatus, error) {
	var status unix.WaitStatus
	for {
		_, err := unix.Wait4(pid, &status, 0, nil)
		if err != unix.EINTR {
			return status, err
		}
	}
}
