package launch

import (
	"context"
	"encoding/binary"
	"fmt"
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
	step := "validate transport and control descriptors"
	defer func() {
		if resultErr != nil {
			resultErr = linuxStepError(errLinuxContainment, "contained init: "+step, resultErr)
		}
	}()
	defer status.Close()
	defer control.Close()
	if w.validate() != nil || status.Fd() < 3 || control.Fd() < 3 || status.Fd() == control.Fd() {
		return errLinuxContainment
	}
	step = "become subreaper"
	if err := linuxBecomeSubreaper(); err != nil {
		return err
	}
	step = "PR_SET_DUMPABLE=0"
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return err
	}
	unix.CloseOnExec(int(status.Fd()))
	unix.CloseOnExec(int(control.Fd()))
	step = "create readiness pipe"
	ready, report, err := os.Pipe()
	if err != nil {
		return err
	}
	defer ready.Close()
	defer report.Close()
	step = "create authorization pipe"
	gate, start, err := os.Pipe()
	if err != nil {
		return err
	}
	defer gate.Close()
	defer start.Close()
	rules := make([]linuxLandlockRule, len(w.Rules))
	for i, rule := range w.Rules {
		rules[i] = linuxLandlockRule{rule.Path, rule.Access}
	}
	terminalFD := -1
	var terminal *linuxPrivateTerminal
	if w.Terminal != nil {
		step = "open private terminal"
		terminal, err = linuxOpenPrivateTerminal(w.Terminal)
		if err != nil {
			return err
		}
		defer terminal.close()
		terminalFD = int(terminal.slave.Fd())
		rules = append(rules, linuxLandlockRule{terminal.slave.Name(), linuxReadFile | linuxWriteFile | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV})
	}
	step = "start restricted child"
	pid, err := linuxStartRestrictedTerminal(rules, w.Executable, w.Argv, env, int(report.Fd()), int(gate.Fd()), terminalFD)
	if err != nil {
		return err
	}
	if terminal != nil {
		_ = terminal.slave.Close()
	}
	_ = report.Close()
	_ = gate.Close()
	// The child cannot pass the gate, and has not been reaped. Its PID cannot
	// be recycled while pidfd_open binds our stable signal reference.
	step = "pidfd_open restricted child"
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		_ = start.Close() // EOF aborts the raw boundary, without numeric-PID kills.
		_, _ = linuxWaitRestricted(pid)
		return err
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
	step = "await restricted child readiness R"
	_ = ready.SetReadDeadline(time.Now().Add(linuxContainmentTimeout))
	var receipt [1]byte
	if _, err := io.ReadFull(ready, receipt[:]); err != nil || receipt[0] != 'R' {
		if err == nil && receipt[0] == 'E' {
			return linuxReadRestrictedFailure(ready)
		}
		select {
		case <-done:
			return fmt.Errorf("readiness byte=%q: %v; child exit=%v wait=%v", receipt[0], err, waitStatus, waitErr)
		default:
			return fmt.Errorf("readiness byte=%q: %v", receipt[0], err)
		}
	}
	step = "report readiness R"
	if _, err := status.Write([]byte{'R'}); err != nil {
		return err
	}
	step = "await start authorization S"
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
	step = "authorize restricted child"
	if _, err := start.Write([]byte{'S'}); err != nil {
		return err
	}
	_ = start.Close()
	_ = ready.SetReadDeadline(time.Now().Add(linuxContainmentTimeout))
	// CLOEXEC status EOF is the restricted boundary's successful exec receipt.
	step = "await restricted exec receipt"
	if n, err := ready.Read(receipt[:]); n != 0 || err != io.EOF {
		if n == 1 && receipt[0] == 'E' {
			return linuxReadRestrictedFailure(ready)
		}
		return errLinuxContainment
	}
	step = "report exec E"
	if _, err := status.Write([]byte{'E'}); err != nil {
		return err
	}
	step = "forward signals and await target exit"
	for {
		select {
		case request := <-requests:
			sig, ok := linuxForwardedSignal(request.code)
			if request.err != nil || !ok {
				return errLinuxContainment
			}
			if terminal != nil && sig == unix.SIGWINCH && terminal.resize() != nil {
				return errLinuxContainment
			}
			if err := unix.PidfdSendSignal(pidfd, sig, nil, 0); err != nil && err != unix.ESRCH {
				return errLinuxContainment
			}
		case <-done:
			if waitErr != nil || !linuxTerminalStatus(waitStatus) {
				return errLinuxContainment
			}
			if terminal != nil && terminal.drain() != nil {
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

// Matches the raw boundary's fixed diagnostic frame. The channel is closed on
// exec; no target-provided strings, arguments, or environment values are read.
func linuxReadRestrictedFailure(reader io.Reader) error {
	var frame [5]byte
	if _, err := io.ReadFull(reader, frame[:]); err != nil {
		return linuxStepError(errLinuxSeal, "read restricted child failure frame", err)
	}
	steps := [...]string{"", "reset signal dispositions", "setsid", "TIOCSCTTY", "dup3 terminal stdio",
		"dup3 status", "dup3 gate", "PR_SET_NO_NEW_PRIVS", "clear ambient capabilities", "capset",
		"landlock_restrict_self", "close_range", "seccomp", "write readiness R", "read start authorization S",
		"close start gate", "restore signal mask", "execve"}
	stage := int(frame[0])
	if stage == 0 || stage >= len(steps) {
		return linuxStepError(errLinuxSeal, "invalid restricted child failure stage", nil)
	}
	var cause error
	if errno := binary.LittleEndian.Uint32(frame[1:]); errno != 0 {
		cause = unix.Errno(errno)
	}
	return linuxStepError(errLinuxSeal, "restricted child: "+steps[stage], cause)
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
