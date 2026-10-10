package launch

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const linuxContainmentTimeout = 5 * time.Second

// Settled includes durable, authenticated cleanup publication. A target exit
// alone never permits Session deletion or credential finalization.
type linuxSessionResult struct {
	Status  unix.WaitStatus
	Exited  bool
	Settled bool
}

type linuxSupervisedCommand struct {
	command   *exec.Cmd
	status    *os.File // namespace helper -> outer supervisor
	control   *os.File // outer supervisor -> namespace helper
	childEnds []*os.File
	cleanup   *linuxSessionCleanup
}

// Must run in a dedicated re-executed supervisor, outside the target cgroup
// and PID namespace. It must own no unrelated children: subreaping is process
// wide. There is deliberately no production CLI entry point or backend yet.
func linuxSuperviseSession(ctx context.Context, owner *os.File, child linuxSupervisedCommand) (result linuxSessionResult, resultErr error) {
	if child.cleanup == nil {
		return result, errLinuxSettlement
	}
	defer func() {
		if child.cleanup.finish(result.Settled) != nil {
			result.Settled = false
			resultErr = errors.Join(resultErr, errLinuxSettlement)
		}
	}()
	defer owner.Close()
	defer child.status.Close()
	defer child.control.Close()
	// These may have arrived through ExtraFiles in this supervisor. Only the
	// command's explicit descriptor map may survive its next exec.
	for _, file := range []*os.File{owner, child.status, child.control} {
		unix.CloseOnExec(int(file.Fd()))
	}
	closeChildEnds := func() {
		for _, f := range child.childEnds {
			_ = f.Close()
		}
	}
	defer closeChildEnds()
	if child.command.Process != nil || child.command.SysProcAttr != nil || linuxBecomeSubreaper() != nil {
		return result, errLinuxContainment
	}
	g, err := linuxNewSessionCgroup()
	if err != nil {
		// No child has been started. An allocation with uncertain cleanup
		// still quarantines, even though it cannot contain target processes.
		result.Settled = !errors.Is(err, errLinuxSettlement)
		return result, err
	}
	defer g.close()
	if child.cleanup.bindCgroup(g) != nil {
		_ = g.remove()
		return result, errLinuxSettlement
	}
	pidfd := -1
	child.command.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(g.directory.Fd()), PidFD: &pidfd}
	if err := child.command.Start(); err != nil {
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
		reaped, reapErr := linuxReapChildren()
		if reapErr == nil && reaped && g.remove() == nil {
			result.Settled = true
		} else {
			resultErr = errLinuxSettlement
		}
		return result, errors.Join(errLinuxContainment, resultErr)
	}
	closeChildEnds()
	waited := make(chan struct{})
	go func() {
		_ = child.command.Wait()
		close(waited)
	}()
	defer func() {
		_ = child.control.Close()
		result.Settled = linuxSettleSession(linuxSettlementOps{
			kill: g.terminate, empty: g.empty, remove: g.remove,
			leaderDead: func() (bool, error) { return linuxPidfdDead(pidfd) },
			reap:       linuxReapChildren,
		}, waited, time.Now().Add(linuxContainmentTimeout)) == nil
		if !result.Settled {
			// Best effort only; an individual pidfd is never tree-death proof.
			if pidfd >= 0 {
				_ = unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0)
			}
			resultErr = errors.Join(resultErr, errLinuxSettlement)
		}
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
	}()
	if pidfd < 0 {
		return result, errLinuxContainment
	}
	status, err := linuxSessionProtocol(ctx, owner, child.status, child.control, func() error {
		if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
			return errLinuxContainment
		}
		return g.contains(child.command.Process.Pid)
	})
	if err != nil {
		return result, err
	}
	result.Status, result.Exited = status, true
	return result, nil
}

func linuxBecomeSubreaper() error {
	if unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != nil {
		return errLinuxContainment
	}
	var enabled int32
	if unix.Prctl(unix.PR_GET_CHILD_SUBREAPER, uintptr(unsafe.Pointer(&enabled)), 0, 0, 0) != nil || enabled != 1 {
		return errLinuxContainment
	}
	return nil
}

type linuxProtocolMessage struct {
	code   byte
	status unix.WaitStatus
	err    error
}

func linuxProtocolReader(ctx context.Context, reader io.Reader, status bool) <-chan linuxProtocolMessage {
	messages := make(chan linuxProtocolMessage)
	go func() {
		for {
			var frame [5]byte
			_, err := io.ReadFull(reader, frame[:1])
			m := linuxProtocolMessage{code: frame[0], err: err}
			if err == nil && status && m.code == 'X' {
				_, m.err = io.ReadFull(reader, frame[1:])
				m.status = unix.WaitStatus(binary.LittleEndian.Uint32(frame[1:]))
			}
			select {
			case messages <- m:
			case <-ctx.Done():
				return
			}
			if m.err != nil {
				return
			}
		}
	}()
	return messages
}

func linuxForwardedSignal(code byte) (unix.Signal, bool) {
	sig := unix.Signal(code)
	switch sig {
	case unix.SIGHUP, unix.SIGINT, unix.SIGQUIT, unix.SIGTERM, unix.SIGWINCH:
		return sig, true
	default:
		return 0, false
	}
}

func linuxTerminalStatus(status unix.WaitStatus) bool {
	raw := uint32(status)
	return status.Exited() && raw&0xff == 0 && raw <= 0xff00 ||
		status.Signaled() && raw <= 0xff && status.Signal() <= 64
}

// The private owner channel is never inherited by the contained command. The
// namespace helper's channel is closed by the raw exec boundary before target
// execution. Neither channel accepts PIDs, paths, or arbitrary control frames.
func linuxSessionProtocol(ctx context.Context, owner, status, control *os.File, member func() error) (unix.WaitStatus, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	requests, reports := linuxProtocolReader(ctx, owner, false), linuxProtocolReader(ctx, status, true)
	timer := time.NewTimer(linuxContainmentTimeout)
	defer timer.Stop()
	state := 0 // preparing, ready, authorized, executing
	for {
		select {
		case <-ctx.Done():
			return 0, errLinuxContainment
		case <-timer.C:
			return 0, errLinuxContainment
		case m := <-requests:
			if m.err != nil {
				return 0, errLinuxContainment // owner loss, including before start
			}
			if m.code == 'S' && state == 1 {
				state = 2
			} else if _, ok := linuxForwardedSignal(m.code); !ok || state != 3 {
				return 0, errLinuxContainment
			}
			if _, err := control.Write([]byte{m.code}); err != nil {
				return 0, errLinuxContainment
			}
		case m := <-reports:
			if m.err != nil {
				return 0, errLinuxContainment
			}
			switch {
			case m.code == 'R' && state == 0:
				if member() != nil {
					return 0, errLinuxContainment
				}
				state = 1
			case m.code == 'E' && state == 2:
				state = 3
				timer.Stop()
			case m.code == 'X' && state == 3 && linuxTerminalStatus(m.status):
				return m.status, nil
			default:
				return 0, errLinuxContainment
			}
			if _, err := owner.Write([]byte{m.code}); err != nil {
				return 0, errLinuxContainment
			}
		}
	}
}

type linuxSettlementOps struct {
	kill       func() error
	empty      func() (bool, error)
	remove     func() error
	leaderDead func() (bool, error)
	reap       func() (bool, error)
}

func linuxSettleSession(ops linuxSettlementOps, waited <-chan struct{}, deadline time.Time) error {
	if ops.kill() != nil {
		return errLinuxSettlement
	}
	for {
		// Only reap adopted descendants AFTER exec.Cmd has reaped its own
		// child; concurrent wait4(-1) would steal the command's exit status.
		select {
		case <-waited:
			dead, deadErr := ops.leaderDead()
			reaped, reapErr := ops.reap()
			empty, emptyErr := ops.empty()
			if deadErr != nil || reapErr != nil || emptyErr != nil {
				return errLinuxSettlement
			}
			if dead && reaped && empty {
				return ops.remove()
			}
		default:
		}
		if !time.Now().Before(deadline) {
			return errLinuxSettlement
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func linuxPidfdDead(fd int) (bool, error) {
	if fd < 0 {
		return false, errLinuxSettlement
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	for {
		_, err := unix.Poll(poll, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil || poll[0].Revents&(unix.POLLERR|unix.POLLNVAL) != 0 {
			return false, errLinuxSettlement
		}
		return poll[0].Revents&unix.POLLIN != 0, nil
	}
}

func linuxReapChildren() (bool, error) {
	for {
		var status unix.WaitStatus
		pid, err := unix.Wait4(-1, &status, unix.WNOHANG, nil)
		if err == unix.EINTR {
			continue
		}
		if err == unix.ECHILD {
			return true, nil
		}
		if err != nil {
			return false, errLinuxSettlement
		}
		if pid == 0 {
			return false, nil
		}
	}
}
