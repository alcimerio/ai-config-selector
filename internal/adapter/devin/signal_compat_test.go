//go:build legacydevin

package devin

// These test-only compatibility helpers preserve the historical white-box
// signal assertions while production signal ownership lives in executor.

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

type signalSupervisor struct {
	forwarded       chan os.Signal
	done            chan struct{}
	cancelPreflight context.CancelFunc
	mutex           sync.Mutex
	child           launch.Process
	pending         os.Signal
	starting        bool
}

func newSignalSupervisor(cancel context.CancelFunc) *signalSupervisor {
	s := &signalSupervisor{forwarded: make(chan os.Signal, 1), done: make(chan struct{}), cancelPreflight: cancel}
	signal.Notify(s.forwarded, os.Interrupt, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGWINCH)
	go s.run()
	return s
}
func (s *signalSupervisor) run() {
	for {
		select {
		case received := <-s.forwarded:
			s.mutex.Lock()
			child := s.child
			if child == nil {
				if s.starting {
					s.pending = received
					s.mutex.Unlock()
					continue
				}
				if received != syscall.SIGWINCH {
					s.pending = received
					s.cancelPreflight()
				}
				s.mutex.Unlock()
				continue
			}
			s.mutex.Unlock()
			_ = child.Signal(received)
		case <-s.done:
			return
		}
	}
}
func (s *signalSupervisor) start(child launch.Process) (bool, error) {
	s.mutex.Lock()
	if s.pending != nil {
		s.mutex.Unlock()
		return false, errors.New("Devin launch interrupted before the interactive process started")
	}
	s.starting = true
	s.mutex.Unlock()
	err := child.Start()
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.starting = false
	if err != nil {
		return false, err
	}
	s.child = child
	pending := s.pending
	s.pending = nil
	if pending == nil {
		return true, nil
	}
	s.mutex.Unlock()
	err = child.Signal(pending)
	s.mutex.Lock()
	if err != nil {
		return true, &launch.SandboxError{Category: launch.SandboxProcessStartFailed}
	}
	return true, nil
}
func (s *signalSupervisor) detach() { s.mutex.Lock(); defer s.mutex.Unlock(); s.child = nil }
func (s *signalSupervisor) stop()   { signal.Stop(s.forwarded); close(s.done) }
func runAttached(process launch.Process, supervisor *signalSupervisor) error {
	started, startErr := supervisor.start(process)
	if !started {
		return startErr
	}
	defer supervisor.detach()
	waitErr := process.Wait()
	if startErr == nil {
		return waitErr
	}
	if waitErr == nil {
		return startErr
	}
	return errors.Join(startErr, &launch.SandboxError{Category: launch.SandboxProcessWaitFailed})
}
