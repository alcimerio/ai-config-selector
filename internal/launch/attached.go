package launch

import (
	"os"
	"os/signal"
	"syscall"
)

// RunAttached starts a prepared process, forwards terminal and termination
// signals received by ACS, and waits for the process to exit. Signal capture is
// installed before Start so resize and termination events cannot be lost in
// the startup handoff.
func RunAttached(process Process) error {
	forwarded := make(chan os.Signal, 1)
	signal.Notify(
		forwarded,
		os.Interrupt,
		syscall.SIGHUP,
		syscall.SIGQUIT,
		syscall.SIGTERM,
		syscall.SIGWINCH,
	)
	defer signal.Stop(forwarded)

	if err := process.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case received := <-forwarded:
				_ = process.Signal(received)
			case <-done:
				return
			}
		}
	}()
	return process.Wait()
}
