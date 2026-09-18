//go:build darwin

package acceptance_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

type devinNativeRun struct {
	Candidate, Home, Tools, Workspace, Profile, Coordination string
	Driver                                                   *devinDriver
	// Must be backed by an observed pinned-target visible-screen contract.
	// No default historical text/timer readiness or blanket approval exists.
	Input func(frame devinInputFrame, stage string) ([]byte, error)
	// Observe validates actual sandbox Session/process identity from public ACS
	// state and the independently built trampoline before releasing a phase.
	Observe       func(phase string, receipt devinPhaseReceipt) error
	VerifyEffects func() error
}

func devinReadJSON(path string, value any) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > 8192 {
		return errors.New("phase receipt shape")
	}
	dec := json.NewDecoder(io.LimitReader(f, 8193))
	dec.DisallowUnknownFields()
	if e = dec.Decode(value); e != nil {
		return e
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return errors.New("receipt trailing JSON")
	}
	return nil
}

func devinPublicACSFailure(cause error, phase int, released bool, stage, drain string, evidence *devinTerminalEvidence, driverFailure bool) error {
	bytes, chunks, unsafe, text := evidence.snapshot()
	driver := "none"
	if driverFailure {
		driver = "driver-failed"
	}
	if unsafe {
		text = ""
	}
	return fmt.Errorf("%w: public ACS diagnostic phase=%d released=%t input-stage=%s drain=%s driver=%s terminal-bytes=%d terminal-chunks=%d secret=%t terminal=%q", cause, phase, released, stage, drain, driver, bytes, chunks, unsafe, text)
}

// runPublicDevinPTY invokes the installed ACS public interface. It is not a
// print-mode target launcher. Any timeout/forced teardown returns failure.
func runPublicDevinPTY(r devinNativeRun) (err error) {
	if r.Input == nil || r.Observe == nil || r.VerifyEffects == nil || r.Driver == nil {
		return errors.New("native proof contract incomplete")
	}
	r.Driver.mu.Lock()
	r.Driver.submissionRequired = true
	r.Driver.mu.Unlock()
	master, terminal, e := pty.Open()
	if e != nil {
		return e
	}
	// pty.Open wraps a blocking descriptor. Rebind a nonblocking duplicate
	// before os.NewFile registers it with Go's poller, enabling real deadlines.
	fd, dupErr := syscall.Dup(int(master.Fd()))
	if dupErr != nil {
		_ = master.Close()
		_ = terminal.Close()
		return dupErr
	}
	syscall.CloseOnExec(fd)
	if e = syscall.SetNonblock(fd, true); e != nil {
		_ = syscall.Close(fd)
		_ = master.Close()
		_ = terminal.Close()
		return e
	}
	_ = master.Close()
	master = os.NewFile(uintptr(fd), "devin-pollable-pty")
	defer master.Close()
	defer terminal.Close()
	if e = pty.Setsize(master, &pty.Winsize{Rows: 40, Cols: 120}); e != nil {
		return e
	}
	cmd := exec.Command(r.Candidate, "devin", "--profile", r.Profile)
	cmd.Dir = r.Workspace
	cmd.Env = []string{"HOME=" + r.Home, "PATH=" + r.Tools + ":/usr/bin:/bin:/usr/sbin:/sbin", "TERM=xterm", "LANG=en_US.UTF-8", "ACS_NATIVE_MCP_ARGUMENT=acs selected argument", "ACS_NATIVE_MCP_SECRET=acs selected synthetic secret", "ACS_NATIVE_MCP_UNSELECTED=acs unselected synthetic poison"}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = terminal, terminal, terminal
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if e = cmd.Start(); e != nil {
		return e
	}
	_ = terminal.Close()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	reaped := false
	defer func() {
		if !reaped {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			select {
			case <-done:
			case <-time.After(2 * time.Second):
			}
			if err == nil {
				err = errors.New("forced outer process cleanup")
			}
		}
	}()
	chunks := make(chan []byte, 8)
	readDone := make(chan error, 1)
	go func() {
		defer close(chunks)
		for {
			b := make([]byte, 8192)
			n, e := master.Read(b)
			if n > 0 {
				select {
				case chunks <- b[:n]:
				case <-time.After(time.Second):
					readDone <- errors.New("terminal consumer stalled")
					return
				}
			}
			if e != nil {
				readDone <- e
				return
			}
		}
	}()
	screen := newDevinScreen()
	var secretStream devinSecretStream
	var evidence devinTerminalEvidence
	feed := func(b []byte) error {
		if e := secretStream.feed(b); e != nil {
			return e
		}
		if e := evidence.feed(b); e != nil {
			return e
		}
		return screen.feed(b)
	}
	deadline := time.NewTimer(90 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	phase := 0
	readyPIDs := make(map[string]int)
	released := false
	progress := devinInputProgress{stage: "paste"}
	sent := 0
	phases := []string{"skills", "auth", "attached"}
	write := func(b []byte) error {
		if len(b) > 4096 || sent+len(b) > 16384 {
			return errors.New("PTY input cap")
		}
		if e := master.SetWriteDeadline(time.Now().Add(time.Second)); e != nil {
			return fmt.Errorf("PTY write deadline unavailable: %w", e)
		}
		n, e := master.Write(b)
		sent += n
		if e != nil {
			return e
		}
		if n != len(b) {
			return io.ErrShortWrite
		}
		return nil
	}
	considerInput := func() error {
		if phase != 2 || !released || (progress.stage != "paste" && progress.stage != "submit" && progress.stage != "approval" && progress.stage != "exit") {
			return nil
		}
		lines, row, ok := screen.visibleLines()
		approvalReady := progress.stage == "approval" && screen.approvalOnceMenu("fixture", "acs_allowed_echo")
		if !ok && !approvalReady {
			return nil
		}
		modes, e := unix.IoctlGetTermios(int(master.Fd()), unix.TIOCGETA)
		if e != nil {
			return e
		}
		frame := devinInputFrame{Lines: lines, Row: row, Column: screen.terminal.CursorPosition().X, InitialStyles: screen.initialPromptStyles(), TypedStyles: screen.typedPromptStyles(), BracketedPaste: screen.bracketed, ApprovalOnce: approvalReady, Raw: modes.Lflag&(unix.ICANON|unix.ECHO|unix.ISIG|unix.IEXTEN|unix.ECHONL) == 0}
		if !frame.Raw {
			return nil
		}
		if progress.stage == "paste" && !devinInitialPrompt(frame) {
			return nil
		}
		if progress.stage == "submit" && !devinRenderedPrompt(frame, progress.prompt) {
			return nil
		}
		input, e := r.Input(frame, progress.stage)
		if e != nil {
			return e
		}
		if len(input) == 0 {
			return nil
		}
		if progress.stage == "exit" {
			r.Driver.mu.Lock()
			complete := r.Driver.models == 4 && r.Driver.modelWrites == 4 && r.Driver.failure == nil
			r.Driver.mu.Unlock()
			if !complete {
				return errors.New("exit before complete successful protocol")
			}
		}
		submitting := progress.stage == "submit"
		exiting := progress.stage == "exit"
		if e = progress.prepare(frame, input); e != nil {
			return e
		}
		if submitting {
			e = r.Driver.submitInput(func() error { return write(input) })
		} else if exiting {
			e = r.Driver.markGuardedExit()
			if e == nil {
				e = write(input)
			}
			if e != nil {
				r.Driver.fail(e)
			}
		} else {
			e = write(input)
		}
		if e != nil {
			return e
		}
		return nil
	}

	for {
		select {
		case <-deadline.C:
			return errors.New("native public Devin deadline")
		case e := <-done:
			reaped = true
			if e != nil {
				r.Driver.mu.Lock()
				driverFailure := r.Driver.failure != nil
				r.Driver.mu.Unlock()
				drain := drainDevinFailureTerminal(chunks, readDone, &evidence, func(e error) bool {
					return errors.Is(e, io.EOF) || errors.Is(e, syscall.EIO)
				})
				return devinPublicACSFailure(fmt.Errorf("public ACS exit: %w", e), phase, released, progress.stage, drain, &evidence, driverFailure)
			}
			// Drain terminal only after the actual process settles. EIO is Darwin PTY
			// EOF, not permission to infer descendant settlement.
			drainDeadline := time.NewTimer(time.Second)
			terminalEOF := false
			for !terminalEOF {
				select {
				case chunk, ok := <-chunks:
					if ok {
						if e = feed(chunk); e != nil {
							drainDeadline.Stop()
							return e
						}
					} else {
						chunks = nil
					}
				case e := <-readDone:
					if !errors.Is(e, io.EOF) && !errors.Is(e, syscall.EIO) {
						drainDeadline.Stop()
						return fmt.Errorf("terminal did not naturally reach EOF: %w", e)
					}
					terminalEOF = true
				case <-drainDeadline.C:
					return errors.New("PTY natural EOF deadline")
				}
			}
			drainDeadline.Stop()
			if chunks != nil {
				for chunk := range chunks {
					if e = feed(chunk); e != nil {
						return e
					}
				}
			}
			if phase == 2 && released {
				if e = verifyDevinPhaseDone(r.Coordination, "attached", readyPIDs["attached"]); e != nil {
					r.Driver.mu.Lock()
					driverFailure := r.Driver.failure != nil
					r.Driver.mu.Unlock()
					return devinPublicACSFailure(e, phase, released, progress.stage, "already-drained", &evidence, driverFailure)
				}
				if e = inspectDevinCompletedPhase(r.Coordination, phases[phase], r.Driver.home, r.Candidate); e != nil {
					return e
				}
				if e = r.Driver.end(true); e != nil {
					return e
				}
				phase = 3
			}
			if progress.stage != "finished" {
				return errors.New("observed exit interaction incomplete")
			}

			if phase != 3 {
				return errors.New("ACS exited before complete phase receipts")
			}
			if e = r.Driver.finalSuccess(); e != nil {
				return e
			}
			return r.VerifyEffects()
		case b, ok := <-chunks:
			if !ok {
				chunks = nil
				continue
			}
			if e = feed(b); e != nil {
				return e
			}
			screen.mu.Lock()
			replies := screen.replies
			screen.replies = nil
			screen.mu.Unlock()
			for _, reply := range replies {
				if e = write(reply); e != nil {
					return e
				}
			}
			if e = considerInput(); e != nil {
				return e
			}
		case <-tick.C:
			if phase >= 3 {
				continue
			}
			name := phases[phase]
			if !released {
				var receipt devinPhaseReceipt
				e = devinReadJSON(filepath.Join(r.Coordination, name+".ready"), &receipt)
				if os.IsNotExist(e) {
					continue
				}
				if e != nil {
					return e
				}
				readyPIDs[name] = receipt.PID
				if e = r.Observe(name, receipt); e != nil {
					return e
				}
				if e = r.Driver.begin(receipt); e != nil {
					return e
				}
				if e = devinRelease(filepath.Join(r.Coordination, name+".release")); e != nil {
					return e
				}
				released = true
			}
			e = verifyDevinPhaseDone(r.Coordination, name, readyPIDs[name])
			if e == nil {
				if e = inspectDevinCompletedPhase(r.Coordination, phases[phase], r.Driver.home, r.Candidate); e != nil {
					return e
				}
				if e = r.Driver.end(true); e != nil {
					return e
				}
				phase++
				released = false
			} else if !os.IsNotExist(e) {
				r.Driver.mu.Lock()
				driverFailure := r.Driver.failure != nil
				r.Driver.mu.Unlock()
				drain := drainDevinFailureTerminal(chunks, readDone, &evidence, func(err error) bool {
					return errors.Is(err, io.EOF) || errors.Is(err, syscall.EIO)
				})
				return devinPublicACSFailure(e, phase, released, progress.stage, drain, &evidence, driverFailure)
			}

			r.Driver.mu.Lock()
			complete := r.Driver.models == 4 && r.Driver.modelWrites == 4
			models, writes := r.Driver.models, r.Driver.modelWrites
			failure := r.Driver.failure
			r.Driver.mu.Unlock()
			if failure != nil {
				return failure
			}
			if e = progress.observedModel(models, writes); e != nil {
				return e
			}
			if complete && (progress.stage == "approval" || progress.stage == "await-result") {
				progress.stage = "exit"
			}
			if e = considerInput(); e != nil {
				return e
			}
		}
	}
}
