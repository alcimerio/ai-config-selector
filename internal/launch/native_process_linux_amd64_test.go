package launch

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const linuxNativeDiagnosticLimit = 32 << 10

// Reap exactly once, including when a protocol assertion fails. Waiting before
// reading diagnostics lets the supervisor finish cleanup and flush its error.
type linuxNativeProcess struct {
	*exec.Cmd
	done   chan struct{}
	err    error
	output []func() string
}

func linuxNativeStartCommand(t *testing.T, cmd *exec.Cmd, diagnostics ...func() string) *linuxNativeProcess {
	t.Helper()
	var output linuxRecipeOutput
	if cmd.Stdout == nil {
		cmd.Stdout = &output
	}
	if cmd.Stderr == nil {
		cmd.Stderr = &output
	}
	// A broken helper must not leave Wait stuck on an inherited output pipe.
	cmd.WaitDelay = linuxContainmentTimeout
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &linuxNativeProcess{Cmd: cmd, done: make(chan struct{}), output: append([]func() string{output.String}, diagnostics...)}
	go func() { p.err = cmd.Wait(); close(p.done) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		select {
		case <-p.done:
		case <-time.After(2 * linuxContainmentTimeout):
			t.Error("native helper did not exit after cleanup kill")
		}
	})
	return p
}

func (p *linuxNativeProcess) Wait() error {
	<-p.done
	return p.err
}

func (p *linuxNativeProcess) diagnostics() string {
	var result strings.Builder
	select {
	case <-p.done:
		fmt.Fprintf(&result, "supervisor exit=%v; wait=%v", p.ProcessState, p.err)
	case <-time.After(2 * linuxContainmentTimeout):
		result.WriteString("supervisor still running; exit status unavailable after cleanup deadline")
	}
	for _, read := range p.output {
		if output := read(); output != "" {
			if len(output) > linuxNativeDiagnosticLimit {
				output = output[:linuxNativeDiagnosticLimit] + "\n[diagnostics truncated]"
			}
			fmt.Fprintf(&result, "\nstderr/stdout: %s", output)
		}
	}
	return result.String()
}

func linuxNativeReadLogs(paths ...string) string {
	var result strings.Builder
	for _, path := range paths {
		file, err := os.Open(path)
		if os.IsNotExist(err) {
			continue // Setup may have failed before creating the target log.
		}
		if err != nil {
			fmt.Fprintf(&result, "%s: %v\n", path, err)
			continue
		}
		data, err := io.ReadAll(io.LimitReader(file, linuxNativeDiagnosticLimit))
		_ = file.Close()
		fmt.Fprintf(&result, "%s: %s (read error: %v)\n", path, data, err)
	}
	return result.String()
}

// Only used after a failed assertion, when no normal test reader is using the
// PTY. Poll avoids blocking on the parent's still-open copy of the slave.
func linuxNativePTYDiagnostics(master *os.File) string {
	if master == nil {
		return ""
	}
	var result strings.Builder
	for result.Len() < linuxNativeDiagnosticLimit {
		ready := []unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}
		if _, err := unix.Poll(ready, 0); err != nil || ready[0].Revents&unix.POLLIN == 0 {
			break
		}
		var data [4096]byte
		n, err := master.Read(data[:])
		result.Write(data[:n])
		if err != nil || n == 0 {
			break
		}
	}
	return result.String()
}
