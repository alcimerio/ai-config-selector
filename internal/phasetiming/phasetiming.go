// Package phasetiming reports opt-in wall-clock durations for Session
// lifecycle phases. It is disabled unless ACS_DEBUG_TIMING=1 is set in the
// environment of the ACS process, and it never reports paths, arguments or
// values: only fixed phase names and durations.
package phasetiming

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// EnvironmentKey enables timing output when set to "1".
const EnvironmentKey = "ACS_DEBUG_TIMING"

var (
	mutex   sync.Mutex
	output  io.Writer = os.Stderr
	enabled           = os.Getenv(EnvironmentKey) == "1"
	now               = time.Now
)

// Start begins timing a phase and returns the function that reports it.
// When timing is disabled the returned function does nothing.
func Start(phase string) func() {
	if !Enabled() {
		return func() {}
	}
	started := now()
	return func() {
		elapsed := now().Sub(started)
		mutex.Lock()
		defer mutex.Unlock()
		fmt.Fprintf(output, "acs timing: %-36s %9.1f ms\n", phase, float64(elapsed.Microseconds())/1000)
	}
}

// Enabled reports whether timing output is active.
func Enabled() bool {
	mutex.Lock()
	defer mutex.Unlock()
	return enabled
}

// setForTest replaces the output and enablement; it returns a restore func.
func setForTest(writer io.Writer, on bool, clock func() time.Time) func() {
	mutex.Lock()
	previousOutput, previousEnabled, previousNow := output, enabled, now
	output, enabled, now = writer, on, clock
	mutex.Unlock()
	return func() {
		mutex.Lock()
		output, enabled, now = previousOutput, previousEnabled, previousNow
		mutex.Unlock()
	}
}
