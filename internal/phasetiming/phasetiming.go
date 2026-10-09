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
	// processStarted approximates ACS process start: package initialization
	// runs before main, after the runtime and linked packages are loaded.
	processStarted = time.Now()
)

// Start begins timing a phase and returns the function that reports it.
// When timing is disabled the returned function does nothing.
func Start(phase string) func() {
	if !Enabled() {
		return func() {}
	}
	started := now()
	return func() {
		mutex.Lock()
		clock := now
		mutex.Unlock()
		report(phase, clock().Sub(started))
	}
}

// SinceProcessStart reports a phase that began when the ACS process started
// (package initialization), for example everything before the first launch
// step. It does nothing when timing is disabled.
func SinceProcessStart(phase string) {
	if !Enabled() {
		return
	}
	mutex.Lock()
	started, clock := processStarted, now
	mutex.Unlock()
	report(phase, clock().Sub(started))
}

func report(phase string, elapsed time.Duration) {
	mutex.Lock()
	defer mutex.Unlock()
	fmt.Fprintf(output, "acs timing: %-36s %9.1f ms\n", phase, float64(elapsed.Microseconds())/1000)
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
