package phasetiming

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestDisabledReportsNothing(t *testing.T) {
	var buffer bytes.Buffer
	restore := setForTest(&buffer, false, time.Now)
	defer restore()
	Start("session.create")()
	if buffer.Len() != 0 {
		t.Fatalf("disabled timing wrote %q", buffer.String())
	}
}

func TestEnabledReportsPhaseAndDuration(t *testing.T) {
	var buffer bytes.Buffer
	instants := []time.Time{time.Unix(0, 0), time.Unix(0, int64(1500*time.Microsecond))}
	clock := func() time.Time { value := instants[0]; instants = instants[1:]; return value }
	restore := setForTest(&buffer, true, clock)
	defer restore()
	Start("session.remove")()
	got := buffer.String()
	if !strings.HasPrefix(got, "acs timing: session.remove") || !strings.Contains(got, "1.5 ms") {
		t.Fatalf("timing line = %q", got)
	}
}

func TestSinceProcessStartReportsElapsedSinceInitialization(t *testing.T) {
	var buffer bytes.Buffer
	clock := func() time.Time { return processStarted.Add(2500 * time.Microsecond) }
	restore := setForTest(&buffer, true, clock)
	defer restore()
	SinceProcessStart("acs.startup-to-launch")
	got := buffer.String()
	if !strings.HasPrefix(got, "acs timing: acs.startup-to-launch") || !strings.Contains(got, "2.5 ms") {
		t.Fatalf("timing line = %q", got)
	}
	buffer.Reset()
	restoreDisabled := setForTest(&buffer, false, clock)
	defer restoreDisabled()
	SinceProcessStart("acs.startup-to-launch")
	if buffer.Len() != 0 {
		t.Fatalf("disabled timing wrote %q", buffer.String())
	}
}
