//go:build darwin

package launch

import "testing"

func TestSeatbeltUnprovenCleanupSignalsWaitersWithoutClaimingCleanup(t *testing.T) {
	process := &seatbeltProcess{cleanupDone: make(chan struct{}), cleanupUnproven: make(chan struct{})}
	t.Cleanup(func() {
		seatbeltCleanupQuarantine.Lock()
		delete(seatbeltCleanupQuarantine.processes, process)
		seatbeltCleanupQuarantine.Unlock()
	})
	process.quarantineUnprovenCleanup()
	process.quarantineUnprovenCleanup() // idempotent: must not double-close
	select {
	case <-process.CleanupUnproven():
	default:
		t.Fatal("unproven cleanup did not notify waiters")
	}
	select {
	case <-process.CleanupDone():
		t.Fatal("unproven cleanup claimed cleanup completion")
	default:
	}
	seatbeltCleanupQuarantine.Lock()
	_, quarantined := seatbeltCleanupQuarantine.processes[process]
	seatbeltCleanupQuarantine.Unlock()
	if !quarantined {
		t.Fatal("unproven cleanup was not quarantined")
	}
	var _ ProcessCleanupUnproven = sanitizedProcess{process: process}
}
