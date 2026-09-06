package executor

import (
	"github.com/alcimerio/ai-config-selector/internal/session"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type orderedSignalProcess struct {
	starts, waits int
	signals       []os.Signal
}

func (p *orderedSignalProcess) Start() error { p.starts++; return nil }
func (p *orderedSignalProcess) Wait() error  { p.waits++; return nil }
func (p *orderedSignalProcess) Signal(signal os.Signal) error {
	p.signals = append(p.signals, signal)
	return nil
}
func TestInteractiveReservationPreservesTerminationAgainstResize(t *testing.T) {
	for _, termination := range []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT} {
		t.Run(termination.String(), func(t *testing.T) {
			for _, before := range []bool{false, true} {
				t.Run(map[bool]string{false: "resize-after", true: "resize-before-and-after"}[before], func(t *testing.T) {
					created, err := session.Create(filepath.Join(t.TempDir(), "sessions"), t.TempDir(), nil)
					if err != nil {
						t.Fatal(err)
					}
					defer created.Remove()
					supervisor := newDevinSignalSupervisor(func() { t.Error("committed startup canceled preflight") })
					defer supervisor.stop()
					if err := supervisor.reserveInteractive(); err != nil {
						t.Fatal(err)
					}
					raw := &orderedSignalProcess{}
					retained, err := created.RetainUntilProcessDone(raw)
					if err != nil {
						t.Fatal(err)
					}
					// Invoke the production receiver synchronously so every queued signal is
					// consumed before Start, without timing assumptions or a copied handler.
					if before {
						supervisor.handleSignal(syscall.SIGWINCH)
					}
					supervisor.handleSignal(termination)
					supervisor.handleSignal(syscall.SIGWINCH)
					if err := runDevinAttachedReserved(retained, supervisor); err != nil {
						t.Fatal(err)
					}
					if raw.starts != 1 || raw.waits != 1 {
						t.Fatalf("Start/Wait = %d/%d", raw.starts, raw.waits)
					}
					found := false
					for _, signal := range raw.signals {
						if signal == termination {
							found = true
						}
					}
					if !found {
						t.Fatalf("termination %v was lost to resize; replayed %v", termination, raw.signals)
					}
					if err := created.Remove(); err != nil {
						t.Fatal(err)
					}
					if _, err := os.Stat(created.RootDirectory()); !os.IsNotExist(err) {
						t.Fatalf("settled Session remained: %v", err)
					}
				})
			}
		})
	}
}
