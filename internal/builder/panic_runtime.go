package builder

import (
	"sync"

	tea "charm.land/bubbletea/v2"
)

// Callback panics use orderly shutdown instead of Bubble Tea's killed path,
// which can close its cancellable reader while the input loop still uses it.
// Keep only a signal: panic values and stacks can contain private Profile data.
type panicRuntime struct {
	once  sync.Once
	done  chan struct{}
	saves *saveRuntime
}

func (r *panicRuntime) record() {
	if r != nil {
		r.once.Do(func() {
			// Close admission before waking the terminal watcher. An already
			// executing repository call must still settle its own outcome.
			r.saves.stop()
			close(r.done)
		})
	}
}

func (r *panicRuntime) failed() bool {
	if r != nil {
		select {
		case <-r.done:
			return true
		default:
		}
	}
	return false
}

type callbackPanicMsg struct{}

func (m Model) callbackPanic() (tea.Model, tea.Cmd) {
	m.runtimePanics.record()
	m.outcome = Outcome{}
	m.terminalError = tea.ErrProgramPanic
	return m, tea.Quit
}

func stoppedView() tea.View {
	// Diagnostics belong to the caller after terminal restoration.
	view := tea.NewView("")
	view.AltScreen = true
	return view
}
