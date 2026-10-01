package builder

import (
	"context"
	"errors"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
)

func TestCallbackPanicsStopRuntimeBeforeFurtherSaves(t *testing.T) {
	for _, site := range []string{"discovery", "loaded", "editor", "prepare", "reload", "view"} {
		t.Run(site, func(t *testing.T) {
			binding, registry := newBuilderFixture(t)
			model := newLoadedSkillsModel(t, "panic", registry.NewDraft(), registry, binding, nil)
			gate := &saveRuntime{}
			model.runtimeSaves = gate
			model.runtimePanics = &panicRuntime{done: make(chan struct{}), saves: gate}
			message := tea.Msg(tea.KeyPressMsg(tea.Key{Code: tea.KeyEnter}))
			switch site {
			case "discovery":
				model.editors[0].registration.discover = func(context.Context) (any, error) { panic(nil) }
				message = model.discoveryCommand(0)()
			case "loaded":
				model.editors[0].loadState = loading
				model.editors[0].registration.loaded = func(Editor, any) (Editor, error) { panic(panicStringer{}) }
				message = discoveryCompletedMsg{categoryID: "skills"}
			case "editor":
				model.screen = categoryScreen
				model.editors[0].editor = panickingEditor{Editor: model.editors[0].editor, update: true}
			case "prepare":
				model.overviewCursor = 1
				model.mutation = &MutationOptions{Prepare: func(category.Draft) (PreparedMutation, error) { panic(panicStringer{}) }}
			case "reload":
				model.screen = reloadScreen
				model.mutation = &MutationOptions{Reload: func(context.Context) (category.Draft, error) { panic(panicStringer{}) }}
				message = tea.KeyPressMsg(tea.Key{Code: 'y', Text: "y"})
			case "view":
				model.screen = categoryScreen
				model.editors[0].editor = panickingEditor{Editor: model.editors[0].editor}
				if view := model.View(); !view.AltScreen || view.Content != stoppedView().Content {
					t.Fatal("view panic did not produce the safe terminal view")
				}
			}
			completed, quit := model.Update(message)
			model = completed.(Model)
			if !errors.Is(model.terminalError, tea.ErrProgramPanic) || quit == nil || !model.runtimePanics.failed() {
				t.Fatalf("callback panic did not request fatal shutdown: %v", model.terminalError)
			}
			if _, ok := quit().(tea.QuitMsg); !ok {
				t.Fatal("callback panic did not request normal Quit")
			}
			if model.outcome.Create || model.outcome.Cancelled {
				t.Fatal("callback panic became success or cancellation")
			}
			if view := model.View(); view.Content != stoppedView().Content {
				t.Fatal("fatal redraw retried callback rendering")
			}
			result := gate.execute(context.Background(), model.draft, func(context.Context, category.Draft) (string, error) {
				t.Fatal("callback panic admitted a late save")
				return "", nil
			})
			if !errors.Is(result.err, context.Canceled) {
				t.Fatal("fatal runtime save gate stayed open")
			}
		})
	}
}

type panickingEditor struct {
	Editor
	update bool
}

func (editor panickingEditor) WithDraft(draft category.Draft) Editor {
	editor.Editor = editor.Editor.WithDraft(draft)
	return editor
}

func (editor panickingEditor) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if editor.update {
		panic("private callback detail")
	}
	return editor.Editor.Update(message)
}

func (editor panickingEditor) View() tea.View {
	if !editor.update {
		panic("private callback detail")
	}
	return editor.Editor.View()
}

func TestCallbackPanicDuringSettlementPreservesRepositoryOutcome(t *testing.T) {
	for _, state := range []profilerepo.State{profilerepo.Committed, profilerepo.Unknown} {
		t.Run(string(state), func(t *testing.T) {
			_, registry := newBuilderFixture(t)
			draft := registry.NewDraft()
			gate := &saveRuntime{}
			panics := &panicRuntime{done: make(chan struct{}), saves: gate}
			entered, cancelled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			go gate.execute(context.Background(), draft, func(ctx context.Context, _ category.Draft) (string, error) {
				close(entered)
				<-ctx.Done()
				close(cancelled)
				<-release
				if state == profilerepo.Committed {
					return "saved", nil
				}
				return "", &profilerepo.OutcomeError{Outcome: profilerepo.Outcome{State: state, RecoveryRequired: true}, Err: errors.New("repository outcome unknown")}
			})
			<-entered
			type result struct {
				outcome Outcome
				err     error
			}
			finished := make(chan result, 1)
			go func() {
				outcome, err := settleRuntime(Outcome{Cancelled: true}, context.Canceled, gate, panics)
				finished <- result{outcome, err}
			}()
			<-cancelled
			// The terminal has already quit; a concurrent discovery callback
			// panics while settlement still waits for the repository.
			panics.record()
			select {
			case <-finished:
				t.Fatal("panic let shutdown outpace the repository")
			default:
			}
			close(release)
			got := <-finished
			var transaction *profilerepo.OutcomeError
			if !errors.Is(got.err, tea.ErrProgramPanic) || !errors.As(got.err, &transaction) || transaction.Outcome.State != state || got.outcome.Cancelled {
				t.Fatalf("panic lost the repository's outcome: %#v %v", got.outcome, got.err)
			}
			if state == profilerepo.Committed {
				if !got.outcome.Create || got.outcome.Path != "saved" || transaction.Outcome.RecoveryRequired {
					t.Fatal("panic lost a known commit or invented cleanup uncertainty")
				}
			} else if got.outcome.Create || !transaction.Outcome.RecoveryRequired {
				t.Fatal("panic changed an unknown outcome")
			}
		})
	}
}

func TestCallbackPanicDoesNotResurrectHandledSaveFailure(t *testing.T) {
	_, registry := newBuilderFixture(t)
	gate := &saveRuntime{}
	oldFailure := errors.New("already handled save failure")
	result := gate.execute(context.Background(), registry.NewDraft(), func(context.Context, category.Draft) (string, error) { return "", oldFailure })
	gate.acknowledge(result)
	panics := &panicRuntime{done: make(chan struct{}), saves: gate}
	panics.record()
	outcome, err := settleRuntime(Outcome{Cancelled: true}, nil, gate, panics)
	if outcome.Cancelled || outcome.Create || !errors.Is(err, tea.ErrProgramPanic) || strings.Contains(err.Error(), oldFailure.Error()) {
		t.Fatalf("panic returned stale cancellation or save failure: %#v %v", outcome, err)
	}
}

func TestCallbackPanicWithoutRuntimeReturnsFatalMessage(t *testing.T) {
	binding, registry := newBuilderFixture(t)
	model := newLoadedSkillsModel(t, "panic", registry.NewDraft(), registry, binding, nil)
	model.editors[0].registration.discover = func(context.Context) (any, error) { panic(nil) }
	completed, quit := model.Update(model.discoveryCommand(0)())
	if !errors.Is(completed.(Model).terminalError, tea.ErrProgramPanic) || quit == nil {
		t.Fatal("direct model discovery panic was not fatal")
	}
	model.screen = categoryScreen
	model.editors[0].editor = panickingEditor{Editor: model.editors[0].editor}
	if view := model.View(); !view.AltScreen || view.Content != "" {
		t.Fatal("direct view exposed a diagnostic before terminal restoration")
	}
}
