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

func TestSavePanicQuitsWithUnknownOutcome(t *testing.T) {
	for _, tracked := range []bool{false, true} {
		name := "model"
		if tracked {
			name = "runtime"
		}
		for _, payload := range []struct {
			name  string
			value any
		}{
			{name: "private text", value: "private save callback detail"},
			{name: "nil"},
			{name: "panicking String method", value: panicStringer{}},
			{name: "claimed commit", value: &profilerepo.OutcomeError{Outcome: profilerepo.Outcome{State: profilerepo.Committed}, Err: errors.New("private save callback detail")}},
		} {
			t.Run(name+"/"+payload.name, func(t *testing.T) {
				binding, registry := newBuilderFixture(t)
				model := newLoadedSkillsModel(t, "panic", registry.NewDraft(), registry, binding, nil)
				const privatePayload = "private save callback detail"
				var saveContext context.Context
				model = model.WithSaver(func(ctx context.Context, _ category.Draft) (string, error) {
					saveContext = ctx
					panic(payload.value)
				})
				if tracked {
					model.runtimeSaves = &saveRuntime{}
				}
				started, save := model.startSave()
				var completion tea.Msg
				func() {
					returned := false
					defer func() {
						if !returned {
							_ = recover()
							t.Fatal("save panic escaped to Bubble Tea's killed shutdown")
						}
					}()
					completion = save()
					returned = true
				}()
				finished, quit := started.Update(completion)
				model = finished.(Model)
				if model.outcome.Create || model.outcome.Cancelled || quit == nil {
					t.Fatalf("panic became success, cancellation, or retry: %#v", model.outcome)
				}
				if _, ok := quit().(tea.QuitMsg); !ok {
					t.Fatal("panic did not request orderly shutdown")
				}
				assertUnknownSavePanic(t, model.terminalError)
				if strings.Contains(model.terminalError.Error(), privatePayload) {
					t.Fatal("panic payload was exposed")
				}
				if saveContext.Err() != context.Canceled {
					t.Fatal("panicking saver retained an active context")
				}
				if tracked {
					settled := model.runtimeSaves.settle()
					if settled == nil || settled.path != "" {
						t.Fatal("panic settlement was lost or fabricated a path")
					}
					assertUnknownSavePanic(t, settled.err)
				}
			})
		}
	}
}

type panicStringer struct{}

func (panicStringer) String() string { panic("panic payload must not be formatted") }

func assertUnknownSavePanic(t *testing.T, err error) {
	t.Helper()
	var transaction *profilerepo.OutcomeError
	if !errors.Is(err, tea.ErrProgramPanic) || !errors.As(err, &transaction) || transaction.Outcome.State != profilerepo.Unknown || !transaction.Outcome.RecoveryRequired {
		t.Fatalf("panic lost its unknown/recovery-required outcome: %v", err)
	}
}
