package builder

import (
	"context"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/creack/pty"
	"testing"
	"time"
)

func TestUnifiedCreationPTYSharedTargetsAndCancellation(t *testing.T) {
	for _, cancelCreation := range []bool{false, true} {
		name := "create"
		if cancelCreation {
			name = "cancel"
		}
		t.Run(name, func(t *testing.T) {
			binding, registry := newBuilderFixture(t)
			model := newLoadedSkillsModel(t, "review", registry.NewDraft(), registry, binding, nil)
			saved := make(chan CreationOptions, 1)
			model = model.WithCreation(func(_ context.Context, _ category.Draft, options CreationOptions) (string, error) {
				saved <- options
				return "stored", nil
			}, func(*category.Draft, bool) error { return nil })
			master, terminal, err := pty.Open()
			if err != nil {
				t.Fatal(err)
			}
			defer master.Close()
			defer terminal.Close()
			if err := pty.Setsize(master, &pty.Winsize{Cols: 100, Rows: 30}); err != nil {
				t.Fatal(err)
			}
			capture := &ptyCapture{}
			go func() {
				buffer := make([]byte, 4096)
				for {
					n, err := master.Read(buffer)
					capture.Write(buffer[:n])
					if err != nil {
						return
					}
				}
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type result struct {
				outcome Outcome
				err     error
			}
			done := make(chan result, 1)
			go func() { outcome, err := Run(ctx, model, terminal, terminal); done <- result{outcome, err} }()
			waitForPTYOutput(t, capture, "Choose targets and workspace access")
			if cancelCreation {
				writePTY(t, master, "\x03")
			} else {
				writePTY(t, master, " \x1b[B \x1b[B\x1b[B\r")
				waitForPTYOutput(t, capture, "Targets: Devin, Codex")
				writePTY(t, master, "\x1b[B\r")
				waitForPTYOutput(t, capture, "Confirm: Create an empty Profile?")
				writePTY(t, master, "y")
			}
			select {
			case result := <-done:
				if result.err != nil {
					t.Fatal(result.err)
				}
				if cancelCreation {
					if !result.outcome.Cancelled {
						t.Fatal("cancel outcome missing")
					}
					select {
					case <-saved:
						t.Fatal("cancel saved Profile")
					default:
					}
				} else {
					if !result.outcome.Create {
						t.Fatal("create outcome missing")
					}
					options := <-saved
					if !options.Devin || !options.Codex || options.Development {
						t.Fatalf("options %+v", options)
					}
				}
			case <-time.After(5 * time.Second):
				t.Fatal("builder did not finish")
			}
		})
	}
}
