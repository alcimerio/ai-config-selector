package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/profile"
)

type UnifiedProfileBuilder interface {
	BuildUnifiedProfile(context.Context, string, category.Draft, builder.CreationSaveFunc, io.Reader, io.Writer) (builder.Outcome, error)
}

func (app App) createUnifiedProfile(ctx context.Context, name string) int {
	if app.UnifiedBuilder == nil || app.Categories == nil || app.Profiles == nil {
		return app.fail("Profile Builder is unavailable")
	}
	if app.Interactive == nil || !app.Interactive(app.Input, app.Output) {
		return app.fail("create Profile requires interactive stdin and stdout")
	}
	if err := app.Profiles.RecoverContext(ctx); err != nil {
		return app.profileCreateError(name, "recover Profile repository", err)
	}
	if _, err := app.Profiles.Load(name); err == nil {
		return app.fail("destination Profile is occupied; nothing was overwritten")
	} else if !errors.Is(err, os.ErrNotExist) {
		return app.fail("destination could not be safely proven absent; nothing was changed")
	}
	save := func(ctx context.Context, draft category.Draft, options builder.CreationOptions) (string, error) {
		candidate, err := app.Categories.NewProfile(name, draft)
		if err != nil {
			return "", err
		}
		candidate.Overlays = map[string]profile.OverlayPayload{}
		if options.Devin {
			candidate.Overlays["devin"] = profile.OverlayPayload{Version: 1}
		}
		if options.Codex {
			candidate.Overlays["codex"] = profile.OverlayPayload{Version: 1}
		}
		return app.Profiles.CreateContext(ctx, candidate)
	}
	outcome, err := app.UnifiedBuilder.BuildUnifiedProfile(ctx, name, app.Categories.NewDraft(), save, app.Input, app.Output)
	if err != nil {
		return app.profileCreateError(name, "create Profile", err)
	}
	if outcome.Cancelled {
		fmt.Fprintln(app.Output, "Profile creation cancelled.")
		return 130
	}
	if !outcome.Create {
		return app.fail("Profile Builder ended without an outcome")
	}
	fmt.Fprintf(app.Output, "Created Profile %q.\n", name)
	return 0
}
