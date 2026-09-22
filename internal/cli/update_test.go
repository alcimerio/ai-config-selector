package cli

import (
	"bytes"
	"context"
	"github.com/alcimerio/ai-config-selector/internal/selfupdate"
	"strings"
	"testing"
)

func TestUpdateHelpAndGrammarBeforeDependencies(t *testing.T) {
	for _, args := range [][]string{{"update", "--help"}, {"help", "update"}} {
		var out, errs bytes.Buffer
		app := App{Output: &out, ErrorOutput: &errs}
		handled, code := app.RunInformational(args)
		if !handled || code != 0 || !strings.Contains(out.String(), "acs update") {
			t.Fatalf("%v: handled=%t code=%d out=%s err=%s", args, handled, code, out.String(), errs.String())
		}
	}
	for _, args := range [][]string{{"update", "--check", "v0.4.0"}, {"update", "v0.4.0", "v0.5.0"}, {"update", "--unknown"}, {"update", "v0.4.0-rc1"}, {"update", "--check", "--check"}} {
		var out, errs bytes.Buffer
		app := App{Output: &out, ErrorOutput: &errs}
		handled, code := app.RunInformational(args)
		if !handled || code == 0 || out.Len() != 0 {
			t.Fatalf("accepted %v", args)
		}
	}
	var out, errs bytes.Buffer
	app := App{Version: "v0.4.0", Output: &out, ErrorOutput: &errs}
	handled, code := app.RunUpdate(context.Background(), []string{"update", "--check"}, selfupdate.Config{PlatformOS: "linux", PlatformArch: "amd64"})
	if !handled || code == 0 || !strings.Contains(errs.String(), "macOS") {
		t.Fatalf("unexpected platform result %t %d %s", handled, code, errs.String())
	}
}
