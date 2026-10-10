package cli_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/cli"
)

func TestLinuxRecipeHelpKeepsProductionAdmissionClosed(t *testing.T) {
	for _, tc := range []struct {
		command string
		phrases []string
	}{
		{"sandbox", []string{"/bin/bash --noprofile --norc", "Production Linux launches remain disabled", "no CLI or environment bypass"}},
		{"run", []string{"literal argv", "amd64 ELF", "Production Linux launches remain disabled", "custom ELF search paths"}},
	} {
		var out, stderr bytes.Buffer
		code := (cli.App{Output: &out, ErrorOutput: &stderr}).Run(context.Background(), []string{tc.command, "--help"})
		if code != 0 || stderr.Len() != 0 {
			t.Fatalf("help: %d %q", code, stderr.String())
		}
		for _, phrase := range tc.phrases {
			if !strings.Contains(out.String(), phrase) {
				t.Errorf("%s help missing %q", tc.command, phrase)
			}
		}
	}
}
