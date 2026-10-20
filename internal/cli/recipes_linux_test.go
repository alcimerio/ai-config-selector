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
		args    []string
		phrases []string
	}{
		{"sandbox", []string{"sandbox", "--help"}, []string{"/bin/bash --noprofile --norc", "qualified Linux sandbox", "no unsandboxed fallback"}},
		{"run", []string{"run", "--help"}, []string{"literal argv", "amd64 ELF", "Qualified linux/amd64", "custom ELF search paths"}},
		{"grok", []string{"grok", "--help"}, []string{"Grok is not a qualified Linux target"}},
		{"codex auth", []string{"codex", "auth", "--help"}, []string{"Linux file provider"}},
	} {
		var out, stderr bytes.Buffer
		code := (cli.App{Output: &out, ErrorOutput: &stderr}).Run(context.Background(), tc.args)
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
