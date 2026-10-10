package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCredentialProviderHelpAndGrammarNeedNoRuntime(t *testing.T) {
	for _, args := range [][]string{
		{"codex", "auth", "provider", "--help"},
		{"help", "codex", "auth", "provider"},
		{"codex", "auth", "provider", "--select"},
		{"codex", "auth", "provider", "--select=private-value"},
		{"codex", "auth", "provider", "--select", "file", "--select", "secret-service"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Setenv("XDG_CONFIG_HOME", "invalid-relative-path")
			var out, errOut bytes.Buffer
			code := (App{Output: &out, ErrorOutput: &errOut}).Run(context.Background(), args)
			if strings.Contains(strings.Join(args, " "), "help") {
				if code != 0 || !strings.Contains(out.String(), "Linux launches remain unavailable") {
					t.Fatalf("help = %d, %q, %q", code, out.String(), errOut.String())
				}
			} else if code != 1 || !strings.Contains(errOut.String(), "acs codex auth provider --help") {
				t.Fatalf("grammar = %d, %q", code, errOut.String())
			}
			if strings.Contains(errOut.String(), "private-value") || strings.Contains(errOut.String(), "invalid-relative-path") {
				t.Fatal("configuration or argument value leaked")
			}
		})
	}
}
