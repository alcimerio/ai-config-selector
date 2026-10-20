package grokcompat

import "testing"

func TestAcceptsOutputAdmitsOnlyTheReviewedRelease(t *testing.T) {
	for _, output := range []string{"grok 1.0.62", "grok 1.0.62\n", "  grok 1.0.62 (1474f9cbdd91)  "} {
		if !AcceptsOutput(output) {
			t.Fatalf("rejected reviewed output %q", output)
		}
	}
	for _, output := range []string{"", "grok 1.0.61", "grok 1.0.62-dev", "grok 1.0.63", "grok 1.0.62 ()", "grok 1.0.62 (1474F9)", "grok 1.0.62 (1474f9cbdd91) extra", "codex-cli 0.156.0"} {
		if AcceptsOutput(output) {
			t.Fatalf("admitted unreviewed output %q", output)
		}
	}
}
