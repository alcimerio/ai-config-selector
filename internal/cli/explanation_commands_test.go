package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestExplanationGrammarAcceptsReorderedIntentSpecificFlags(t *testing.T) {
	for _, arguments := range [][]string{
		{"explain", "sandbox", "--json", "--profile", "example", "--check-native-readiness"},
		{"explain", "devin", "--check-native-readiness", "--profile", "example", "--json"},
		{"explain", "codex", "--json", "--auth", "work", "--profile", "example", "--check-native-readiness"},
		{"explain", "run", "--json", "--profile", "example", "--check-native-readiness", "--", "/usr/bin/true", "--json"},
	} {
		if _, problem := parseCommand(arguments); problem != "" {
			t.Errorf("parse %q: %s", arguments, problem)
		}
	}
}

func TestExplanationGrammarRejectsCrossIntentAndDigestFlags(t *testing.T) {
	for _, arguments := range [][]string{
		{"explain", "sandbox", "--profile", "example", "--auth", "work"},
		{"explain", "devin", "--profile", "example", "--expect-authority-digest", "sha256:" + strings.Repeat("0", 64)},
		{"explain", "codex", "--profile", "example", "--", "/usr/bin/true"},
		{"explain", "run", "--profile", "example", "/usr/bin/true"},
		{"sandbox", "--profile", "example", "--json"},
		{"run", "--profile", "example", "--check-native-readiness", "--", "/usr/bin/true"},
		{"devin", "--profile", "example", "--expect-authority-digest", "sha256:" + strings.Repeat("A", 64)},
	} {
		if _, problem := parseCommand(arguments); problem == "" {
			t.Errorf("accepted invalid grammar %q", arguments)
		}
	}
}

func TestExplainRunHelpDocumentsLiteralBoundaryWithoutDependencies(t *testing.T) {
	var stdout, stderr bytes.Buffer
	app := App{Output: &stdout, ErrorOutput: &stderr}
	if handled, code := app.RunInformational([]string{"explain", "run", "--help"}); !handled || code != 0 {
		t.Fatalf("handled=%v code=%d stderr=%q", handled, code, stderr.String())
	}
	for _, marker := range []string{"one required -- boundary", "one literal child argv", "--check-native-readiness", "--json"} {
		if !strings.Contains(stdout.String(), marker) {
			t.Errorf("help omitted %q: %s", marker, stdout.String())
		}
	}
}
