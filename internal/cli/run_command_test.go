package cli

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestRunGrammarPreservesLiteralTailAndReorderedFlags(t *testing.T) {
	inv, problem := parseCommand([]string{"run", "--dry-run", "--profile", "review", "--", "/usr/bin/git", "diff", "--", "space path", "", "-x"})
	if problem != "" {
		t.Fatal(problem)
	}
	want := []string{"/usr/bin/git", "diff", "--", "space path", "", "-x"}
	if inv.command.path != "run" || inv.value != "review" || !inv.enabled || !reflect.DeepEqual(inv.arguments, want) {
		t.Fatalf("parsed invocation = %#v", inv)
	}
}

func TestRunGrammarFailsClosedBeforeDiscovery(t *testing.T) {
	tests := [][]string{
		{"run", "--profile", "review", "/bin/true"},
		{"run", "--profile", "review", "--"},
		{"run", "--profile", "review", "--", "--"},
		{"run", "--profile", "../private", "--", "/bin/true"},
		{"run", "--profile", "review", "--profile", "other", "--", "/bin/true"},
		{"run", "--unknown", "--profile", "review", "--", "/bin/true"},
		{"run", "--profile", "review", "--", "nested/tool"},
		{"run", "--profile", "review", "--", "tool", "private\x00argument"},
	}
	for _, args := range tests {
		if _, problem := parseCommand(args); problem == "" {
			t.Fatalf("accepted %q", args)
		} else if strings.Contains(problem, "private") {
			t.Fatalf("diagnostic leaked private input: %q", problem)
		}
		if GenericRunRequested(args) {
			t.Fatalf("invalid invocation reached runtime assembly: %q", args)
		}
	}
}

func TestRunHelpDoesNotRequireCommandBoundary(t *testing.T) {
	inv, problem := parseCommand([]string{"run", "--help"})
	if problem != "" || !inv.help {
		t.Fatalf("help parse = %#v, %q", inv, problem)
	}
}

func TestRunHelpDescribesTheLiteralBoundary(t *testing.T) {
	var output bytes.Buffer
	app := App{Output: &output, ErrorOutput: &bytes.Buffer{}}
	if handled, code := app.RunInformational([]string{"run", "--help"}); !handled || code != 0 {
		t.Fatalf("help = (%v, %d)", handled, code)
	}
	for _, marker := range []string{"exactly one required -- boundary", "later -- belongs to the child", "implicit shell"} {
		if !strings.Contains(output.String(), marker) {
			t.Fatalf("run help omitted %q: %s", marker, output.String())
		}
	}
}

func FuzzRunGrammarPreservesChildArgumentElements(f *testing.F) {
	f.Add("space value", "")
	f.Add("--", "*.go")
	f.Add("$HOME", "-leading-dash")
	f.Fuzz(func(t *testing.T, first, second string) {
		inv, problem := parseCommand([]string{"run", "--profile", "review", "--", "/bin/true", first, second})
		if strings.IndexByte(first, 0) >= 0 || strings.IndexByte(second, 0) >= 0 {
			if problem == "" {
				t.Fatal("accepted a NUL child argument")
			}
			return
		}
		if problem != "" {
			t.Fatalf("literal arguments were rejected: %q", problem)
		}
		want := []string{"/bin/true", first, second}
		if !reflect.DeepEqual(inv.arguments, want) {
			t.Fatalf("arguments = %#v, want %#v", inv.arguments, want)
		}
	})
}
