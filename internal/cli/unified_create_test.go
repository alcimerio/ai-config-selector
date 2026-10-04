package cli

import "testing"

func TestUnifiedCreateGrammar(t *testing.T) {
	for _, args := range [][]string{{"profile", "create", "--name", "review"}, {"profile", "create", "--file", "profile.json", "--dry-run"}} {
		if _, problem := parseCommand(args); problem != "" {
			t.Errorf("%v: %s", args, problem)
		}
	}
	for _, args := range [][]string{{"profile", "create"}, {"profile", "create", "--name", "review", "--file", "profile.json"}, {"profile", "create", "--name", "review", "--dry-run"}, {"profile", "create", "--name", "../review"}} {
		if _, problem := parseCommand(args); problem == "" {
			t.Errorf("accepted %v", args)
		}
	}
}
