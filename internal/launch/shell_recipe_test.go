package launch

import (
	"reflect"
	"testing"
)

func TestFixedShellRecipes(t *testing.T) {
	t.Setenv("SHELL", "/untrusted/shell")
	t.Setenv("PATH", "/untrusted/bin")
	for _, tc := range []struct {
		os, path string
		args     []string
	}{
		{"darwin", "/bin/zsh", []string{"-f"}},
		{"linux", "/bin/bash", []string{"--noprofile", "--norc"}},
	} {
		path, args := ShellRecipe(tc.os)
		if path != tc.path || !reflect.DeepEqual(args, tc.args) {
			t.Fatalf("%s recipe = %q %v", tc.os, path, args)
		}
		args[0] = "mutated"
		_, again := ShellRecipe(tc.os)
		if !reflect.DeepEqual(again, tc.args) {
			t.Fatal("caller mutated fixed recipe")
		}
	}
}
