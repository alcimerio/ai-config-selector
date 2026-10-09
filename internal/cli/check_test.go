package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/codexauth"
)

func TestCheckGrammarAndPassiveDispatch(t *testing.T) {
	for _, args := range []string{"check", "check --profile example", "check --profile example --target other", "check --profile ../private --target sandbox", "check --profile example --target sandbox --auth work", "check --profile example --target codex --check-authentication", "check --profile example --target sandbox --check-authentication --auth work", "check --profile=example --target sandbox", "check --profile example --target sandbox --json --json"} {
		var out, errout bytes.Buffer
		code := (cli.App{Output: &out, ErrorOutput: &errout}).Run(context.Background(), strings.Fields(args))
		if code != 1 || out.Len() != 0 || errout.Len() == 0 {
			t.Fatalf("%s: %d %s %s", args, code, &out, &errout)
		}
	}
	home := t.TempDir()
	auth := &recordingCodexAuthRegistry{}
	var first []byte
	for i := 0; i < 2; i++ {
		var out, errout bytes.Buffer
		app := cli.App{CodexAuth: auth, Output: &out, ErrorOutput: &errout}
		handled, code := app.RunCheck(context.Background(), strings.Fields("check --profile missing --target sandbox --json"), func() (string, error) { return home, nil })
		if !handled || code != 1 || errout.Len() != 0 {
			t.Fatalf("%v %d %s", handled, code, &errout)
		}
		var result struct {
			Operation string
			Checks    []struct{ ID, Status string }
		}
		if json.Unmarshal(out.Bytes(), &result) != nil || result.Operation != "check" {
			t.Fatal(out.String())
		}
		if i == 0 {
			first = append([]byte(nil), out.Bytes()...)
		} else if !bytes.Equal(first, out.Bytes()) {
			t.Fatal("nondeterministic JSON")
		}
	}
	if auth.statusCalls != 0 {
		t.Fatal("implicit status")
	}
}

func TestCheckDefaultNeverExecutesTargetOrQueriesStoredAuth(t *testing.T) {
	home := t.TempDir()
	profiles := filepath.Join(home, ".acs", "profiles")
	if err := os.MkdirAll(profiles, 0700); err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"version":3,"name":"example","common":{"skills":{"version":1,"selection":[]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"codex":{"version":1,"authRef":"private-identity"}}}`)
	path := filepath.Join(profiles, "example.json")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	marker := filepath.Join(bin, "executed")
	if err := os.WriteFile(filepath.Join(bin, "codex"), []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	var out, stderr bytes.Buffer
	app := cli.App{Output: &out, ErrorOutput: &stderr, CheckAuthentication: func(context.Context, string) (codexauth.IdentityStatus, error) {
		t.Fatal("credential status called")
		return codexauth.IdentityStatus{}, nil
	}}
	handled, _ := app.RunCheck(context.Background(), strings.Fields("check --profile example --target codex --json"), func() (string, error) { return home, nil })
	if !handled || stderr.Len() != 0 {
		t.Fatal(stderr.String())
	}
	var result struct{ Checks []struct{ ID, Status string } }
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	for _, c := range result.Checks {
		if (c.ID == "authentication" || c.ID == "runtime.enforcement" || c.ID == "native.readiness" || c.ID == "executable.version") && c.Status != "unchecked" {
			t.Fatal(c)
		}
	}
	if len(out.Bytes()) > 8192 || strings.Contains(out.String(), "private-identity") || strings.Contains(out.String(), home) || strings.Contains(out.String(), bin) {
		t.Fatal("private or unbounded output")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("target executed")
	}
	actual, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(actual, body) {
		t.Fatal("Profile changed")
	}
	entries, err := os.ReadDir(filepath.Join(home, ".acs"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "profiles" {
		t.Fatal("runtime storage created")
	}
}
