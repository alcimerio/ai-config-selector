package cli_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/session"
	"github.com/alcimerio/ai-config-selector/internal/sessionops"
)

func TestSessionCommandsArePassiveBeforeRuntimeAndEmitBoundedJSON(t *testing.T) {
	home := t.TempDir()
	sessions := filepath.Join(home, ".acs", "sessions")
	created, err := session.CreateTracked(sessions, home, nil, "shell")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := created.ArmOperation(nil); err != nil {
		t.Fatal(err)
	}
	defer created.Remove()

	var output, stderr bytes.Buffer
	app := cli.App{Output: &output, ErrorOutput: &stderr}
	homeCalls := 0
	homeLookup := func() (string, error) { homeCalls++; return home, nil }
	handled, code := app.RunSessionOperations([]string{"session", "list", "--state", "active", "--json"}, homeLookup)
	if !handled || code != 0 || homeCalls != 1 || stderr.Len() != 0 {
		t.Fatalf("list = (%v, %d, %d, %q)", handled, code, homeCalls, stderr.String())
	}
	var listed sessionops.ListResult
	if err := json.Unmarshal(output.Bytes(), &listed); err != nil {
		t.Fatalf("invalid JSON: %v: %q", err, output.String())
	}
	if len(listed.Sessions) != 1 || listed.Sessions[0].ID != created.PublicID() {
		t.Fatalf("list = %+v", listed)
	}
	if strings.Contains(output.String(), filepath.Base(created.RootDirectory())) || strings.Contains(output.String(), "rootToken") || strings.Contains(output.String(), "challenge") {
		t.Fatalf("private data in output: %s", output.String())
	}

	output.Reset()
	handled, code = app.RunSessionOperations([]string{"session", "inspect", created.PublicID(), "--json"}, homeLookup)
	if !handled || code != 0 {
		t.Fatalf("inspect = (%v, %d): %s", handled, code, stderr.String())
	}
	var inspected sessionops.InspectResult
	if err := json.Unmarshal(output.Bytes(), &inspected); err != nil || inspected.Session.ID != created.PublicID() {
		t.Fatalf("inspect JSON = %+v, %v", inspected, err)
	}
}

func TestSessionHelpAndGrammarDoNotDiscoverHome(t *testing.T) {
	for _, test := range []struct {
		args       []string
		code       int
		wantOutput string
	}{
		{[]string{"session", "list", "--help"}, 0, "Usage:"},
		{[]string{"session", "list", "--state", "invalid"}, 2, "state must be"},
		{[]string{"session", "recover", "session-private"}, 2, "invalid Session ID"},
		{[]string{"session", "inspect"}, 2, "missing required"},
		{[]string{"session", "unknown"}, 2, "unknown command"},
		{[]string{"session", "list", "--json", "--json"}, 2, "duplicate flag"},
		{[]string{"session", "inspect", "ses_abcd234567abcdef234567abcd", "--", "private"}, 2, "unsupported flag"},
	} {
		var output, stderr bytes.Buffer
		app := cli.App{Output: &output, ErrorOutput: &stderr}
		homeCalls := 0
		homeLookup := func() (string, error) {
			homeCalls++
			return "", errors.New("home discovery tripwire")
		}
		handled, code := app.RunInformational(test.args)
		if !handled {
			handled, code = app.RunSessionOperations(test.args, homeLookup)
		}
		if !handled || code != test.code {
			t.Fatalf("bootstrap result for %v = (%v, %d), want (true, %d)", test.args, handled, code, test.code)
		}
		if homeCalls != 0 {
			t.Fatalf("home discovered for %v", test.args)
		}
		combined := output.String() + stderr.String()
		if !strings.Contains(combined, test.wantOutput) {
			t.Fatalf("output for %v = %q, want %q", test.args, combined, test.wantOutput)
		}
	}
}

func TestSessionRecoverOperationalJSONIsOneSanitizedObject(t *testing.T) {
	home := t.TempDir()
	sessions := filepath.Join(home, ".acs", "sessions")
	created, err := session.CreateTracked(sessions, home, nil, "command")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := created.ArmOperation(nil); err != nil {
		t.Fatal(err)
	}
	defer created.Remove()
	var output, stderr bytes.Buffer
	app := cli.App{Output: &output, ErrorOutput: &stderr}
	handled, code := app.RunSessionOperations([]string{"session", "recover", created.PublicID(), "--json"}, func() (string, error) { return home, nil })
	if !handled || code != 1 || stderr.Len() != 0 {
		t.Fatalf("recover = (%v, %d, %q)", handled, code, stderr.String())
	}
	decoder := json.NewDecoder(&output)
	var diagnostic map[string]any
	if err := decoder.Decode(&diagnostic); err != nil {
		t.Fatal(err)
	}
	if diagnostic["outcome"] != "active" || diagnostic["diagnostic"] != "active" {
		t.Fatalf("diagnostic = %#v", diagnostic)
	}
	var extra any
	if err := decoder.Decode(&extra); err == nil {
		t.Fatalf("multiple JSON values: %#v", extra)
	}
}
