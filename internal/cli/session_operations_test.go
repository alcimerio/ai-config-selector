package cli_test

import (
	"bytes"
	"encoding/json"
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
	var output, stderr bytes.Buffer
	app := cli.App{Output: &output, ErrorOutput: &stderr}
	for _, args := range [][]string{
		{"session", "list", "--help"},
		{"session", "list", "--state", "invalid"},
		{"session", "recover", "session-private"},
		{"session", "inspect", "ses_abcd234567abcdef234567abcd", "--", "private"},
	} {
		homeCalls := 0
		if handled, _ := app.RunInformational(args); !handled {
			t.Fatalf("informational path did not handle %v", args)
		}
		if homeCalls != 0 {
			t.Fatalf("home discovered for %v", args)
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
