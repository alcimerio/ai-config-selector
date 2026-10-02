package cli_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
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
		{[]string{"session", "list", "--limit", "0"}, 2, "limit must be"},
		{[]string{"session", "list", "--limit", "513"}, 2, "limit must be"},
		{[]string{"session", "list", "--limit", "1.5"}, 2, "limit must be"},
		{[]string{"session", "list", "--limit", "+1"}, 2, "limit must be"},
		{[]string{"session", "list", "--limit", "9999999999999999999999999999"}, 2, "limit must be"},
		{[]string{"session", "list", "--limit"}, 2, "missing value"},
		{[]string{"session", "list", "--limit", "-1"}, 2, "missing value"},
		{[]string{"session", "list", "--limit", "1", "--limit", "2"}, 2, "duplicate flag"},
		{[]string{"session", "list", "--after", "ses_abcd234567abcdef234567abcd"}, 2, "--after requires --limit"},
		{[]string{"session", "list", "--limit", "1", "--after", "session-private"}, 2, "invalid Session ID"},
		{[]string{"session", "list", "--limit", "1", "--after", "ses_Abcd234567abcdef234567abcd"}, 2, "invalid Session ID"},
		{[]string{"session", "list", "--limit", "1", "--after", "../private"}, 2, "invalid Session ID"},
		{[]string{"session", "list", "--limit", "1", "--after"}, 2, "missing value"},
		{[]string{"session", "list", "--limit=1"}, 2, "separate arguments"},
		{[]string{"session", "list", "--limit", "1", "--after=ses_abcd234567abcdef234567abcd"}, 2, "separate arguments"},
		{[]string{"session", "inspect", "ses_abcd234567abcdef234567abcd", "--limit", "1"}, 2, "unsupported flag"},
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

func TestSessionListPagesVisitSortedRecords(t *testing.T) {
	home := t.TempDir()
	sessions := filepath.Join(home, ".acs", "sessions")
	var ids []string
	for range 3 {
		created, err := session.CreateTracked(sessions, home, nil, "shell")
		if err != nil {
			t.Fatal(err)
		}
		defer created.Remove()
		if _, err := created.ArmOperation(nil); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, created.PublicID())
	}
	sort.Strings(ids)

	after := ""
	for index, id := range ids {
		var output, stderr bytes.Buffer
		app := cli.App{Output: &output, ErrorOutput: &stderr}
		args := []string{"session", "list", "--limit", "1", "--state", "active", "--json"}
		if after != "" {
			args = append(args, "--after", after)
		}
		handled, code := app.RunSessionOperations(args, func() (string, error) { return home, nil })
		if !handled || code != 0 || stderr.Len() != 0 {
			t.Fatalf("page %d = (%t, %d, %q)", index, handled, code, stderr.String())
		}
		var result sessionops.ListResult
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if len(result.Sessions) != 1 || result.Sessions[0].ID != id {
			t.Fatalf("page %d = %+v, want %s", index, result, id)
		}
		if index < len(ids)-1 && result.NextAfter != id || index == len(ids)-1 && result.NextAfter != "" {
			t.Fatalf("page %d cursor = %q", index, result.NextAfter)
		}
		after = result.NextAfter
	}
}

func TestSessionListPageMissingStorageStaysAbsent(t *testing.T) {
	for _, after := range []string{"", "ses_abcd234567abcdef234567abcd"} {
		home := t.TempDir()
		var output, stderr bytes.Buffer
		app := cli.App{Output: &output, ErrorOutput: &stderr}
		args := []string{"session", "list", "--limit", "512", "--json"}
		if after != "" {
			args = append(args, "--after", after)
		}
		handled, code := app.RunSessionOperations(args, func() (string, error) { return home, nil })
		if !handled || code != 0 || stderr.Len() != 0 {
			t.Fatalf("missing page = (%t, %d, %q)", handled, code, stderr.String())
		}
		if output.String() != "{\"schemaVersion\":1,\"sessions\":[],\"untrackedCount\":0}\n" {
			t.Fatalf("missing page JSON = %q", output.String())
		}
		if _, err := os.Lstat(filepath.Join(home, ".acs")); !os.IsNotExist(err) {
			t.Fatalf("passive page created storage: %v", err)
		}
	}
}
