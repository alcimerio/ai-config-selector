package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/cli"
	"github.com/alcimerio/ai-config-selector/internal/exchangefile"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profileexchange"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
	"golang.org/x/sys/unix"
)

func exchangeProfile(t *testing.T, name string) profile.Profile {
	t.Helper()
	references, _ := json.Marshal([]map[string]string{{"source": "shared-agents", "relativePath": "review"}})
	return profile.Profile{Version: 3, SourceVersion: 3, Name: name, Common: map[string]profile.CommonPayload{
		"skills": {Version: 1, Selection: references}, "workspace": {Version: 1, Selection: json.RawMessage(`{"access":"read-only"}`)},
	}, Overlays: map[string]profile.OverlayPayload{"devin": {Version: 1}, "codex": {Version: 1, AuthRef: "work"}}}
}

func exchangeApp(t *testing.T, acsHome string) (cli.App, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	editor, err := devin.NewProfileEditor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	return cli.App{Repository: profilerepo.New(acsHome), Categories: editor.Categories(), Output: out, ErrorOutput: errOut}, out, errOut
}

func TestProfileExchangeGrammarRejectsBeforeDependencies(t *testing.T) {
	for _, args := range [][]string{
		{"profile", "export"}, {"profile", "export", "name", "--file"}, {"profile", "export", "../name"},
		{"profile", "import"}, {"profile", "import", "--file", "secret"}, {"profile", "import", "--file=secret", "--as", "name"},
		{"profile", "import", "--file", "secret", "--as", "../name"}, {"profile", "import", "--file", "secret", "--as", "name", "--bindings", "one", "--bindings", "two"},
		{"profile", "import", "validate"}, {"profile", "import", "validate", "--file", "secret", "--dry-run"},
	} {
		var out, errOut bytes.Buffer
		app := cli.App{Output: &out, ErrorOutput: &errOut, Interactive: func(io.Reader, io.Writer) bool { t.Fatal("grammar touched terminal"); return false }}
		if code := app.Run(context.Background(), args); code != 1 || out.Len() != 0 {
			t.Fatalf("%q: code=%d stdout=%q stderr=%q", args, code, out.String(), errOut.String())
		}
		if strings.Contains(errOut.String(), "secret") {
			t.Fatalf("diagnostic disclosed path: %q", errOut.String())
		}
	}
}

func TestProfileExportAndImportRoundTripSeparateHomes(t *testing.T) {
	sourceHome := filepath.Join(t.TempDir(), ".acs")
	app, stdout, stderr := exchangeApp(t, sourceHome)
	store := profile.NewStore(sourceHome, app.Categories)
	if _, err := store.Create(exchangeProfile(t, "source")); err != nil {
		t.Fatal(err)
	}
	sourcePath := filepath.Join(sourceHome, "profiles", "source.json")
	before, _ := os.ReadFile(sourcePath)
	beforeSnapshot, err := app.Repository.Read(context.Background(), "source")
	if err != nil {
		t.Fatal(err)
	}
	if code := app.Run(context.Background(), []string{"profile", "export", "source"}); code != 0 {
		t.Fatalf("export=%d stderr=%q", code, stderr.String())
	}
	exported := append([]byte(nil), stdout.Bytes()...)
	for _, forbidden := range []string{"shared-agents", `"work"`, sourceHome} {
		if bytes.Contains(exported, []byte(forbidden)) {
			t.Fatalf("export disclosed %q: %s", forbidden, exported)
		}
	}
	after, _ := os.ReadFile(sourcePath)
	if !bytes.Equal(before, after) {
		t.Fatal("export changed source bytes")
	}
	afterSnapshot, err := app.Repository.Read(context.Background(), "source")
	if err != nil || beforeSnapshot.Revision != afterSnapshot.Revision {
		t.Fatalf("export changed source revision: %v", err)
	}

	destinationHome := filepath.Join(t.TempDir(), ".acs")
	importApp, importOut, importErr := exchangeApp(t, destinationHome)
	directory := t.TempDir()
	exchangePath := filepath.Join(directory, "exchange.json")
	bindingPath := filepath.Join(directory, "bindings.json")
	if err := os.WriteFile(exchangePath, exported, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bindingPath, []byte(`{"bindingVersion":1,"sources":{"source-1":"shared-agents"},"authentications":{"authentication-1":"personal"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"profile", "import", "--file", exchangePath, "--as", "imported", "--bindings", bindingPath}
	if code := importApp.Run(context.Background(), args); code != 0 {
		t.Fatalf("import=%d stdout=%q stderr=%q", code, importOut.String(), importErr.String())
	}
	stored, err := profile.NewStore(destinationHome, importApp.Categories).Load("imported")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Overlays["codex"].AuthRef != "personal" || stored.Name != "imported" {
		t.Fatalf("stored=%#v", stored)
	}
	if code := importApp.Run(context.Background(), args); code != 1 {
		t.Fatalf("overwrite exit=%d", code)
	}
}

func TestProfileImportValidationUnresolvedIsPassive(t *testing.T) {
	document, err := profileexchangeExportFixture(t)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	input := filepath.Join(root, "exchange.json")
	if err := os.WriteFile(input, document, 0o600); err != nil {
		t.Fatal(err)
	}
	acsHome := filepath.Join(root, "absent")
	app, out, errOut := exchangeApp(t, acsHome)
	if code := app.Run(context.Background(), []string{"profile", "import", "validate", "--file", input, "--json"}); code != 2 {
		t.Fatalf("code=%d out=%q err=%q", code, out.String(), errOut.String())
	}
	if !strings.Contains(out.String(), `"status":"unresolved"`) || !strings.Contains(out.String(), `"structure":"pass"`) || !strings.Contains(out.String(), `"semantics":"pass"`) || !strings.Contains(out.String(), `"bindings":"unresolved"`) || !strings.Contains(out.String(), `"sourceAvailability":"unchecked"`) {
		t.Fatalf("diagnostic=%q", out.String())
	}
	if _, err := os.Stat(acsHome); !os.IsNotExist(err) {
		t.Fatalf("validation created storage: %v", err)
	}
}

func TestProfileExportFileNoClobberAndTruthfulPostPublicationFailure(t *testing.T) {
	acsHome := filepath.Join(t.TempDir(), ".acs")
	app, _, errOut := exchangeApp(t, acsHome)
	if _, err := profile.NewStore(acsHome, app.Categories).Create(exchangeProfile(t, "source")); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	destination := filepath.Join(directory, "exchange.json")
	if err := os.WriteFile(destination, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := app.Run(context.Background(), []string{"profile", "export", "source", "--file", destination}); code != 1 {
		t.Fatalf("collision code=%d", code)
	}
	if contents, _ := os.ReadFile(destination); string(contents) != "sentinel" {
		t.Fatalf("collision overwrote: %q", contents)
	}

	errOut.Reset()
	published := filepath.Join(directory, "published.json")
	app.ExchangePublisher = exchangefile.Publisher{Hook: func(point string) error {
		if point == "directory-sync.before" {
			return errors.New("private injected detail")
		}
		return nil
	}}
	if code := app.Run(context.Background(), []string{"profile", "export", "source", "--file", published}); code != 1 {
		t.Fatalf("post-publication code=%d", code)
	}
	if _, err := os.Stat(published); err != nil || !strings.Contains(errOut.String(), "was published") || strings.Contains(errOut.String(), "private injected") {
		t.Fatalf("outcome stderr=%q err=%v", errOut.String(), err)
	}
}

func TestProfileImportValidationFileSafetyDoesNotBlock(t *testing.T) {
	document, err := profileexchangeExportFixture(t)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	regular := filepath.Join(root, "exchange.json")
	if err := os.WriteFile(regular, document, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(root, "exchange-link.json")
	if err := os.Symlink(regular, symlink); err != nil {
		t.Fatal(err)
	}
	app, _, _ := exchangeApp(t, filepath.Join(root, "acs"))
	if code := app.Run(context.Background(), []string{"profile", "import", "validate", "--file", symlink}); code != 2 {
		t.Fatalf("regular symlink code=%d", code)
	}
	fifo := filepath.Join(root, "exchange.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	large := filepath.Join(root, "large.json")
	if err := os.WriteFile(large, bytes.Repeat([]byte{'x'}, profilerepo.MaxDocumentBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{root, "/dev/null", fifo, large} {
		started := time.Now()
		if code := app.Run(context.Background(), []string{"profile", "import", "validate", "--file", input}); code != 1 {
			t.Fatalf("%s code=%d", filepath.Base(input), code)
		}
		if time.Since(started) > time.Second {
			t.Fatalf("%s blocked for %s", filepath.Base(input), time.Since(started))
		}
	}
}

func TestProfileExportRequiresExistingExplicitLegacyMigration(t *testing.T) {
	acsHome := filepath.Join(t.TempDir(), ".acs")
	profiles := filepath.Join(acsHome, "profiles")
	if err := os.MkdirAll(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	legacy := []byte(`{"version":2,"name":"legacy","target":"devin","categories":{"skills":{"schemaVersion":1,"selection":[]}}}`)
	path := filepath.Join(profiles, "legacy.json")
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	app, out, errOut := exchangeApp(t, acsHome)
	before, err := app.Repository.Read(context.Background(), "legacy")
	if err != nil {
		t.Fatal(err)
	}
	if code := app.Run(context.Background(), []string{"profile", "export", "legacy"}); code != 1 {
		t.Fatalf("code=%d", code)
	}
	after, err := app.Repository.Read(context.Background(), "legacy")
	if err != nil || !bytes.Equal(after.Bytes, legacy) || before.Revision != after.Revision || out.Len() != 0 || !strings.Contains(errOut.String(), "acs profile migrate NAME") {
		t.Fatalf("legacy changed or guidance missing: %v stdout=%q stderr=%q", err, out.String(), errOut.String())
	}
}

func TestConcurrentProfileImportsHaveOneNoOverwriteWinner(t *testing.T) {
	document, err := profileexchangeExportFixture(t)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	exchangePath, bindingPath := filepath.Join(root, "exchange.json"), filepath.Join(root, "bindings.json")
	if err := os.WriteFile(exchangePath, document, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bindingPath, []byte(`{"bindingVersion":1,"sources":{"source-1":"shared-agents"},"authentications":{"authentication-1":"work"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	acsHome := filepath.Join(root, ".acs")
	apps := make([]cli.App, 2)
	for index := range apps {
		apps[index], _, _ = exchangeApp(t, acsHome)
	}
	start := make(chan struct{})
	codes := make(chan int, 2)
	var wait sync.WaitGroup
	args := []string{"profile", "import", "--file", exchangePath, "--as", "winner", "--bindings", bindingPath}
	for _, app := range apps {
		wait.Add(1)
		go func(app cli.App) { defer wait.Done(); <-start; codes <- app.Run(context.Background(), args) }(app)
	}
	close(start)
	wait.Wait()
	close(codes)
	successes := 0
	for code := range codes {
		if code == 0 {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successes=%d", successes)
	}
	if _, err := profile.NewStore(acsHome, apps[0].Categories).Load("winner"); err != nil {
		t.Fatal(err)
	}
}

type exchangeOutcomeRepository struct {
	cli.ProfileRepository
	outcome profilerepo.Outcome
	err     error
}

func (repository exchangeOutcomeRepository) Apply(context.Context, profilerepo.Request) (profilerepo.Outcome, error) {
	return repository.outcome, repository.err
}

func TestProfileImportPreservesTransactionOutcomePrecedence(t *testing.T) {
	document, err := profileexchangeExportFixture(t)
	if err != nil {
		t.Fatal(err)
	}
	bindings := []byte(`{"bindingVersion":1,"sources":{"source-1":"shared-agents"},"authentications":{"authentication-1":"work"}}`)
	for _, test := range []struct {
		state    profilerepo.State
		recovery bool
		want     string
	}{
		{profilerepo.NotCommitted, false, "not committed"},
		{profilerepo.Committed, false, "committed; reporting failed"},
		{profilerepo.Unknown, true, "outcome unknown"},
	} {
		t.Run(string(test.state), func(t *testing.T) {
			app, _, errOut := exchangeApp(t, filepath.Join(t.TempDir(), ".acs"))
			app.Repository = exchangeOutcomeRepository{ProfileRepository: app.Repository, outcome: profilerepo.Outcome{State: test.state, RecoveryRequired: test.recovery}, err: errors.New("private sentinel")}
			app.ReadProfileDocument = func(path string) ([]byte, error) {
				if path == "exchange" {
					return document, nil
				}
				return bindings, nil
			}
			args := []string{"profile", "import", "--file", "exchange", "--as", "outcome", "--bindings", "bindings"}
			if code := app.Run(context.Background(), args); code != 1 || !strings.Contains(strings.ToLower(errOut.String()), test.want) || strings.Contains(errOut.String(), "private sentinel") {
				t.Fatalf("code/output = %d %q", code, errOut.String())
			}
		})
	}
}

func profileexchangeExportFixture(t *testing.T) ([]byte, error) {
	// Keep the fixture at the public source-code boundary by creating and
	// exporting once through the pure package indirectly used by the CLI.
	value, _, err := profileexchange.Export(exchangeProfile(t, "source"))
	return value, err
}
