package cli_test

import (
	"bytes"
	"context"
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
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
	"golang.org/x/sys/unix"
)

func declarativeDocument(name string) []byte {
	return []byte(`{"version":3,"name":"` + name + `","common":{"skills":{"version":1,"selection":[{"source":"shared-agents","relativePath":"review"}]},"workspace":{"version":1,"selection":{"access":"read-only"}}},"overlays":{"codex":{"version":1,"authRef":"work"},"devin":{"version":1}}}`)
}

func declarativeApp(t *testing.T, acsHome string) cli.App {
	t.Helper()
	editor, err := devin.NewProfileEditor(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return cli.App{Categories: editor.Categories(), Profiles: profile.NewStore(acsHome, editor.Categories()), Output: &bytes.Buffer{}, ErrorOutput: &bytes.Buffer{}}
}

func TestDeclarativeCreateGrammarRejectsHostileInputBeforeDependencies(t *testing.T) {
	for _, args := range [][]string{
		{"profile", "create"},
		{"profile", "create", "--file"},
		{"profile", "create", "--file", "one", "--file", "two"},
		{"profile", "create", "--file", "private", "--dry-run", "--dry-run"},
		{"profile", "create", "--file", "private", "--dry-run=true"},
		{"profile", "create", "--file=private"},
		{"profile", "create", "--file", "private", "extra"},
		{"profile", "create", "--file", "private", "--unknown=secret"},
		{"profile", "create", "--file", "private", "--"},
		{"profile", "create", "--file", "bad\x00path"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			var out, errOut bytes.Buffer
			app := cli.App{Output: &out, ErrorOutput: &errOut, Interactive: func(io.Reader, io.Writer) bool { t.Fatal("syntax checked terminal"); return false }}
			if code := app.Run(context.Background(), args); code != 1 || out.Len() != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
			}
			if strings.Contains(errOut.String(), "private") || strings.Contains(errOut.String(), "secret") || strings.Contains(errOut.String(), "bad") {
				t.Fatalf("diagnostic disclosed input: %q", errOut.String())
			}
		})
	}
}

func TestDeclarativeDryRunCanonicalizesOnceWithoutWrites(t *testing.T) {
	root := t.TempDir()
	acsHome := filepath.Join(root, "absent-acs-home")
	app := declarativeApp(t, acsHome)
	calls := 0
	app.ReadProfileDocument = func(string) ([]byte, error) {
		calls++
		return declarativeDocument("example"), nil
	}
	var out, errOut bytes.Buffer
	app.Output, app.ErrorOutput = &out, &errOut
	if code := app.Run(context.Background(), []string{"profile", "create", "--dry-run", "--file", "ignored"}); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
	if calls != 1 {
		t.Fatalf("input reads=%d, want 1", calls)
	}
	for _, want := range []string{`"version": 3`, `"name": "example"`, `"source": "shared-agents"`, `"authRef": "work"`, "readiness was not checked", "No Profile storage, lock, journal, Session, credential, input, or process was changed."} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("preview missing %q: %s", want, out.String())
		}
	}
	if _, err := os.Stat(acsHome); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry-run created storage: %v", err)
	}
}

func TestDeclarativeCreatePublishesExactCapturedCandidateAndDoesNotTouchInput(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "candidate.json")
	original := declarativeDocument("example")
	if err := os.WriteFile(input, original, 0o640); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(input)
	app := declarativeApp(t, filepath.Join(root, "acs"))
	var out, errOut bytes.Buffer
	app.Output, app.ErrorOutput = &out, &errOut
	if code := app.Run(context.Background(), []string{"profile", "create", "--file", input}); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errOut.String())
	}
	stored, err := os.ReadFile(filepath.Join(root, "acs", "profiles", "example.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(stored, []byte("\n  \"common\"")) || !bytes.Contains(stored, []byte(`"codex"`)) || !bytes.Contains(stored, []byte(`"devin"`)) {
		t.Fatalf("stored bytes are not canonical complete v3: %s", stored)
	}
	after, _ := os.Stat(input)
	unchanged, _ := os.ReadFile(input)
	if !bytes.Equal(unchanged, original) || before.Mode() != after.Mode() {
		t.Fatal("source bytes or mode changed")
	}
	if !strings.Contains(out.String(), `Created Profile "example".`) || strings.Contains(out.String(), input) {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

func TestDeclarativeCreateStrictlyRejectsUnsupportedOrLossyDocuments(t *testing.T) {
	valid := string(declarativeDocument("example"))
	cases := map[string]string{
		"legacy":          strings.Replace(valid, `"version":3`, `"version":2`, 1),
		"future":          strings.Replace(valid, `"version":3`, `"version":4`, 1),
		"duplicate":       strings.Replace(valid, `"version":3`, `"version":3,"version":3`, 1),
		"unknown common":  strings.Replace(valid, `"skills":`, `"network":{"version":1,"selection":{}},"skills":`, 1),
		"unknown overlay": strings.Replace(valid, `"codex":`, `"future":{"version":1},"codex":`, 1),
		"unsafe skill":    strings.Replace(valid, `"relativePath":"review"`, `"relativePath":"../review"`, 1),
		"unknown field":   strings.Replace(valid, `"name":"example"`, `"name":"example","secret":"value"`, 1),
	}
	for name, document := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			app := declarativeApp(t, filepath.Join(root, "acs"))
			app.ReadProfileDocument = func(string) ([]byte, error) { return []byte(document), nil }
			var errOut bytes.Buffer
			app.ErrorOutput = &errOut
			if code := app.Run(context.Background(), []string{"profile", "create", "--file", "ignored"}); code != 1 {
				t.Fatalf("code=%d stderr=%q", code, errOut.String())
			}
			if strings.Contains(errOut.String(), "secret") || strings.Contains(errOut.String(), "value") || strings.Contains(errOut.String(), "../review") {
				t.Fatalf("diagnostic echoed unsupported content: %q", errOut.String())
			}
			if _, err := os.Stat(filepath.Join(root, "acs")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("rejection wrote storage: %v", err)
			}
		})
	}
}

func TestDeclarativeCreateRejectsNonRegularAndOversizedInputWithoutBlocking(t *testing.T) {
	root := t.TempDir()
	app := declarativeApp(t, filepath.Join(root, "acs"))
	paths := []string{root, "/dev/null"}
	fifo := filepath.Join(root, "candidate.fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	paths = append(paths, fifo)
	large := filepath.Join(root, "large.json")
	if err := os.WriteFile(large, bytes.Repeat([]byte{'x'}, profilerepo.MaxDocumentBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	paths = append(paths, large)
	for _, path := range paths {
		started := time.Now()
		var errOut bytes.Buffer
		app.ErrorOutput = &errOut
		if code := app.Run(context.Background(), []string{"profile", "create", "--file", path}); code != 1 {
			t.Fatalf("%s: code=%d", filepath.Base(path), code)
		}
		if time.Since(started) > time.Second {
			t.Fatalf("%s blocked for %s", filepath.Base(path), time.Since(started))
		}
		if strings.Contains(errOut.String(), path) {
			t.Fatalf("diagnostic disclosed path: %q", errOut.String())
		}
	}
}

func TestDeclarativeCreateDestinationCollisionAndConcurrencyNeverOverwrite(t *testing.T) {
	root := t.TempDir()
	acsHome := filepath.Join(root, "acs")
	input := filepath.Join(root, "candidate.json")
	if err := os.WriteFile(input, declarativeDocument("example"), 0o600); err != nil {
		t.Fatal(err)
	}
	apps := []cli.App{declarativeApp(t, acsHome), declarativeApp(t, acsHome)}
	start := make(chan struct{})
	codes := make(chan int, 2)
	var wait sync.WaitGroup
	for i := range apps {
		wait.Add(1)
		go func(app cli.App) {
			defer wait.Done()
			<-start
			codes <- app.Run(context.Background(), []string{"profile", "create", "--file", input})
		}(apps[i])
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
		t.Fatalf("successful creates=%d, want 1", successes)
	}
	stored, err := os.ReadFile(filepath.Join(acsHome, "profiles", "example.json"))
	if err != nil || !bytes.Contains(stored, []byte(`"name": "example"`)) {
		t.Fatalf("stored candidate invalid: %v %s", err, stored)
	}
}

type outcomeStore struct {
	recoverErr error
	createErr  error
	candidate  profile.Profile
	reads      int
	recovered  bool
	onCreate   func()
}

func (*outcomeStore) Create(profile.Profile) (string, error) { panic("legacy Create called") }
func (s *outcomeStore) CreateContext(_ context.Context, candidate profile.Profile) (string, error) {
	if s.onCreate != nil {
		s.onCreate()
	}
	s.candidate = candidate
	return "", s.createErr
}
func (*outcomeStore) Load(string) (profile.Profile, error) { return profile.Profile{}, os.ErrNotExist }
func (s *outcomeStore) RecoverContext(context.Context) error {
	s.recovered = true
	return s.recoverErr
}

func TestDeclarativeCreatePreservesTransactionOutcomeAndNeverRereadsSource(t *testing.T) {
	for _, state := range []profilerepo.State{profilerepo.NotCommitted, profilerepo.Committed, profilerepo.Unknown} {
		t.Run(string(state), func(t *testing.T) {
			app := declarativeApp(t, t.TempDir())
			failure := &profilerepo.OutcomeError{Outcome: profilerepo.Outcome{State: state, RecoveryRequired: state != profilerepo.NotCommitted}, Err: errors.New("fixture failure")}
			store := &outcomeStore{createErr: failure}
			app.Profiles = store
			calls := 0
			app.ReadProfileDocument = func(string) ([]byte, error) { calls++; return declarativeDocument("captured"), nil }
			var errOut bytes.Buffer
			app.ErrorOutput = &errOut
			if code := app.Run(context.Background(), []string{"profile", "create", "--file", "ignored"}); code != 1 || calls != 1 || store.candidate.Name != "captured" || store.recovered {
				t.Fatalf("code=%d reads=%d candidate=%q separate-recovery=%v", code, calls, store.candidate.Name, store.recovered)
			}
			if state != profilerepo.NotCommitted && !strings.Contains(errOut.String(), string(state)) && !strings.Contains(errOut.String(), "Outcome unknown") && !strings.Contains(errOut.String(), "committed") {
				t.Fatalf("outcome missing: %q", errOut.String())
			}
		})
	}
}

func TestDeclarativeCreateUsesCapturedBytesWhenInputChangesBeforePublication(t *testing.T) {
	input := filepath.Join(t.TempDir(), "candidate.json")
	if err := os.WriteFile(input, declarativeDocument("captured"), 0o600); err != nil {
		t.Fatal(err)
	}
	app := declarativeApp(t, t.TempDir())
	reads := 0
	app.ReadProfileDocument = func(path string) ([]byte, error) {
		reads++
		return os.ReadFile(path)
	}
	store := &outcomeStore{onCreate: func() {
		if err := os.WriteFile(input, declarativeDocument("replacement"), 0o600); err != nil {
			t.Error(err)
		}
	}}
	app.Profiles = store
	if code := app.Run(context.Background(), []string{"profile", "create", "--file", input}); code != 0 {
		t.Fatalf("code=%d", code)
	}
	if reads != 1 || store.candidate.Name != "captured" {
		t.Fatalf("reads=%d published=%q, want one captured read", reads, store.candidate.Name)
	}
}

func TestDeclarativeDryRunSurfacesDestinationConflictWithoutRecovery(t *testing.T) {
	app := declarativeApp(t, t.TempDir())
	app.ReadProfileDocument = func(string) ([]byte, error) { return declarativeDocument("occupied"), nil }
	store := &outcomeStore{}
	store.reads = 1
	app.Profiles = &existingOutcomeStore{outcomeStore: store}
	var errOut bytes.Buffer
	app.ErrorOutput = &errOut
	if code := app.Run(context.Background(), []string{"profile", "create", "--file", "ignored", "--dry-run"}); code != 1 || !strings.Contains(errOut.String(), "occupied") || store.recovered || store.candidate.Name != "" {
		t.Fatalf("code=%d recovered=%v candidate=%q stderr=%q", code, store.recovered, store.candidate.Name, errOut.String())
	}
}

type existingOutcomeStore struct{ *outcomeStore }

func (*existingOutcomeStore) Load(name string) (profile.Profile, error) {
	return profile.Profile{Name: name}, nil
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("output unavailable") }

func TestDeclarativeCreateHandlesPreviewAndCommittedReportingFailures(t *testing.T) {
	t.Run("preview", func(t *testing.T) {
		root := t.TempDir()
		acsHome := filepath.Join(root, "absent")
		app := declarativeApp(t, acsHome)
		app.ReadProfileDocument = func(string) ([]byte, error) { return declarativeDocument("preview"), nil }
		app.Output = failingWriter{}
		var errOut bytes.Buffer
		app.ErrorOutput = &errOut
		if code := app.Run(context.Background(), []string{"profile", "create", "--file", "ignored", "--dry-run"}); code != 1 || !strings.Contains(errOut.String(), "write Profile dry-run preview") {
			t.Fatalf("code=%d stderr=%q", code, errOut.String())
		}
		if _, err := os.Stat(acsHome); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed preview wrote storage: %v", err)
		}
	})
	t.Run("committed", func(t *testing.T) {
		root := t.TempDir()
		acsHome := filepath.Join(root, "acs")
		app := declarativeApp(t, acsHome)
		app.ReadProfileDocument = func(string) ([]byte, error) { return declarativeDocument("committed"), nil }
		app.Output = failingWriter{}
		var errOut bytes.Buffer
		app.ErrorOutput = &errOut
		if code := app.Run(context.Background(), []string{"profile", "create", "--file", "ignored"}); code != 1 || !strings.Contains(errOut.String(), "transaction committed; reporting failed") {
			t.Fatalf("code=%d stderr=%q", code, errOut.String())
		}
		if _, err := os.Stat(filepath.Join(acsHome, "profiles", "committed.json")); err != nil {
			t.Fatalf("reporting failure lost committed Profile: %v", err)
		}
	})
}

func TestDeclarativeCreateOutcomeStatePrecedesNestedCause(t *testing.T) {
	for _, state := range []profilerepo.State{profilerepo.Committed, profilerepo.Unknown} {
		t.Run(string(state), func(t *testing.T) {
			app := declarativeApp(t, t.TempDir())
			app.ReadProfileDocument = func(string) ([]byte, error) { return declarativeDocument("priority"), nil }
			app.Profiles = &outcomeStore{createErr: &profilerepo.OutcomeError{
				Outcome: profilerepo.Outcome{State: state, RecoveryRequired: true},
				Err:     errors.Join(profile.ErrProfileExists, context.Canceled),
			}}
			var out, errOut bytes.Buffer
			app.Output, app.ErrorOutput = &out, &errOut
			if code := app.Run(context.Background(), []string{"profile", "create", "--file", "ignored"}); code != 1 {
				t.Fatalf("code=%d", code)
			}
			if strings.Contains(errOut.String(), "occupied") || strings.Contains(out.String(), "cancelled") {
				t.Fatalf("nested cause hid outcome: stdout=%q stderr=%q", out.String(), errOut.String())
			}
			want := "committed"
			if state == profilerepo.Unknown {
				want = "outcome unknown"
			}
			if !strings.Contains(errOut.String(), want) || !strings.Contains(errOut.String(), "Do not retry") {
				t.Fatalf("outcome missing: %q", errOut.String())
			}
		})
	}
}
