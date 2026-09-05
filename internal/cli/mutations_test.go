package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestMutationGrammarAccepted(t *testing.T) {
	for _, args := range [][]string{
		{"profile", "edit", "old"},
		{"profile", "clone", "old", "--name", "new"},
		{"profile", "clone", "--name", "new", "old"},
		{"profile", "rename", "old", "--name", "new"},
		{"profile", "rename", "--name", "new", "old"},
		{"profile", "delete", "old"},
		{"profile", "delete", "--confirm", "old", "old"},
		{"profile", "delete", "old", "--confirm", "old"},
	} {
		if _, problem := parseCommand(args); problem != "" {
			t.Errorf("%q: %s", args, problem)
		}
	}
}

func TestMutationGrammarRejectsBypassesBeforeDependencies(t *testing.T) {
	for _, args := range [][]string{
		{"profile", "clone", "old"}, {"profile", "clone", "--name", "new"},
		{"profile", "clone", "old", "--name=new"}, {"profile", "clone", "old", "--name", "new", "--name", "two"},
		{"profile", "clone", "old", "--name", "old"}, {"profile", "clone", "old", "--name", "OLD"},
		{"profile", "edit", "../old"}, {"profile", "edit", "old", "--name", "new"},
		{"profile", "edit", "old", "extra"}, {"profile", "--name", "new", "clone", "old"},
		{"profile", "delete", "old", "--yes"}, {"profile", "delete", "old", "--confirm", "OLD"},
		{"profile", "delete", "old", "--confirm"}, {"profile", "delete", "old", "--confirm=old"},
		{"profile", "delete", "old", "--confirm", "old", "--confirm", "old"},
		{"profile", "delete", "old", "--"}, {"profile", "delete", "old", "--force"},
	} {
		var output bytes.Buffer
		app := App{Output: &output, ErrorOutput: &output, Interactive: func(io.Reader, io.Writer) bool { t.Fatal("grammar touched terminal"); return true }}
		handled, code := app.RunInformational(args)
		if !handled || code != 1 {
			t.Errorf("%q accepted: %v %d", args, handled, code)
		}
	}
	for _, command := range []string{"edit", "clone", "rename", "delete"} {
		var output bytes.Buffer
		app := App{Output: &output, ErrorOutput: &output}
		if handled, code := app.RunInformational([]string{"profile", command, "--help"}); !handled || code != 0 {
			t.Fatalf("help %s: %v %d", command, handled, code)
		}
	}
}

type mutationEditorFunc func(context.Context, string, category.Draft, builder.MutationOptions, io.Reader, io.Writer) (builder.Outcome, error)

func (f mutationEditorFunc) MutateProfile(ctx context.Context, name string, draft category.Draft, options builder.MutationOptions, input io.Reader, output io.Writer) (builder.Outcome, error) {
	return f(ctx, name, draft, options, input, output)
}

func mutationFixture(t *testing.T, raw []byte) (App, *profilerepo.Repository, string, *bytes.Buffer) {
	t.Helper()
	home := t.TempDir()
	directory := filepath.Join(home, ".acs", "profiles")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "old.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	editor, err := devin.NewProfileEditor(home)
	if err != nil {
		t.Fatal(err)
	}
	repository := profilerepo.New(filepath.Join(home, ".acs"))
	output := &bytes.Buffer{}
	app := App{Repository: repository, Categories: editor.Categories(), MutationBuilder: editor, Input: strings.NewReader(""), Output: output, ErrorOutput: output, Interactive: func(io.Reader, io.Writer) bool { return true }}
	return app, repository, home, output
}

var legacyMutationDocument = []byte(`{"version":1,"name":"old","target":"devin","skillReferences":[{"source":"shared-agents","relativePath":"lost"},{"source":"devin-config","relativePath":"lost"}]}`)

func TestMutationPreviewCommitsExactCanonicalBytes(t *testing.T) {
	for _, operation := range []string{"edit", "clone", "rename"} {
		for _, version := range []int{1, 2} {
			t.Run(fmt.Sprintf("%s-v%d", operation, version), func(t *testing.T) {
				raw := append([]byte(nil), legacyMutationDocument...)
				if version == 2 {
					raw = []byte(`{"version":2,"name":"old","target":"devin","categories":{"skills":{"schemaVersion":1,"selection":[{"source":"shared-agents","relativePath":"lost"},{"source":"devin-config","relativePath":"lost"}]}}}`)
				}
				app, repository, _, output := mutationFixture(t, raw)
				destination := "old"
				args := []string{"profile", operation, "old"}
				if operation != "edit" {
					destination = "new"
					args = append(args, "--name", "new")
				}
				app.MutationBuilder = mutationEditorFunc(func(ctx context.Context, name string, draft category.Draft, options builder.MutationOptions, _ io.Reader, _ io.Writer) (builder.Outcome, error) {
					if name != destination || draft.Summaries()[0].Count != 2 {
						t.Fatalf("seed/name: %s %v", name, draft.Summaries())
					}
					prepared, err := options.Prepare(draft)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(prepared.Text, fmt.Sprintf("Stored v%d -> v2", version)) {
						t.Fatalf("no conversion preview: %s", prepared.Text)
					}
					_, canonical, ok := strings.Cut(prepared.Text, "Exact resulting canonical JSON (including final newline):\n")
					if !ok {
						t.Fatal("no canonical preview")
					}
					path, err := prepared.Save(ctx, app.Categories.NewDraft())
					if err != nil {
						return builder.Outcome{}, err
					}
					stored, err := repository.Read(ctx, destination)
					if err != nil || !bytes.Equal(stored.Bytes, []byte(canonical)) {
						t.Fatalf("preview mismatch: %s %v", stored.Bytes, err)
					}
					return builder.Outcome{Create: true, Draft: draft, Path: path}, nil
				})
				if code := app.Run(context.Background(), args); code != 0 {
					t.Fatalf("exit %d: %s", code, output)
				}
				source, err := repository.Read(context.Background(), "old")
				if err != nil {
					t.Fatal(err)
				}
				if operation == "clone" && !bytes.Equal(source.Bytes, raw) {
					t.Fatal("clone changed source")
				}
				if operation == "rename" && source.Exists {
					t.Fatal("rename retained source")
				}
			})
		}
	}
}

func TestMutationRefusesUnsupportedBytesWithoutTreeChanges(t *testing.T) {
	fixtures := []string{
		`{"version":3,"name":"old","target":"devin","categories":{}}`,
		`{"version":2,"name":"other","target":"devin","categories":{}}`,
		`{"version":2,"name":"old","target":"future","categories":{}}`,
		`{"version":2,"name":"old","target":"devin","categories":{},"future":true}`,
		`{"version":1,"name":"old","target":"devin","skillReferences":[],"future":true}`,
		`{"version":2,"name":"old","target":"devin","categories":{"future":{}}}`,
		`{"version":2,"name":"old","target":"devin","categories":{"skills":{"schemaVersion":1,"selection":[],"future":true}}}`,
		`{"version":2,"name":"old","target":"devin","categories":{"skills":{"schemaVersion":2,"selection":[]}}}`,
		`{"version":1,"name":"old","target":"devin","skillReferences":[{"source":"devin-config","relativePath":"ok","future":true}]}`,
		`{"version":1,"name":"old","target":"devin","skillReferences":[{"source":"future","relativePath":"ok"}]}`,
		`{"version":1,"name":"old","target":"devin","skillReferences":[{"source":"devin-config","relativePath":"../outside"}]}`,
		`{"version":2,"version":2,"name":"old","target":"devin","categories":{}}`,
		`{"version":2,"name":"old","target":"devin","categories":{"skills":{"schemaVersion":1,"schemaVersion":1,"selection":[]}}}`,
		`{"version":1,"name":"old","target":"devin","skillReferences":[{"source":"devin-config","source":"shared-agents","relativePath":"ok"}]}`,
		`{"version":1,"name":"old","target":"devin","skillReferences":[{"source":"devin-config","relativePath":"ok"},{"source":"devin-config","relativePath":"./ok"}]}`,
		`not json`,
	}
	for index, raw := range fixtures {
		for _, operation := range []string{"edit", "clone", "rename"} {
			t.Run(fmt.Sprintf("%d-%s", index, operation), func(t *testing.T) {
				app, _, home, output := mutationFixture(t, []byte(raw))
				before := mutationTree(t, home)
				app.MutationBuilder = mutationEditorFunc(func(context.Context, string, category.Draft, builder.MutationOptions, io.Reader, io.Writer) (builder.Outcome, error) {
					t.Fatal("unsupported bytes opened builder")
					return builder.Outcome{}, nil
				})
				args := []string{"profile", operation, "old"}
				if operation != "edit" {
					args = append(args, "--name", "new")
				}
				if code := app.Run(context.Background(), args); code != 1 {
					t.Fatalf("exit %d: %s", code, output)
				}
				if after := mutationTree(t, home); !reflect.DeepEqual(before, after) {
					t.Fatalf("refusal changed bytes/modes/tree: before %v after %v", before, after)
				}
			})
		}
	}
}

func mutationTree(t *testing.T, home string) map[string]string {
	t.Helper()
	tree := map[string]string{}
	err := filepath.WalkDir(home, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(home, path)
		value := info.Mode().String()
		if info.Mode().IsRegular() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += " " + string(raw)
		}
		tree[relative] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

func TestMutationCancellationNeverPublishes(t *testing.T) {
	for _, operation := range []string{"edit", "clone", "rename", "delete"} {
		t.Run(operation, func(t *testing.T) {
			app, _, home, output := mutationFixture(t, legacyMutationDocument)
			before := mutationTree(t, home)
			app.MutationBuilder = mutationEditorFunc(func(_ context.Context, _ string, draft category.Draft, options builder.MutationOptions, _ io.Reader, _ io.Writer) (builder.Outcome, error) {
				if _, err := options.Prepare(draft); err != nil {
					t.Fatal(err)
				}
				return builder.Outcome{Draft: draft, Cancelled: true}, nil
			})
			args := []string{"profile", operation, "old"}
			if operation == "clone" || operation == "rename" {
				args = append(args, "--name", "new")
			}
			if code := app.Run(context.Background(), args); code != 130 {
				t.Fatalf("exit %d: %s", code, output)
			}
			if !reflect.DeepEqual(before, mutationTree(t, home)) {
				t.Fatal("cancel changed bytes/modes/tree")
			}
		})
	}
}

func TestDeleteUnsupportedDocumentAndSentinelPreservation(t *testing.T) {
	app, _, home, output := mutationFixture(t, []byte(`future or corrupt`))
	for _, relative := range []string{".acs/identities/sentinel", ".acs/sessions/active/old.json", ".acs/profiles/other.json"} {
		path := filepath.Join(home, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("sentinel"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	before := mutationTree(t, home)
	app.Interactive = func(io.Reader, io.Writer) bool { t.Fatal("explicit delete checked TTY"); return false }
	if code := app.Run(context.Background(), []string{"profile", "delete", "--confirm", "old", "old"}); code != 0 {
		t.Fatalf("exit %d: %s", code, output)
	}
	if !strings.Contains(output.String(), "unsupported or corrupt") {
		t.Fatalf("no warning: %s", output)
	}
	after := mutationTree(t, home)
	for path, value := range before {
		if path == ".acs/profiles/old.json" {
			if _, exists := after[path]; exists {
				t.Fatal("not deleted")
			}
			continue
		}
		if after[path] != value {
			t.Fatalf("sentinel changed %s", path)
		}
	}
}

func TestMutationNoninteractiveRejectsBeforeHome(t *testing.T) {
	for _, args := range [][]string{{"profile", "edit", "old"}, {"profile", "clone", "old", "--name", "new"}, {"profile", "rename", "old", "--name", "new"}, {"profile", "delete", "old"}} {
		var output bytes.Buffer
		app := App{Output: &output, ErrorOutput: &output, Interactive: func(io.Reader, io.Writer) bool { return false }}
		handled, code := app.RunProfileMutations(context.Background(), args, func() (string, error) { t.Fatal("noninteractive path read HOME"); return "", nil })
		if !handled || code != 1 {
			t.Fatalf("%q: %v %d", args, handled, code)
		}
	}
}

// Independent helper processes use the repository normally, rather than mutating
// the UI fake or borrowing a revision from the editor under test.
func TestMutationIndependentWriterHelper(t *testing.T) {
	home := os.Getenv("ACS_MUTATION_TEST_HOME")
	if home == "" {
		t.Skip("independent writer helper")
	}
	repository := profilerepo.New(filepath.Join(home, ".acs"))
	name := os.Getenv("ACS_MUTATION_TEST_NAME")
	snapshot, err := repository.Read(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	var request profilerepo.Request = profilerepo.CreateRequest{Name: name, Expected: snapshot.Revision, Bytes: []byte("independent newer bytes")}
	if snapshot.Exists {
		request = profilerepo.ReplaceRequest{Name: name, Expected: snapshot.Revision, Bytes: []byte("independent newer bytes")}
	}
	out, err := repository.Apply(context.Background(), request)
	if err != nil || out.State != profilerepo.Committed {
		t.Fatalf("writer: %v %v", out, err)
	}
}

func independentMutationWriter(t *testing.T, home, name string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestMutationIndependentWriterHelper$")
	cmd.Env = append(os.Environ(), "ACS_MUTATION_TEST_HOME="+home, "ACS_MUTATION_TEST_NAME="+name)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("independent writer: %v %s", err, output)
	}
}

func TestMutationExpectedRevisionAgainstIndependentWriter(t *testing.T) {
	for _, operation := range []string{"edit", "clone", "rename", "delete"} {
		for _, raceDestination := range []bool{false, true} {
			if raceDestination && operation != "clone" && operation != "rename" {
				continue
			}
			t.Run(fmt.Sprintf("%s-destination=%v", operation, raceDestination), func(t *testing.T) {
				app, repository, home, output := mutationFixture(t, legacyMutationDocument)
				app.MutationBuilder = mutationEditorFunc(func(ctx context.Context, _ string, draft category.Draft, options builder.MutationOptions, _ io.Reader, _ io.Writer) (builder.Outcome, error) {
					prepared, err := options.Prepare(draft)
					if err != nil {
						t.Fatal(err)
					}
					raced := "old"
					if raceDestination {
						raced = "new"
					}
					// Barrier: the editor has captured and previewed; writer completes before confirmation.
					independentMutationWriter(t, home, raced)
					_, err = prepared.Save(ctx, draft)
					var outcome *profilerepo.OutcomeError
					if !errors.Is(err, profilerepo.ErrConflict) || !errors.As(err, &outcome) || outcome.Outcome.State != profilerepo.NotCommitted {
						t.Fatalf("missing stale condition: %v", err)
					}
					newer, readErr := repository.Read(ctx, raced)
					if readErr != nil || string(newer.Bytes) != "independent newer bytes" {
						t.Fatalf("lost newer writer: %s %v", newer.Bytes, readErr)
					}
					source, _ := repository.Read(ctx, "old")
					if raceDestination && !bytes.Equal(source.Bytes, legacyMutationDocument) {
						t.Fatal("destination race changed source")
					}
					if !raceDestination && (operation == "clone" || operation == "rename") {
						dest, _ := repository.Read(ctx, "new")
						if dest.Exists {
							t.Fatal("stale source published destination")
						}
					}
					if operation != "delete" && draft.Summaries()[0].Count != 2 {
						t.Fatal("stale save lost draft")
					}
					return builder.Outcome{}, err
				})
				args := []string{"profile", operation, "old"}
				if operation == "clone" || operation == "rename" {
					args = append(args, "--name", "new")
				}
				if code := app.Run(context.Background(), args); code != 1 || !strings.Contains(output.String(), "storage changed") {
					t.Fatalf("exit %d: %s", code, output)
				}
			})
		}
	}
}

func TestMutationNonregularAndOccupiedDestinationRefusal(t *testing.T) {
	for _, kind := range []string{"symlink", "directory", "hardlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			app, _, home, output := mutationFixture(t, legacyMutationDocument)
			path := filepath.Join(home, ".acs", "profiles", "old.json")
			outside := filepath.Join(home, "sentinel")
			if err := os.WriteFile(outside, legacyMutationDocument, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "symlink":
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(outside, path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := mutationTree(t, home)
			if code := app.Run(context.Background(), []string{"profile", "delete", "old", "--confirm", "old"}); code != 1 {
				t.Fatalf("exit %d: %s", code, output)
			}
			if !reflect.DeepEqual(before, mutationTree(t, home)) {
				t.Fatal("nonregular refusal changed tree")
			}
		})
	}
	for _, operation := range []string{"clone", "rename"} {
		t.Run(operation+"-occupied", func(t *testing.T) {
			app, _, home, output := mutationFixture(t, legacyMutationDocument)
			if err := os.WriteFile(filepath.Join(home, ".acs", "profiles", "new.json"), []byte("malformed occupied destination"), 0600); err != nil {
				t.Fatal(err)
			}
			before := mutationTree(t, home)
			if code := app.Run(context.Background(), []string{"profile", operation, "old", "--name", "new"}); code != 1 {
				t.Fatalf("exit %d: %s", code, output)
			}
			if !reflect.DeepEqual(before, mutationTree(t, home)) {
				t.Fatal("occupied destination changed tree")
			}
		})
	}
}

type outcomeMutationRepository struct {
	ProfileRepository
	outcome profilerepo.Outcome
	calls   int
}

func (r *outcomeMutationRepository) Apply(context.Context, profilerepo.Request) (profilerepo.Outcome, error) {
	r.calls++
	return r.outcome, context.Canceled
}

func TestMutationTruthfulTerminalOutcomes(t *testing.T) {
	for _, state := range []profilerepo.State{profilerepo.Committed, profilerepo.Unknown} {
		t.Run(string(state), func(t *testing.T) {
			app, repository, _, output := mutationFixture(t, legacyMutationDocument)
			injected := &outcomeMutationRepository{ProfileRepository: repository, outcome: profilerepo.Outcome{State: state, RecoveryRequired: true}}
			app.Repository = injected
			code := app.Run(context.Background(), []string{"profile", "delete", "old", "--confirm", "old"})
			if code != 1 || injected.calls != 1 {
				t.Fatalf("exit=%d calls=%d", code, injected.calls)
			}
			message := output.String()
			if strings.Contains(message, "cancelled") || !strings.Contains(message, "acs devin create-profile --name old") || !strings.Contains(message, "Cancel the builder if it opens") {
				t.Fatalf("false cancellation/missing guidance: %s", message)
			}
			if state == profilerepo.Committed && !strings.Contains(message, "mutation committed") {
				t.Fatalf("lost committed state: %s", message)
			}
			if state == profilerepo.Unknown && !strings.Contains(message, "Outcome unknown") {
				t.Fatalf("lost uncertain state: %s", message)
			}
		})
	}
}

func TestMutationExplicitReloadCreatesNewRevisionAndLeavesOldPreviewFrozen(t *testing.T) {
	app, repository, _, output := mutationFixture(t, legacyMutationDocument)
	app.MutationBuilder = mutationEditorFunc(func(ctx context.Context, _ string, draft category.Draft, options builder.MutationOptions, _ io.Reader, _ io.Writer) (builder.Outcome, error) {
		oldPreview, err := options.Prepare(draft)
		if err != nil {
			t.Fatal(err)
		}
		snapshot, err := repository.Read(ctx, "old")
		if err != nil {
			t.Fatal(err)
		}
		newer := []byte(`{"version":2,"name":"old","target":"devin","categories":{}}`)
		out, err := repository.Apply(ctx, profilerepo.ReplaceRequest{Name: "old", Expected: snapshot.Revision, Bytes: newer})
		if err != nil || out.State != profilerepo.Committed {
			t.Fatal(out, err)
		}
		reloaded, err := options.Reload(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if reloaded.Summaries()[0].Count != 0 || draft.Summaries()[0].Count != 2 {
			t.Fatal("reload mutated old draft")
		}
		if _, err := oldPreview.Save(ctx, reloaded); !errors.Is(err, profilerepo.ErrConflict) {
			t.Fatalf("reload changed old preview condition: %v", err)
		}
		freshPreview, err := options.Prepare(reloaded)
		if err != nil {
			t.Fatal(err)
		}
		path, err := freshPreview.Save(ctx, reloaded)
		return builder.Outcome{Create: err == nil, Draft: reloaded, Path: path}, err
	})
	if code := app.Run(context.Background(), []string{"profile", "edit", "old"}); code != 0 {
		t.Fatalf("reload commit: %d %s", code, output)
	}
}
