package cli

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/builder"
	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
)

type mutationCompletionWriter struct {
	short bool
	calls int
	allow int
}

func (w *mutationCompletionWriter) Write(p []byte) (int, error) {
	w.calls++
	if w.calls <= w.allow {
		return len(p), nil
	}
	if w.short {
		return len(p) / 2, nil
	}
	return 0, io.ErrClosedPipe
}

type completionRepository struct {
	*profilerepo.Repository
	applies int
}

func (r *completionRepository) Apply(ctx context.Context, request profilerepo.Request) (profilerepo.Outcome, error) {
	r.applies++
	return r.Repository.Apply(ctx, request)
}

func TestMutationAcknowledgmentFailurePreservesCommit(t *testing.T) {
	for _, operation := range []string{"edit", "clone", "rename", "delete"} {
		for _, short := range []bool{false, true} {
			t.Run(operation+map[bool]string{false: "/error", true: "/short"}[short], func(t *testing.T) {
				app, base, _, _ := mutationFixture(t, mutationDocument)
				repository := &completionRepository{Repository: base}
				app.Repository = repository
				writer := &mutationCompletionWriter{short: short}
				var stderr bytes.Buffer
				app.Output, app.ErrorOutput = writer, &stderr
				app.MutationBuilder = mutationEditorFunc(func(ctx context.Context, _ string, draft category.Draft, options builder.MutationOptions, _ io.Reader, _ io.Writer) (builder.Outcome, error) {
					prepared, err := options.Prepare(draft)
					if err != nil {
						return builder.Outcome{}, err
					}
					path, err := prepared.Save(ctx, draft)
					return builder.Outcome{Create: err == nil, Path: path, Draft: draft}, err
				})
				name := "old"
				args := []string{"profile", operation, "old"}
				if operation == "clone" || operation == "rename" {
					name = "new"
					args = append(args, "--name", name)
				}
				if operation == "delete" {
					args = append(args, "--confirm", "old")
					writer.allow = 1
				}
				code := app.Run(context.Background(), args)
				if repository.applies != 1 {
					t.Fatalf("lost/replayed mutation: applies=%d code=%d stderr=%s", repository.applies, code, stderr.String())
				}
				snapshot, err := base.Read(context.Background(), name)
				if err != nil || snapshot.Exists != (operation != "delete") {
					t.Fatalf("lost committed state: %+v %v", snapshot, err)
				}
				if code != 1 || !strings.Contains(stderr.String(), "committed") || !strings.Contains(stderr.String(), "reporting failed") || strings.Contains(stderr.String(), "acs profile recover") {
					t.Fatalf("code=%d stderr=%s", code, stderr.String())
				}
				if writer.calls != writer.allow+1 {
					t.Fatalf("retried acknowledgment: %d", writer.calls)
				}
			})
		}
	}
}
func TestDeletePreviewFailurePreventsCommit(t *testing.T) {
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "short"}[short], func(t *testing.T) {
			app, base, _, _ := mutationFixture(t, mutationDocument)
			repository := &completionRepository{Repository: base}
			app.Repository = repository
			writer := &mutationCompletionWriter{short: short}
			var stderr bytes.Buffer
			app.Output, app.ErrorOutput = writer, &stderr
			code := app.Run(context.Background(), []string{"profile", "delete", "old", "--confirm", "old"})
			snapshot, err := base.Read(context.Background(), "old")
			if code != 1 || repository.applies != 0 || writer.calls != 1 || err != nil || !bytes.Equal(snapshot.Bytes, mutationDocument) {
				t.Fatalf("preview failure mutated storage: code=%d applies=%d writes=%d snapshot=%+v err=%v", code, repository.applies, writer.calls, snapshot, err)
			}
			if !strings.Contains(stderr.String(), "not committed") || strings.Contains(stderr.String(), "acs profile recover") {
				t.Fatalf("false outcome: %s", stderr.String())
			}
		})
	}
}
func TestProfileRecoveryShortAcknowledgmentDoesNotReplay(t *testing.T) {
	for _, jsonOutput := range []bool{false, true} {
		repository := &recoveryRepository{outcome: profilerepo.Outcome{State: profilerepo.Committed}}
		writer := &mutationCompletionWriter{short: true}
		var stderr bytes.Buffer
		app := App{Repository: repository, Output: writer, ErrorOutput: &stderr}
		args := []string{"profile", "recover"}
		if jsonOutput {
			args = append(args, "--json")
		}
		if code := app.Run(context.Background(), args); code != 1 || repository.calls != 1 || writer.calls != 1 || !strings.Contains(stderr.String(), "committed") || !strings.Contains(stderr.String(), "reporting failed") {
			t.Fatalf("code=%d calls=%d writes=%d stderr=%s", code, repository.calls, writer.calls, stderr.String())
		}
	}
}
