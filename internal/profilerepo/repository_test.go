package profilerepo

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestRevisionConditionsAndFutureBytes(t *testing.T) {
	r := New(t.TempDir())
	ctx := context.Background()
	a, err := r.Read(ctx, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.Read(ctx, "beta")
	if err != nil {
		t.Fatal(err)
	}
	if a.Exists || a.Revision == b.Revision {
		t.Fatal("absence must be explicit and name bound")
	}
	bytes := []byte("future codec\x00\xff\n")
	out, err := r.Apply(ctx, CreateRequest{Name: "alpha", Expected: a.Revision, Bytes: bytes})
	if err != nil || out.State != Committed {
		t.Fatalf("create: %+v %v", out, err)
	}
	first, err := r.Read(ctx, "alpha")
	if err != nil || string(first.Bytes) != string(bytes) {
		t.Fatalf("exact bytes: %+v %v", first, err)
	}
	out, err = r.Apply(ctx, ReplaceRequest{Name: "alpha", Expected: first.Revision, Bytes: nil})
	if err != nil || out.State != Committed {
		t.Fatalf("empty replace: %+v %v", out, err)
	}
	empty, err := r.Read(ctx, "alpha")
	if err != nil || !empty.Exists || len(empty.Bytes) != 0 || empty.Revision == a.Revision {
		t.Fatal("empty present is not absent", err)
	}
	out, err = r.Apply(ctx, DeleteRequest{Name: "alpha", Expected: first.Revision})
	if !errors.Is(err, ErrConflict) || out.State != NotCommitted {
		t.Fatalf("stale: %+v %v", out, err)
	}
	if _, err = r.Apply(ctx, ReplaceRequest{Name: "alpha", Expected: empty.Revision, Bytes: bytes}); err != nil {
		t.Fatal(err)
	}
	again, _ := r.Read(ctx, "alpha")
	if again.Revision != first.Revision {
		t.Fatal("content ABA is intentional")
	}
	info, err := os.Stat(filepath.Join(r.acsHome, "profiles", "alpha.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("private bytes", err)
	}
}

func TestPublicationSyncFailureIsNotSuccess(t *testing.T) {
	r := New(t.TempDir())
	ctx := context.Background()
	s, _ := r.Read(ctx, "alpha")
	failure := errors.New("directory sync failed")
	r.hook = func(point string) error {
		if point == "publish.sync.before" {
			return failure
		}
		return nil
	}
	out, err := r.Apply(ctx, CreateRequest{Name: "alpha", Expected: s.Revision, Bytes: []byte("new")})
	if !errors.Is(err, failure) || out.State != Unknown || !out.RecoveryRequired {
		t.Fatalf("hidden durability failure: %+v %v", out, err)
	}
	r.hook = nil
	out, err = r.Recover(ctx)
	if err != nil || out.State != Committed {
		t.Fatalf("recover: %+v %v", out, err)
	}
	if _, err = r.Recover(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestNarrowOperationsRespectAllConditions(t *testing.T) {
	ctx := context.Background()
	r := seeded(t)
	source, _ := r.Read(ctx, "source")
	destination, _ := r.Read(ctx, "destination")
	for _, request := range []Request{
		CreateRequest{"destination", source.Revision, []byte("x")},
		ReplaceRequest{"source", Revision{}, []byte("x")},
		DeleteRequest{"source", destination.Revision},
		CloneRequest{"source", "destination", destination.Revision, destination.Revision, []byte("x")},
		RenameRequest{"source", "source", source.Revision, source.Revision, []byte("x")},
	} {
		out, err := r.Apply(ctx, request)
		if !errors.Is(err, ErrConflict) || out.State != NotCommitted {
			t.Fatalf("invalid condition: %+v %v", out, err)
		}
	}
	if _, err := r.Apply(ctx, ReplaceRequest{"source", source.Revision, []byte("new source")}); err != nil {
		t.Fatal(err)
	}
	for _, request := range []Request{
		CloneRequest{"source", "destination", source.Revision, destination.Revision, nil},
		RenameRequest{"source", "destination", source.Revision, destination.Revision, nil},
	} {
		out, err := r.Apply(ctx, request)
		if !errors.Is(err, ErrConflict) || out.State != NotCommitted {
			t.Fatalf("stale source: %+v %v", out, err)
		}
	}
	current, _ := r.Read(ctx, "source")
	if _, err := r.Apply(ctx, DeleteRequest{"source", current.Revision}); err != nil {
		t.Fatal(err)
	}
	absent, _ := r.Read(ctx, "source")
	expected, _ := AbsentRevision("source")
	if absent.Exists || absent.Revision != expected {
		t.Fatal("deletion did not restore named absence")
	}
}
