package devinruntime

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"os"

	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func TestInterpretCatalogExcludesBuiltinsAndKnownProjectBundles(t *testing.T) {
	home := t.TempDir()
	work := t.TempDir()
	managed := filepath.Join(home, ".config", "devin", "skills", "selected")
	project := filepath.Join(work, ".agents", "skills", "project")
	for _, path := range []string{managed, project} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	output := []byte(`[
  {"name":"built-in","provider":"Builtin","base_dir":"/not-managed"},
  {"name":"selected","provider":"Devin","base_dir":` + quoteJSON(t, managed) + `},
  {"name":"project","provider":"Devin","base_dir":` + quoteJSON(t, project) + `}
]`)

	observation, reason := InterpretCatalog(home, work, output)
	if reason != 0 {
		t.Fatalf("interpret reason = %d, want success", reason)
	}
	want := []skills.SkillReference{{Source: GlobalSourceDevinConfig, RelativePath: "selected"}}
	if got := observation.ManagedReferences(); !reflect.DeepEqual(got, want) {
		t.Fatalf("managed references = %#v, want %#v", got, want)
	}
	if observation.HasUnmanagedSource() {
		t.Fatal("known sources were marked unmanaged")
	}
}

func TestInterpretCatalogCanonicalizesAliasedHome(t *testing.T) {
	realHome := filepath.Join(t.TempDir(), "real-home")
	aliasParent := t.TempDir()
	aliasHome := filepath.Join(aliasParent, "home-alias")
	managed := filepath.Join(realHome, ".config", "devin", "skills", "selected")
	if err := os.MkdirAll(managed, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realHome, aliasHome); err != nil {
		t.Fatal(err)
	}

	output := []byte(`[{"name":"selected","provider":"Devin","base_dir":` + quoteJSON(t, managed) + `}]`)
	observation, reason := InterpretCatalog(aliasHome, t.TempDir(), output)
	if reason != 0 || observation.HasUnmanagedSource() {
		t.Fatalf("aliased home observation = %#v, reason = %d", observation, reason)
	}
	if got, want := observation.ManagedReferences(), []skills.SkillReference{{Source: GlobalSourceDevinConfig, RelativePath: "selected"}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("managed references = %#v, want %#v", got, want)
	}
}

func TestInterpretCatalogRejectsEscapedManagedRootAndUnknownGlobalSource(t *testing.T) {
	home := t.TempDir()
	external := filepath.Join(t.TempDir(), "external")
	if err := os.MkdirAll(filepath.Join(external, "selected"), 0o700); err != nil {
		t.Fatal(err)
	}
	managedRoot := filepath.Join(home, ".config", "devin", "skills")
	if err := os.MkdirAll(filepath.Dir(managedRoot), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, managedRoot); err != nil {
		t.Fatal(err)
	}
	output := []byte(`[{"name":"selected","provider":"Devin","base_dir":` + quoteJSON(t, filepath.Join(external, "selected")) + `}]`)

	observation, reason := InterpretCatalog(home, t.TempDir(), output)
	if reason != 0 {
		t.Fatalf("interpret reason = %d, want success", reason)
	}
	if !observation.HasUnmanagedSource() {
		t.Fatal("escaped source root was not rejected as unknown global source")
	}
}

func TestInterpretCatalogRejectsMalformedOutput(t *testing.T) {
	_, reason := InterpretCatalog(t.TempDir(), t.TempDir(), []byte(`{"not":"an array"}`))
	if reason != ReasonSkillInspectionOutputInvalid {
		t.Fatalf("reason = %d, want %d", reason, ReasonSkillInspectionOutputInvalid)
	}
}

func TestCatalogReferenceComparisonIsStableAndAuthenticationRecognitionIsExact(t *testing.T) {
	left := []skills.SkillReference{{Source: GlobalSourceSharedAgents, RelativePath: "b"}, {Source: GlobalSourceDevinConfig, RelativePath: "a"}}
	SortSkillReferences(left)
	right := []skills.SkillReference{{Source: GlobalSourceDevinConfig, RelativePath: "a"}, {Source: GlobalSourceSharedAgents, RelativePath: "b"}}
	if !EqualSkillReferences(left, right) {
		t.Fatal("sorted selected references did not compare equal")
	}
	if !AuthenticationLoggedIn([]byte(" \nLogged in (via Devin).\n")) {
		t.Fatal("logged-in output was not recognized")
	}
	if AuthenticationLoggedIn([]byte("Not logged in. token=private")) {
		t.Fatal("unavailable authentication was accepted")
	}
}

func TestPreflightErrorsRemainRedactedAndCategorized(t *testing.T) {
	err := NewPreflightError(Capability("private\n\x1b"), ReasonVerificationInterrupted)
	if got, want := err.Category(), DevinPreflightFailed; got != want {
		t.Fatalf("category = %q, want %q", got, want)
	}
	if message := err.Error(); !strings.HasPrefix(message, string(DevinPreflightFailed)+":") || strings.ContainsAny(message, "\n\r\x1b") || strings.Contains(message, "private") {
		t.Fatalf("redacted error = %q", message)
	}
}

func quoteJSON(t *testing.T, value string) string {
	t.Helper()
	quoted := strings.ReplaceAll(value, `\`, `\\`)
	quoted = strings.ReplaceAll(quoted, `"`, `\"`)
	return `"` + quoted + `"`
}
