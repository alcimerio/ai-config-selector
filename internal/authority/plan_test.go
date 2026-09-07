package authority

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestPlanOwnsImmutableRequirementsAndSanitizedAuthorityExplanation(t *testing.T) {
	requirements := TargetRequirements{
		Recipe: RecipeDevin, Executable: "/private/target", RuntimeInputs: []string{"/private/runtime"}, RuntimeInputIDs: []string{"target-runtime"}, ExistingHomeDirectory: "/private/home",
	}
	plan := New(nil, launch.WorkspaceAccessReadOnly, 3, "devin", requirements)
	requirements.RuntimeInputs[0] = "/changed"

	resolved := plan.Requirements()
	resolved.RuntimeInputs[0] = "/also-changed"
	if got := plan.Requirements().RuntimeInputs[0]; got != "/private/runtime" {
		t.Fatalf("plan requirements were mutable: %q", got)
	}
	explanation, err := plan.Plan(context.Background(), "/private/workspace")
	if err != nil {
		t.Fatal(err)
	}
	if len(explanation.Sections) != 1 || explanation.Sections[0].Title != "Resolved execution authority:" {
		t.Fatalf("authority explanation = %#v", explanation)
	}
	for _, item := range explanation.Sections[0].Items {
		for _, detail := range item.Details {
			if detail.Value == "/private/target" || detail.Value == "/private/runtime" || detail.Value == "/private/home" || detail.Value == "/private/workspace" {
				t.Fatalf("explanation exposed intrinsic path: %#v", explanation)
			}
		}
	}
}

func TestAuthorityManifestIsCanonicalAndContainsIntrinsicNativeGrants(t *testing.T) {
	firstSemantics := CodexSemantics()
	secondSemantics := CodexSemantics()
	for left, right := 0, len(secondSemantics.Configuration)-1; left < right; left, right = left+1, right-1 {
		secondSemantics.Configuration[left], secondSemantics.Configuration[right] = secondSemantics.Configuration[right], secondSemantics.Configuration[left]
	}
	first := New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", TargetRequirements{Recipe: RecipeCodex, ExecutableRequirementID: "codex-cli-0.149.1", RuntimeInputIDs: []string{"runtime-b", "runtime-a"}, RuntimeInputs: []string{"/private/b", "/private/a"}, Semantics: firstSemantics})
	second := New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", TargetRequirements{Recipe: RecipeCodex, ExecutableRequirementID: "codex-cli-0.149.1", RuntimeInputIDs: []string{"runtime-a", "runtime-b"}, RuntimeInputs: []string{"/elsewhere/a", "/elsewhere/b"}, Semantics: secondSemantics})
	if first.AuthorityDigest() != second.AuthorityDigest() {
		t.Fatal("registration or local-binding order changed canonical semantic digest")
	}
	explanation := first.Explanation()
	want := map[string]bool{
		"runtime.devices":       false,
		"runtime.environment":   false,
		"runtime.mach-services": false,
		"runtime.metadata":      false,
		"runtime.network":       false,
		"runtime.process":       false,
		"runtime.session":       false,
		"runtime.sysctls":       false,
		"runtime.system-read":   false,
		"runtime.terminal":      false,
	}
	for _, fact := range explanation.Effective {
		if _, exists := want[fact.ID]; exists {
			want[fact.ID] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("missing intrinsic effective fact %q", id)
		}
	}
	if got := factByID(t, explanation.Effective, "runtime.mach-services").Value.Names; !reflect.DeepEqual(got, []string{"com.apple.SecurityServer", "com.apple.trustd.agent"}) {
		t.Fatalf("Mach services = %q", got)
	}
	if got := factByID(t, explanation.Effective, "runtime.sysctls").Value.Names; !reflect.DeepEqual(got, []string{"hw.pagesize", "hw.pagesize_compat", "hw.ncpu"}) {
		t.Fatalf("sysctls = %q", got)
	}
	explanation.Effective[0].Value.Names = append(explanation.Effective[0].Value.Names, "mutated")
	if reflect.DeepEqual(explanation.Effective, first.Explanation().Effective) {
		t.Fatal("test mutation did not alter returned explanation")
	}
}

func factByID(t *testing.T, facts []Fact, id string) Fact {
	t.Helper()
	for _, fact := range facts {
		if fact.ID == id {
			return fact
		}
	}
	t.Fatalf("fact %q not found", id)
	return Fact{}
}

func TestAuthorityDigestTracksSemanticAuthorityButNotPrivateBindings(t *testing.T) {
	base := New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", TargetRequirements{
		Recipe: RecipeCodex, Executable: "/private/one/codex", RuntimeInputs: []string{"/private/runtime"}, RuntimeInputIDs: []string{"codex-runtime"},
	}).WithAuthRef("first")
	sameSemantics := New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", TargetRequirements{
		Recipe: RecipeCodex, Executable: "/other/private/codex", RuntimeInputs: []string{"/other/runtime"}, RuntimeInputIDs: []string{"codex-runtime"},
	}).WithAuthRef("second")
	if base.AuthorityDigest() != sameSemantics.AuthorityDigest() {
		t.Fatal("private local bindings changed semantic authority digest")
	}
	writable := New(nil, launch.WorkspaceAccessReadWrite, 3, "codex", base.Requirements()).WithAuthRef("first")
	if base.AuthorityDigest() == writable.AuthorityDigest() {
		t.Fatal("workspace authority did not change digest")
	}
	if !strings.HasPrefix(base.AuthorityDigest(), "sha256:") || len(base.AuthorityDigest()) != len("sha256:")+64 {
		t.Fatalf("digest = %q", base.AuthorityDigest())
	}
}

func TestCommandDigestIncludesSelectionFormAndCount(t *testing.T) {
	base := New(nil, launch.WorkspaceAccessReadOnly, 3, "")
	abs, err := base.ForCommandIntent("absolute path (hidden)", 2)
	if err != nil {
		t.Fatal(err)
	}
	same, _ := base.ForCommandIntent("absolute path (hidden)", 2)
	if abs.AuthorityDigest() != same.AuthorityDigest() {
		t.Fatal("equal sanitized command intent produced different digest")
	}
	relative, _ := base.ForCommandIntent("workspace-relative ./ path (hidden)", 2)
	differentCount, _ := base.ForCommandIntent("absolute path (hidden)", 3)
	if abs.AuthorityDigest() == relative.AuthorityDigest() || abs.AuthorityDigest() == differentCount.AuthorityDigest() {
		t.Fatal("command executable form or literal argument count did not change digest")
	}
}
