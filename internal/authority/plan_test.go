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
	if got := factByID(t, explanation.Effective, "runtime.sysctls").Value.Names; !reflect.DeepEqual(got, []string{"hw.ncpu", "hw.pagesize", "hw.pagesize_compat"}) {
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

func TestAuthorityDigestTracksEveryRuntimeAuthorityFieldAndIgnoresSetOrder(t *testing.T) {
	base := New(nil, launch.WorkspaceAccessReadOnly, 3, "")
	mutations := []struct {
		name   string
		mutate func(*launch.RuntimeAuthority)
	}{
		{"version", func(value *launch.RuntimeAuthority) { value.Version++ }},
		{"process", func(value *launch.RuntimeAuthority) { value.ProcessMode += "-changed" }},
		{"system-read", func(value *launch.RuntimeAuthority) { value.SystemReadMode += "-changed" }},
		{"metadata", func(value *launch.RuntimeAuthority) { value.MetadataMode += "-changed" }},
		{"session", func(value *launch.RuntimeAuthority) { value.SessionAccess += "-changed" }},
		{"network", func(value *launch.RuntimeAuthority) { value.NetworkMode += "-changed" }},
		{"terminal", func(value *launch.RuntimeAuthority) { value.TerminalMode += "-changed" }},
		{"device", func(value *launch.RuntimeAuthority) { value.DeviceMode += "-changed" }},
		{"fixed-path", func(value *launch.RuntimeAuthority) { value.FixedPath += ":/changed" }},
		{"synthetic-environment", func(value *launch.RuntimeAuthority) {
			value.SyntheticEnvironmentNames = append(value.SyntheticEnvironmentNames, "CHANGED")
		}},
		{"inherited-environment", func(value *launch.RuntimeAuthority) {
			value.InheritedEnvironmentNames = append(value.InheritedEnvironmentNames, "CHANGED")
		}},
		{"sysctls", func(value *launch.RuntimeAuthority) { value.SysctlNames = append(value.SysctlNames, "changed") }},
		{"mach-services", func(value *launch.RuntimeAuthority) { value.MachServices = append(value.MachServices, "changed") }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := base
			changed.runtimeAuthority = base.runtimeAuthority.Clone()
			mutation.mutate(&changed.runtimeAuthority)
			changed.explanation = buildExplanation(changed)
			if changed.AuthorityDigest() == base.AuthorityDigest() {
				t.Fatalf("runtime authority field %q is absent from semantic digest", mutation.name)
			}
		})
	}

	reordered := base
	reordered.runtimeAuthority = base.runtimeAuthority.Clone()
	for _, values := range []*[]string{&reordered.runtimeAuthority.SyntheticEnvironmentNames, &reordered.runtimeAuthority.InheritedEnvironmentNames, &reordered.runtimeAuthority.SysctlNames, &reordered.runtimeAuthority.MachServices} {
		for left, right := 0, len(*values)-1; left < right; left, right = left+1, right-1 {
			(*values)[left], (*values)[right] = (*values)[right], (*values)[left]
		}
	}
	reordered.explanation = buildExplanation(reordered)
	if reordered.AuthorityDigest() != base.AuthorityDigest() {
		t.Fatal("set-like runtime registration order changed semantic digest")
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

func TestPlanDeepCopiesTargetSemanticsAndExplanationPointers(t *testing.T) {
	semantics := CodexSemantics()
	requirements := TargetRequirements{Recipe: RecipeCodex, ExecutableRequirementID: "codex-cli", Semantics: semantics}
	plan := New(nil, launch.WorkspaceAccessReadOnly, 3, "codex", requirements)

	semantics.Configuration[0].Mode = "mutated"
	semantics.Unsupported[0].Mode = "mutated"
	requirements.Semantics.CredentialProjection = "mutated"
	if got := plan.Requirements().Semantics; !reflect.DeepEqual(got, CodexSemantics()) {
		t.Fatalf("caller mutation changed captured target semantics: %#v", got)
	}

	returned := plan.Requirements()
	returned.Semantics.Configuration[0].Mode = "returned-mutation"
	returned.Semantics.Unsupported[0].Mode = "returned-mutation"
	returned.Semantics.CredentialProjection = "returned-mutation"
	if got := plan.Requirements().Semantics; !reflect.DeepEqual(got, CodexSemantics()) {
		t.Fatalf("returned requirements alias captured target semantics: %#v", got)
	}
	devinSemantics := DevinSemantics()
	devinPlan := New(nil, launch.WorkspaceAccessReadOnly, 3, "devin", TargetRequirements{Recipe: RecipeDevin, ExecutableRequirementID: "devin-cli", Semantics: devinSemantics})
	devinSemantics.Preflights[0].Mode = "mutated"
	devinSemantics.Inheritance[0].LogicalRoots[0] = "mutated"
	devinReturned := devinPlan.Requirements()
	devinReturned.Semantics.Preflights[0].Mode = "returned-mutation"
	devinReturned.Semantics.Inheritance[0].LogicalRoots[0] = "returned-mutation"
	if got := devinPlan.Requirements().Semantics; !reflect.DeepEqual(got, DevinSemantics()) {
		t.Fatalf("Devin preflight/inheritance slices alias captured plan: %#v", got)
	}

	command, err := New(nil, launch.WorkspaceAccessReadOnly, 3, "").ForCommandIntent("absolute path (hidden)", 2)
	if err != nil {
		t.Fatal(err)
	}
	explanation := command.Explanation()
	literal := factByID(t, explanation.Requested, "run.literal-argv")
	if literal.Value.Count == nil {
		t.Fatal("command explanation omitted argument count")
	}
	digest := command.AuthorityDigest()
	secondBeforeMutation := factByID(t, command.Explanation().Requested, "run.literal-argv")
	if literal.Value.Count == secondBeforeMutation.Value.Count {
		t.Fatal("separate explanation snapshots share the argument-count pointer")
	}
	*literal.Value.Count = 99
	if got := factByID(t, command.Explanation().Requested, "run.literal-argv").Value.Count; got == nil || *got != 2 {
		t.Fatalf("returned explanation count aliased immutable plan: %v", got)
	}
	if command.AuthorityDigest() != digest {
		t.Fatal("returned explanation mutation changed immutable authority digest")
	}
}

func TestAuthorityDigestTracksEveryTypedTargetSemanticAndShippedValidationRejectsMutation(t *testing.T) {
	tests := []struct {
		name   string
		recipe Recipe
		base   func() TargetSemantics
		mutate func(*TargetSemantics)
	}{
		{name: "codex-version", recipe: RecipeCodex, base: CodexSemantics, mutate: func(value *TargetSemantics) { value.Version++ }},
		{name: "codex-authentication", recipe: RecipeCodex, base: CodexSemantics, mutate: func(value *TargetSemantics) { value.AuthenticationMode += "-changed" }},
		{name: "codex-configuration-id", recipe: RecipeCodex, base: CodexSemantics, mutate: func(value *TargetSemantics) { value.Configuration[0].ID += "-changed" }},
		{name: "codex-configuration-mode", recipe: RecipeCodex, base: CodexSemantics, mutate: func(value *TargetSemantics) { value.Configuration[0].Mode += "-changed" }},
		{name: "codex-unsupported-id", recipe: RecipeCodex, base: CodexSemantics, mutate: func(value *TargetSemantics) { value.Unsupported[0].ID += "-changed" }},
		{name: "codex-unsupported-mode", recipe: RecipeCodex, base: CodexSemantics, mutate: func(value *TargetSemantics) { value.Unsupported[0].Mode += "-changed" }},
		{name: "codex-credential-projection", recipe: RecipeCodex, base: CodexSemantics, mutate: func(value *TargetSemantics) { value.CredentialProjection += "-changed" }},
		{name: "devin-preflight-id", recipe: RecipeDevin, base: DevinSemantics, mutate: func(value *TargetSemantics) { value.Preflights[0].ID += "-changed" }},
		{name: "devin-preflight-mode", recipe: RecipeDevin, base: DevinSemantics, mutate: func(value *TargetSemantics) { value.Preflights[0].Mode += "-changed" }},
		{name: "devin-inheritance-id", recipe: RecipeDevin, base: DevinSemantics, mutate: func(value *TargetSemantics) { value.Inheritance[0].ID += "-changed" }},
		{name: "devin-inheritance-root", recipe: RecipeDevin, base: DevinSemantics, mutate: func(value *TargetSemantics) { value.Inheritance[0].LogicalRoots[0] += "-changed" }},
		{name: "devin-credential-projection", recipe: RecipeDevin, base: DevinSemantics, mutate: func(value *TargetSemantics) { value.CredentialProjection += "-changed" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baseline := test.base()
			changed := baseline.Clone()
			test.mutate(&changed)
			baselinePlan := New(nil, launch.WorkspaceAccessReadOnly, 3, string(test.recipe), TargetRequirements{Recipe: test.recipe, ExecutableRequirementID: string(test.recipe) + "-cli", Semantics: baseline})
			changedPlan := New(nil, launch.WorkspaceAccessReadOnly, 3, string(test.recipe), TargetRequirements{Recipe: test.recipe, ExecutableRequirementID: string(test.recipe) + "-cli", Semantics: changed})
			if baselinePlan.AuthorityDigest() == changedPlan.AuthorityDigest() {
				t.Fatal("typed target semantic mutation was absent from authority digest")
			}
			if changed.Supports(test.recipe) {
				t.Fatal("shipped target validation accepted mutated semantics")
			}
		})
	}
}
