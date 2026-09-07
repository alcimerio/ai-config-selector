// Package authority owns the immutable resolved plan shared by explanation,
// materialization, executor checks, probes, and attached target execution.
package authority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"reflect"
	"sort"

	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

type Contribution struct {
	ID    string
	Value launch.Contribution
}

type Recipe string

const (
	RecipeShell   Recipe = "shell"
	RecipeDevin   Recipe = "devin"
	RecipeCodex   Recipe = "codex"
	RecipeCommand Recipe = "command"
)

// TargetRequirements are registered once during application assembly. They
// are intrinsic target inputs, not per-launch adapter authority, and are never
// rendered by the sanitized explanation.
type TargetRequirements struct {
	Recipe                  Recipe
	Executable              string
	ExecutableRequirementID string
	RuntimeInputs           []string
	RuntimeInputIDs         []string
	ExistingHomeDirectory   string
	Semantics               TargetSemantics
}

type ConfigurationDecision struct {
	ID, Mode string
}

type InheritanceRule struct {
	ID           string
	LogicalRoots []string
}

// TargetSemantics is registered beside the executable and consumed by both
// target runtime composition and semantic explanation.
type TargetSemantics struct {
	Version              int
	AuthenticationMode   string
	Configuration        []ConfigurationDecision
	Preflights           []ConfigurationDecision
	Unsupported          []ConfigurationDecision
	Inheritance          []InheritanceRule
	CredentialProjection string
}

func DevinSemantics() TargetSemantics {
	return TargetSemantics{Version: 1,
		Preflights:           []ConfigurationDecision{{ID: "devin.preflight.skills", Mode: "contained-exact-catalog"}, {ID: "devin.preflight.authentication", Mode: "contained-status"}},
		Inheritance:          []InheritanceRule{{ID: "devin.project-skills", LogicalRoots: []string{".devin/skills", ".agents/skills"}}},
		CredentialProjection: "optional-allowlisted-value-omitted"}
}

func CodexSemantics() TargetSemantics {
	return TargetSemantics{Version: 1, AuthenticationMode: "required-value-omitted", Configuration: []ConfigurationDecision{
		{ID: "codex.approval", Mode: "never"}, {ID: "codex.apps", Mode: "disabled"},
		{ID: "codex.auth-storage", Mode: "file-in-session"}, {ID: "codex.endpoint", Mode: "chatgpt-backend-api"},
		{ID: "codex.login", Mode: "chatgpt"}, {ID: "codex.mcp", Mode: "disabled"},
		{ID: "codex.plugins", Mode: "disabled"}, {ID: "codex.project-trust", Mode: "untrusted"},
		{ID: "codex.provider", Mode: "openai"}, {ID: "codex.sandbox", Mode: "danger-full-access-under-acs"},
	}, Unsupported: []ConfigurationDecision{
		{ID: "codex.global-auth-fallback", Mode: "disabled"}, {ID: "codex.target-approval-prompts", Mode: "disabled"}, {ID: "codex.target-sandbox-enforcement", Mode: "disabled-under-acs"},
	}, CredentialProjection: "required-named-auth-to-session-file-value-omitted"}
}

func (value TargetSemantics) Supports(recipe Recipe) bool {
	switch recipe {
	case RecipeDevin:
		return reflect.DeepEqual(value, DevinSemantics())
	case RecipeCodex:
		return reflect.DeepEqual(value, CodexSemantics())
	default:
		return value.Version == 0 && value.AuthenticationMode == "" && len(value.Configuration) == 0 && len(value.Preflights) == 0 && len(value.Unsupported) == 0 && len(value.Inheritance) == 0 && value.CredentialProjection == ""
	}
}

func (value TargetSemantics) ConfigurationMode(id string) (string, bool) {
	for _, decision := range value.Configuration {
		if decision.ID == id {
			return decision.Mode, true
		}
	}
	return "", false
}

func (value TargetSemantics) PreflightMode(id string) (string, bool) {
	for _, decision := range value.Preflights {
		if decision.ID == id {
			return decision.Mode, true
		}
	}
	return "", false
}

const AuthorityManifestVersion = 1

// Fact is one typed, sanitized semantic decision captured when the executable
// authority plan is constructed. Value is a stable enum or logical identity,
// never a canonical host path, credential, environment value, or raw policy.
type FactSource struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Version int    `json:"version,omitempty"`
}

type SkillIdentity struct {
	Source       string `json:"source"`
	RelativePath string `json:"relativePath"`
}

type FactValue struct {
	Access          string         `json:"access,omitempty"`
	Mode            string         `json:"mode,omitempty"`
	LogicalLocation string         `json:"logicalLocation,omitempty"`
	RequirementID   string         `json:"requirementId,omitempty"`
	Identity        *SkillIdentity `json:"identity,omitempty"`
	Names           []string       `json:"names,omitempty"`
	Count           *int           `json:"count,omitempty"`
}

type Fact struct {
	ID     string     `json:"id"`
	Kind   string     `json:"kind"`
	Value  FactValue  `json:"value"`
	Reason string     `json:"reason"`
	Source FactSource `json:"source"`
}

type Facts struct {
	Requested   []Fact
	TargetAdded []Fact
	Effective   []Fact
	Unsupported []Fact
}

// Explanation is a copy of the immutable semantic manifest. The digest
// identifies these semantic facts, not excluded machine-local bindings.
type Explanation struct {
	AuthorityManifestVersion int    `json:"authorityManifestVersion"`
	AuthorityDigest          string `json:"authorityDigest"`
	Requested                []Fact `json:"requested"`
	TargetAdded              []Fact `json:"targetAdded"`
	Effective                []Fact `json:"effective"`
	Unsupported              []Fact `json:"unsupported"`
}

type semanticContributor interface{ SemanticFacts(int, string) Facts }

type Plan struct {
	contributions    []Contribution
	workspaceAccess  launch.WorkspaceAccess
	sourceVersion    int
	overlay          string
	requirements     TargetRequirements
	authRef          string
	authSource       string
	runtimeAuthority launch.RuntimeAuthority
	commandForm      string
	commandArguments int
	explanation      Explanation
}

func New(contributions []Contribution, workspaceAccess launch.WorkspaceAccess, sourceVersion int, overlay string, supplied ...TargetRequirements) Plan {
	requirements := TargetRequirements{Recipe: RecipeShell}
	if overlay != "" {
		requirements.Recipe = RecipeDevin
	}
	if len(supplied) != 0 {
		requirements = supplied[0]
		requirements.RuntimeInputs = append([]string(nil), requirements.RuntimeInputs...)
		requirements.RuntimeInputIDs = append([]string(nil), requirements.RuntimeInputIDs...)
		requirements.Semantics = requirements.Semantics.Clone()
	}
	if reflect.DeepEqual(requirements.Semantics, TargetSemantics{}) {
		if requirements.Recipe == RecipeCodex {
			requirements.Semantics = CodexSemantics()
		}
		if requirements.Recipe == RecipeDevin {
			requirements.Semantics = DevinSemantics()
		}
	}
	plan := Plan{contributions: append([]Contribution(nil), contributions...), workspaceAccess: workspaceAccess, sourceVersion: sourceVersion, overlay: overlay, requirements: requirements, runtimeAuthority: launch.DefaultRuntimeAuthority()}
	plan.explanation = buildExplanation(plan)
	return plan
}
func (plan Plan) WorkspaceAccess() launch.WorkspaceAccess {
	if plan.workspaceAccess == "" {
		return launch.WorkspaceAccessReadWrite
	}
	return plan.workspaceAccess
}
func (plan Plan) SourceVersion() int { return plan.sourceVersion }
func (plan Plan) Overlay() string    { return plan.overlay }
func (plan Plan) AuthRef() string    { return plan.authRef }

// WithAuthRef returns an independent resolved plan with one canonical opaque
// authentication reference. Validation belongs to the target adapter.
func (plan Plan) WithAuthRef(value string) Plan {
	plan.authRef, plan.authSource = value, "overlay"
	plan.explanation = buildExplanation(plan)
	return plan
}

// WithAuthOverride selects an opaque one-run binding without placing its value
// in the semantic manifest. The binding source is a semantic recipe decision.
func (plan Plan) WithAuthOverride(value string) Plan {
	plan.authRef, plan.authSource = value, "one_run_override"
	plan.explanation = buildExplanation(plan)
	return plan
}

// ForCommand returns an independent authority plan for one explicit command.
// The command itself remains a separate declarative executor input; it cannot
// add filesystem, environment, credential, or sandbox authority.
func (plan Plan) ForCommand() (Plan, error) {
	return plan.ForCommandIntent("validated", 0)
}

func (plan Plan) ForCommandIntent(form string, argumentCount int) (Plan, error) {
	if plan.requirements.Recipe != RecipeShell || plan.overlay != "" {
		return Plan{}, fmt.Errorf("generic command requires common Profile authority")
	}
	plan.requirements = TargetRequirements{Recipe: RecipeCommand}
	plan.commandForm, plan.commandArguments = form, argumentCount
	plan.explanation = buildExplanation(plan)
	return plan, nil
}
func (plan Plan) Requirements() TargetRequirements {
	result := plan.requirements
	result.RuntimeInputs = append([]string(nil), result.RuntimeInputs...)
	result.RuntimeInputIDs = append([]string(nil), result.RuntimeInputIDs...)
	result.Semantics = result.Semantics.Clone()
	return result
}

func (value TargetSemantics) Clone() TargetSemantics {
	value.Configuration = append([]ConfigurationDecision(nil), value.Configuration...)
	value.Preflights = append([]ConfigurationDecision(nil), value.Preflights...)
	value.Unsupported = append([]ConfigurationDecision(nil), value.Unsupported...)
	value.Inheritance = append([]InheritanceRule(nil), value.Inheritance...)
	for index := range value.Inheritance {
		value.Inheritance[index].LogicalRoots = append([]string(nil), value.Inheritance[index].LogicalRoots...)
	}
	return value
}

func (plan Plan) AuthorityDigest() string                   { return plan.explanation.AuthorityDigest }
func (plan Plan) RuntimeAuthority() launch.RuntimeAuthority { return plan.runtimeAuthority.Clone() }

func (plan Plan) Explanation() Explanation {
	result := plan.explanation
	result.Requested = cloneFacts(result.Requested)
	result.TargetAdded = cloneFacts(result.TargetAdded)
	result.Effective = cloneFacts(result.Effective)
	result.Unsupported = cloneFacts(result.Unsupported)
	return result
}

func cloneFacts(values []Fact) []Fact {
	result := append([]Fact(nil), values...)
	for index := range result {
		result[index].Value.Names = append([]string(nil), result[index].Value.Names...)
		if result[index].Value.Identity != nil {
			identity := *result[index].Value.Identity
			result[index].Value.Identity = &identity
		}
	}
	if result == nil {
		return []Fact{}
	}
	return result
}

func buildExplanation(plan Plan) Explanation {
	facts := Facts{}
	add := func(value Facts) {
		facts.Requested = append(facts.Requested, value.Requested...)
		facts.TargetAdded = append(facts.TargetAdded, value.TargetAdded...)
		facts.Effective = append(facts.Effective, value.Effective...)
		facts.Unsupported = append(facts.Unsupported, value.Unsupported...)
	}
	workspaceReason := "stored_v3_intent"
	if plan.sourceVersion < 3 {
		workspaceReason = "legacy_compatibility_default"
	}
	add(Facts{Requested: []Fact{{ID: "common.workspace", Kind: "workspace", Value: FactValue{Access: string(plan.WorkspaceAccess())}, Reason: workspaceReason, Source: FactSource{Kind: "profile", ID: "workspace", Version: 1}}}})
	for _, contribution := range plan.contributions {
		if semantic, ok := contribution.Value.(semanticContributor); ok {
			add(semantic.SemanticFacts(plan.sourceVersion, plan.overlay))
		}
	}
	add(recipeFacts(plan))
	add(runtimeFacts(plan.runtimeAuthority))
	for _, list := range []*[]Fact{&facts.Requested, &facts.TargetAdded, &facts.Effective, &facts.Unsupported} {
		sort.Slice(*list, func(i, j int) bool {
			left, right := (*list)[i], (*list)[j]
			if left.ID != right.ID {
				return left.ID < right.ID
			}
			return bytes.Compare(canonicalFactEncoding(left), canonicalFactEncoding(right)) < 0
		})
		if *list == nil {
			*list = []Fact{}
		}
	}
	encoded := canonicalManifest(plan.sourceVersion, plan.overlay, plan.requirements.Recipe, facts)
	sum := sha256.Sum256(encoded)
	return Explanation{AuthorityManifestVersion: AuthorityManifestVersion, AuthorityDigest: "sha256:" + hex.EncodeToString(sum[:]), Requested: facts.Requested, TargetAdded: facts.TargetAdded, Effective: facts.Effective, Unsupported: facts.Unsupported}
}

func recipeFacts(plan Plan) Facts {
	recipe := string(plan.requirements.Recipe)
	result := Facts{Requested: []Fact{{ID: "execution.recipe", Kind: "recipe", Value: FactValue{Mode: recipe}, Reason: "selected_intent", Source: FactSource{Kind: "command", ID: recipe}}}}
	if plan.overlay != "" {
		result.Requested = append(result.Requested, Fact{ID: "target.overlay", Kind: "overlay", Value: FactValue{Mode: plan.overlay}, Reason: "selected_target", Source: FactSource{Kind: "profile", ID: plan.overlay, Version: 1}})
	}
	semantics := plan.requirements.Semantics
	if semantics.AuthenticationMode != "" {
		source := plan.authSource
		if source == "" {
			source = "overlay"
		}
		result.Requested = append(result.Requested, Fact{ID: recipe + ".authentication", Kind: "opaque-binding", Value: FactValue{Mode: semantics.AuthenticationMode}, Reason: source, Source: FactSource{Kind: "target", ID: recipe, Version: semantics.Version}})
	}
	for _, decision := range semantics.Configuration {
		fact := Fact{ID: decision.ID, Kind: "generated-configuration", Value: FactValue{Mode: decision.Mode}, Reason: "fixed_target_recipe", Source: FactSource{Kind: "target", ID: recipe, Version: semantics.Version}}
		result.TargetAdded = append(result.TargetAdded, fact)
		if decision.ID == "codex.apps" || decision.ID == "codex.mcp" || decision.ID == "codex.plugins" {
			result.Unsupported = append(result.Unsupported, fact)
		}
	}
	for _, preflight := range semantics.Preflights {
		result.TargetAdded = append(result.TargetAdded, Fact{ID: preflight.ID, Kind: "target-preflight", Value: FactValue{Mode: preflight.Mode}, Reason: "fixed_target_recipe", Source: FactSource{Kind: "target", ID: recipe, Version: semantics.Version}})
	}
	for _, unsupported := range semantics.Unsupported {
		result.Unsupported = append(result.Unsupported, Fact{ID: "unsupported." + unsupported.ID, Kind: "target-control", Value: FactValue{Mode: unsupported.Mode}, Reason: "not_supported", Source: FactSource{Kind: "target", ID: recipe, Version: semantics.Version}})
	}
	for _, rule := range semantics.Inheritance {
		result.TargetAdded = append(result.TargetAdded, Fact{ID: rule.ID, Kind: "project-inheritance", Value: FactValue{Names: append([]string(nil), rule.LogicalRoots...)}, Reason: "target_inheritance", Source: FactSource{Kind: "target", ID: recipe, Version: semantics.Version}})
	}
	if semantics.CredentialProjection != "" {
		result.TargetAdded = append(result.TargetAdded, Fact{ID: recipe + ".credentials", Kind: "credential-projection", Value: FactValue{Mode: semantics.CredentialProjection}, Reason: "fixed_target_recipe", Source: FactSource{Kind: "target", ID: recipe, Version: semantics.Version}})
	}
	if plan.requirements.Recipe == RecipeShell {
		result.TargetAdded = append(result.TargetAdded, Fact{ID: "sandbox.shell", Kind: "executable", Value: FactValue{RequirementID: "system-zsh-no-rc"}, Reason: "fixed_recipe", Source: FactSource{Kind: "acs", ID: "sandbox"}})
	}
	if plan.requirements.Recipe == RecipeCommand {
		result.TargetAdded = append(result.TargetAdded, Fact{ID: "run.command", Kind: "executable", Value: FactValue{Mode: "literal-no-shell"}, Reason: "validated_command_recipe", Source: FactSource{Kind: "command", ID: "run"}})
		count := plan.commandArguments
		result.Requested = append(result.Requested, Fact{ID: "run.literal-argv", Kind: "command", Value: FactValue{Mode: plan.commandForm, Count: &count}, Reason: "validated_command_recipe", Source: FactSource{Kind: "command", ID: "run"}})
	}
	if plan.requirements.Recipe == RecipeDevin || plan.requirements.Recipe == RecipeCodex {
		if plan.requirements.ExecutableRequirementID != "" {
			result.TargetAdded = append(result.TargetAdded, Fact{ID: "target.executable", Kind: "executable", Value: FactValue{RequirementID: plan.requirements.ExecutableRequirementID}, Reason: "registered_requirement", Source: FactSource{Kind: "target", ID: recipe, Version: semantics.Version}})
			result.Effective = append(result.Effective, Fact{ID: "target.executable-access", Kind: "filesystem", Value: FactValue{Access: "read-execute", RequirementID: plan.requirements.ExecutableRequirementID}, Reason: "registered_requirement", Source: FactSource{Kind: "target", ID: recipe, Version: semantics.Version}})
		}
	}
	for _, id := range plan.requirements.RuntimeInputIDs {
		result.TargetAdded = append(result.TargetAdded, Fact{ID: "target.runtime." + id, Kind: "runtime-input", Value: FactValue{RequirementID: id}, Reason: "registered_requirement", Source: FactSource{Kind: "target", ID: recipe, Version: semantics.Version}})
		result.Effective = append(result.Effective, Fact{ID: "target.runtime-access." + id, Kind: "filesystem", Value: FactValue{Access: "read", RequirementID: id}, Reason: "registered_requirement", Source: FactSource{Kind: "target", ID: recipe, Version: semantics.Version}})
	}
	return result
}

func runtimeFacts(runtime launch.RuntimeAuthority) Facts {
	effective := []Fact{
		{ID: "runtime.devices", Kind: "device", Value: FactValue{Mode: runtime.DeviceMode}, Reason: "acs_runtime", Source: FactSource{Kind: "acs", ID: "native-sandbox", Version: runtime.Version}},
		{ID: "runtime.environment", Kind: "environment", Value: FactValue{Mode: "conditional-inheritance-values-omitted", Names: sortedStrings(runtime.InheritedEnvironmentNames)}, Reason: "acs_runtime", Source: FactSource{Kind: "acs", ID: "native-sandbox", Version: runtime.Version}},
		{ID: "runtime.environment.fixed-path", Kind: "environment", Value: FactValue{Mode: runtime.FixedPath, Names: []string{"PATH"}}, Reason: "acs_runtime", Source: FactSource{Kind: "acs", ID: "native-sandbox", Version: runtime.Version}},
		{ID: "runtime.environment.synthetic", Kind: "environment", Value: FactValue{Mode: "session-relative-values-omitted", Names: sortedStrings(runtime.SyntheticEnvironmentNames)}, Reason: "acs_runtime", Source: FactSource{Kind: "acs", ID: "native-sandbox", Version: runtime.Version}},
		{ID: "runtime.mach-services", Kind: "mach-service", Value: FactValue{Names: sortedStrings(runtime.MachServices)}, Reason: "acs_runtime", Source: FactSource{Kind: "acs", ID: "native-sandbox", Version: runtime.Version}},
		{ID: "runtime.metadata", Kind: "filesystem-metadata", Value: FactValue{Mode: runtime.MetadataMode}, Reason: "acs_runtime", Source: FactSource{Kind: "acs", ID: "native-sandbox", Version: runtime.Version}},
		{ID: "runtime.network", Kind: "network", Value: FactValue{Mode: runtime.NetworkMode}, Reason: "acs_runtime", Source: FactSource{Kind: "acs", ID: "native-sandbox", Version: runtime.Version}},
		{ID: "runtime.process", Kind: "process", Value: FactValue{Mode: runtime.ProcessMode}, Reason: "acs_runtime", Source: FactSource{Kind: "acs", ID: "native-sandbox", Version: runtime.Version}},
		{ID: "runtime.session", Kind: "filesystem", Value: FactValue{Access: runtime.SessionAccess}, Reason: "intrinsic_session", Source: FactSource{Kind: "acs", ID: "session", Version: runtime.Version}},
		{ID: "runtime.sysctls", Kind: "sysctl", Value: FactValue{Names: sortedStrings(runtime.SysctlNames)}, Reason: "acs_runtime", Source: FactSource{Kind: "acs", ID: "native-sandbox", Version: runtime.Version}},
		{ID: "runtime.system-read", Kind: "filesystem", Value: FactValue{Access: "read", Mode: runtime.SystemReadMode}, Reason: "acs_runtime", Source: FactSource{Kind: "acs", ID: "native-sandbox", Version: runtime.Version}},
		{ID: "runtime.terminal", Kind: "terminal", Value: FactValue{Mode: runtime.TerminalMode}, Reason: "acs_runtime", Source: FactSource{Kind: "acs", ID: "native-sandbox", Version: runtime.Version}},
	}
	unsupported := []Fact{
		{ID: "unsupported.arbitrary-executables", Kind: "executable", Value: FactValue{Mode: "arbitrary-grants"}, Reason: "not_supported", Source: FactSource{Kind: "acs", ID: "native-sandbox"}},
		{ID: "unsupported.arbitrary-host-paths", Kind: "filesystem", Value: FactValue{Mode: "arbitrary-grants"}, Reason: "not_supported", Source: FactSource{Kind: "acs", ID: "native-sandbox"}},
		{ID: "unsupported.host-environment", Kind: "environment", Value: FactValue{Mode: "arbitrary-values"}, Reason: "not_supported", Source: FactSource{Kind: "acs", ID: "native-sandbox"}},
		{ID: "unsupported.network-destinations", Kind: "network", Value: FactValue{Mode: "destination-filtering"}, Reason: "not_supported", Source: FactSource{Kind: "acs", ID: "native-sandbox"}},
		{ID: "unsupported.sandbox-bypass", Kind: "isolation", Value: FactValue{Mode: "bypass"}, Reason: "not_supported", Source: FactSource{Kind: "acs", ID: "native-sandbox"}},
		{ID: "unsupported.target-pass-through", Kind: "target-control", Value: FactValue{Mode: "arbitrary-options"}, Reason: "not_supported", Source: FactSource{Kind: "acs", ID: "recipes"}},
		{ID: "unsupported.raw-policy", Kind: "isolation", Value: FactValue{Mode: "caller-supplied"}, Reason: "not_supported", Source: FactSource{Kind: "acs", ID: "native-sandbox"}},
		{ID: "unsupported.durable-session-operations", Kind: "session", Value: FactValue{Mode: "public-management-ui"}, Reason: "not_supported", Source: FactSource{Kind: "acs", ID: "session"}},
	}
	targetAdded := []Fact{{ID: "runtime.session-destinations", Kind: "session-destination", Value: FactValue{Names: []string{"session-home", "session-temporary", "session-home/.config", "session-home/.local/share", "session-home/.cache", "session-home/.local/state"}}, Reason: "intrinsic_session", Source: FactSource{Kind: "acs", ID: "session", Version: runtime.Version}}}
	return Facts{TargetAdded: targetAdded, Effective: effective, Unsupported: unsupported}
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func canonicalFactEncoding(fact Fact) []byte {
	encoded := []byte{}
	putUint := func(value uint64) {
		var buffer [8]byte
		binary.BigEndian.PutUint64(buffer[:], value)
		encoded = append(encoded, buffer[:]...)
	}
	putString := func(value string) { putUint(uint64(len(value))); encoded = append(encoded, value...) }
	putString(fact.ID)
	putString(fact.Kind)
	putString(fact.Reason)
	putString(fact.Source.Kind)
	putString(fact.Source.ID)
	putUint(uint64(fact.Source.Version))
	putString(fact.Value.Access)
	putString(fact.Value.Mode)
	putString(fact.Value.LogicalLocation)
	putString(fact.Value.RequirementID)
	if fact.Value.Identity == nil {
		putUint(0)
	} else {
		putUint(1)
		putString(fact.Value.Identity.Source)
		putString(fact.Value.Identity.RelativePath)
	}
	if fact.Value.Count == nil {
		putUint(0)
	} else {
		putUint(1)
		putUint(uint64(*fact.Value.Count))
	}
	putUint(uint64(len(fact.Value.Names)))
	for _, name := range fact.Value.Names {
		putString(name)
	}
	return encoded
}

func canonicalManifest(sourceVersion int, overlay string, recipe Recipe, facts Facts) []byte {
	encoded := []byte("acs-semantic-authority-manifest")
	putUint := func(value uint64) {
		var buffer [8]byte
		binary.BigEndian.PutUint64(buffer[:], value)
		encoded = append(encoded, buffer[:]...)
	}
	putString := func(value string) { putUint(uint64(len(value))); encoded = append(encoded, value...) }
	putUint(AuthorityManifestVersion)
	putUint(uint64(sourceVersion))
	putString(overlay)
	putString(string(recipe))
	putFacts := func(values []Fact) {
		putUint(uint64(len(values)))
		for _, fact := range values {
			encodedFact := canonicalFactEncoding(fact)
			putUint(uint64(len(encodedFact)))
			encoded = append(encoded, encodedFact...)
		}
	}
	putFacts(facts.Requested)
	putFacts(facts.TargetAdded)
	putFacts(facts.Effective)
	putFacts(facts.Unsupported)
	return encoded
}

func (plan Plan) DevinExpectedCatalog() []skills.SkillReference {
	for _, entry := range plan.contributions {
		if expected, ok := entry.Value.(interface {
			DevinExpectedCatalog() []skills.SkillReference
		}); ok {
			return append([]skills.SkillReference(nil), expected.DevinExpectedCatalog()...)
		}
	}
	return nil
}

func (plan Plan) Plan(ctx context.Context, workingDirectory string) (launch.Plan, error) {
	provenance := fmt.Sprintf("Profile envelope v%d", plan.sourceVersion)
	if plan.sourceVersion < 3 {
		provenance += " legacy compatibility"
	} else {
		provenance += " common workspace v1"
	}
	explanation := launch.Plan{Sections: []launch.PlanSection{{
		Title: "Resolved execution authority:",
		Items: []launch.PlanItem{
			{Label: "recipe", Details: []launch.PlanDetail{{Label: "selected", Value: string(plan.requirements.Recipe)}}},
			{Label: "workspace", Details: []launch.PlanDetail{{Label: "access", Value: string(plan.WorkspaceAccess())}, {Label: "source", Value: provenance}}},
			{Label: "Session", Details: []launch.PlanDetail{{Label: "access", Value: "private and writable"}}},
			{Label: "intrinsic target/runtime inputs", Details: []launch.PlanDetail{{Label: "authority", Value: "registered by ACS"}}},
		},
	}}}
	if plan.requirements.Recipe == RecipeCodex {
		explanation.Sections[0].Items = append(explanation.Sections[0].Items,
			launch.PlanItem{Label: "authentication", Details: []launch.PlanDetail{{Label: "reference", Value: plan.authRef}, {Label: "existence/status", Value: "unchecked"}}})
	}
	for _, entry := range plan.contributions {
		var err error
		if resolved, ok := entry.Value.(interface {
			PlanResolved(context.Context, string, int, string, *launch.Plan) error
		}); ok {
			err = resolved.PlanResolved(ctx, workingDirectory, plan.sourceVersion, plan.overlay, &explanation)
		} else {
			err = entry.Value.Plan(ctx, workingDirectory, &explanation)
		}
		if err != nil {
			return launch.Plan{}, fmt.Errorf("plan %s capability: %w", entry.ID, err)
		}
	}
	return explanation, nil
}

func (plan Plan) Materialize(sessionHome string) error {
	for _, entry := range plan.contributions {
		var err error
		if resolved, ok := entry.Value.(interface {
			MaterializeResolved(string, int, string) error
		}); ok {
			err = resolved.MaterializeResolved(sessionHome, plan.sourceVersion, plan.overlay)
		} else {
			err = entry.Value.Materialize(sessionHome)
		}
		if err != nil {
			return fmt.Errorf("materialize %s capability: %w", entry.ID, err)
		}
	}
	return nil
}

func (plan Plan) Verify(ctx context.Context, verification launch.VerificationContext) error {
	for _, entry := range plan.contributions {
		if err := entry.Value.Verify(ctx, verification); err != nil {
			return fmt.Errorf("verify %s capability: %w", entry.ID, err)
		}
	}
	return nil
}
