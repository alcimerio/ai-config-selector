package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/runcommand"
)

const maximumExplanationBytes = 1 << 20
const maximumExplanationFacts = 4096
const maximumExplanationStringBytes = 4096
const maximumExplanationChecks = 32
const maximumExplanationLimitations = 16

type explanationProfile struct {
	Name          string `json:"name"`
	StoredVersion int    `json:"storedVersion"`
	Compatibility string `json:"compatibility"`
}
type explanationIntent struct {
	Recipe  string  `json:"recipe"`
	Overlay *string `json:"overlay"`
}
type explanationCheck struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}
type explanationLimitation struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}
type explanationDiagnostic struct {
	Code     string `json:"code"`
	Message  string `json:"message"`
	NextStep string `json:"nextStep"`
}
type explanationResult struct {
	FormatVersion int                     `json:"formatVersion"`
	Operation     string                  `json:"operation"`
	Profile       explanationProfile      `json:"profile"`
	Intent        explanationIntent       `json:"intent"`
	Plan          *authority.Explanation  `json:"plan"`
	Checks        []explanationCheck      `json:"checks"`
	Limitations   []explanationLimitation `json:"limitations"`
	Diagnostic    any                     `json:"diagnostic"`
}

func (app App) RunExplanation(ctx context.Context, args []string) (bool, int) {
	inv, problem := parseCommand(args)
	if problem != "" || inv.help || !strings.HasPrefix(inv.command.path, "explain ") {
		return false, 0
	}
	fail := func(code, detail string) (bool, int) {
		if inv.enabled {
			return true, app.writeExplanationDiagnostic(inv, code, detail)
		}
		return true, app.fail("%s: %s", code, detail)
	}
	if app.Profiles == nil || app.Categories == nil {
		return fail("explanation_unavailable", "Capability explanation is unavailable.")
	}
	mode := strings.TrimPrefix(inv.command.path, "explain ")
	store, registry := app.Profiles, app.Categories
	if mode == "codex" {
		store, registry = app.CodexProfiles, app.CodexCategories
	}
	if store == nil || registry == nil {
		return fail("target_unavailable", "The selected target explanation is unavailable.")
	}
	loaded, err := store.Load(inv.value)
	if err != nil {
		return fail("profile_load_failed", "The selected Profile could not be loaded.")
	}
	overlay := ""
	if mode == "devin" || mode == "codex" {
		overlay = mode
	}
	resolved, err := registry.ResolveFor(ctx, loaded, overlay)
	if err != nil {
		return fail("profile_resolution_failed", "The selected Profile could not be resolved for this intent.")
	}
	if mode == "codex" {
		resolved, err = app.CodexTarget.ResolveAuth(resolved, inv.auxValue)
		if err != nil {
			return fail("authentication_syntax_invalid", "The named authentication reference is invalid.")
		}
	}
	if mode == "run" {
		command, commandErr := runcommand.Resolve(app.WorkingDirectory, inv.arguments)
		if commandErr != nil {
			return fail("command_resolution_failed", "The literal command could not be resolved.")
		}
		resolved, err = resolved.ForCommandIntent(string(command.Form()), command.ArgumentCount())
		if err != nil {
			return fail("command_authority_failed", "The command authority could not be resolved.")
		}
	}
	semantic := resolved.Explanation()
	appendInactiveOverlays(&semantic, loaded, overlay)
	overlayCheck := explanationCheck{"profile.overlay", "unchecked", "not_applicable", "Common execution does not select a target overlay."}
	if overlay != "" {
		overlayCheck = explanationCheck{"profile.overlay", "pass", "selected_overlay_supported", "The selected target overlay is supported."}
	}
	authSyntax := explanationCheck{"authentication.syntax", "unchecked", "not_applicable", "This intent has no named authentication binding."}
	if mode == "codex" {
		authSyntax = explanationCheck{"authentication.syntax", "pass", "valid_reference", "The required opaque named-auth reference has valid syntax; its value is omitted."}
	}
	executableAvailability := explanationCheck{"executable.availability", "unchecked", "not_probed", "The fixed target executable was not inspected."}
	if mode == "run" {
		executableAvailability = explanationCheck{"executable.availability", "pass", "literal_executable_resolved", "The literal executable selection was resolved and snapshotted; its path is omitted."}
	}
	checks := []explanationCheck{
		{"profile.structure", "pass", "supported_structure", "The exact stored Profile bytes were admitted."},
		{"profile.sources", "pass", "selected_sources_resolved", "Selected Skill identities resolved; contents may change before execution."},
		overlayCheck,
		authSyntax,
		{"authentication.existence_status", "unchecked", "not_queried", "No credential provider or secret value was accessed."},
		executableAvailability,
		{"executable.version", "unchecked", "not_probed", "No target or user command was started."},
		{"runtime.inputs", "unchecked", "not_resolved", "Registered runtime-input paths were not resolved."},
		{"generated.configuration", "unchecked", "not_materialized", "Generated configuration is declared but was not written or observed."},
		{"project.inheritance", "unchecked", "not_enumerated", "Inheritance rules are effective intent; project-local files were not enumerated."},
		{"runtime.enforcement", "unchecked", "not_probed", "A semantic plan is not proof of native enforcement."},
		{"network.enforcement", "unchecked", "not_probed", "Coarse network intent is not destination-enforcement proof."},
		{"native.platform", "unchecked", "not_probed", "Use --check-native-readiness for the bounded native observation."},
		{"native.backend", "unchecked", "not_probed", "Use --check-native-readiness for the bounded native observation."},
	}
	exitCode := 0
	if inv.secondEnabled {
		if app.NativeReadiness == nil {
			return fail("native_readiness_unavailable", "The bounded native readiness check is unavailable.")
		}
		readiness, readinessErr := app.NativeReadiness.Readiness(ctx)
		if readinessErr != nil {
			return fail("native_readiness_failed", "The bounded native readiness check failed.")
		}
		status, code, detail := "fail", "unsupported_platform", "The current host is not a supported macOS 26 Apple Silicon runtime."
		if readiness.Supported {
			status, code, detail = "pass", "supported_platform", "The current host matches supported platform policy."
		}
		checks[len(checks)-2] = explanationCheck{"native.platform", status, code, detail}
		status, code, detail = "fail", "backend_not_ready", "The fixed native backend readiness observation did not pass."
		if readiness.Ready {
			status, code, detail = "pass", "backend_ready", "The fixed native backend readiness observation passed; launch-specific checks remain."
		}
		checks[len(checks)-1] = explanationCheck{"native.backend", status, code, detail}
		if !readiness.Supported || !readiness.Ready {
			exitCode = 1
		}
	}
	if !explanationWithinBounds(semantic, checks) {
		return fail("explanation_too_large", "The semantic explanation exceeds a declared format bound.")
	}
	result := explanationResult{FormatVersion: 1, Operation: "explain", Profile: explanationProfile{Name: inv.value, StoredVersion: resolved.SourceVersion(), Compatibility: compatibility(resolved.SourceVersion())}, Intent: explanationIntent{Recipe: string(resolved.Requirements().Recipe), Overlay: optionalOverlay(overlay)}, Plan: &semantic, Checks: checks, Limitations: []explanationLimitation{
		{"semantic_digest_only", "The digest excludes local paths, file contents, argument values, credentials, concrete project files, and host readiness; equal digests do not mean file-level execution-plan equality."},
		{"native_readiness_not_launch_readiness", "Native readiness, when requested, does not check target version, authentication, materialization, generated policy, preflights, or cleanup."},
	}, Diagnostic: nil}
	var output bytes.Buffer
	if inv.enabled {
		encoded, marshalErr := json.Marshal(result)
		if marshalErr != nil {
			return true, 1
		}
		output.Write(encoded)
		output.WriteByte('\n')
	} else {
		renderExplanation(&output, result)
	}
	if output.Len() > maximumExplanationBytes {
		return fail("explanation_too_large", "The semantic explanation exceeds its output-size bound.")
	}
	if _, err := app.Output.Write(output.Bytes()); err != nil {
		return true, 1
	}
	return true, exitCode
}

func (app App) writeExplanationDiagnostic(inv invocation, code, detail string) int {
	result := explanationResult{FormatVersion: 1, Operation: "explain", Profile: explanationProfile{Name: inv.value}, Intent: explanationIntent{Recipe: strings.TrimPrefix(inv.command.path, "explain ")}, Plan: nil, Checks: []explanationCheck{}, Limitations: []explanationLimitation{}, Diagnostic: explanationDiagnostic{Code: code, Message: detail, NextStep: "Correct the reported condition and run the explanation again."}}
	encoded, err := json.Marshal(result)
	if err != nil || len(encoded)+1 > maximumExplanationBytes {
		return 1
	}
	encoded = append(encoded, '\n')
	if _, err := app.Output.Write(encoded); err != nil {
		return 1
	}
	return 1
}

func appendInactiveOverlays(explanation *authority.Explanation, loaded profile.Profile, selected string) {
	ids := make([]string, 0, len(loaded.Overlays))
	for id := range loaded.Overlays {
		if id != selected {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	unknownIndex := 0
	for _, id := range ids {
		payload := loaded.Overlays[id]
		factID := "overlay.inactive." + id
		source := authority.FactSource{Kind: "profile", ID: id, Version: payload.Version}
		mode, reason := "inactive", "supported_inactive_overlay"
		if payload.Support != "supported" {
			unknownIndex++
			factID = fmt.Sprintf("overlay.inactive.unknown-%d", unknownIndex)
			source = authority.FactSource{Kind: "profile", ID: "unknown-overlay"}
			mode, reason = "opaque-inert", "inactive_overlay_unknown"
		}
		explanation.Unsupported = append(explanation.Unsupported, authority.Fact{ID: factID, Kind: "overlay", Value: authority.FactValue{Mode: mode}, Reason: reason + "_presentation_only_excluded_from_digest", Source: source})
	}
	sort.Slice(explanation.Unsupported, func(i, j int) bool { return explanation.Unsupported[i].ID < explanation.Unsupported[j].ID })
}

func explanationWithinBounds(explanation authority.Explanation, checks []explanationCheck) bool {
	limitations := 2
	if len(checks) > maximumExplanationChecks || limitations > maximumExplanationLimitations || len(explanation.Requested)+len(explanation.TargetAdded)+len(explanation.Effective)+len(explanation.Unsupported) > maximumExplanationFacts {
		return false
	}
	bounded := func(values ...string) bool {
		for _, value := range values {
			if len(value) > maximumExplanationStringBytes {
				return false
			}
		}
		return true
	}
	for _, list := range [][]authority.Fact{explanation.Requested, explanation.TargetAdded, explanation.Effective, explanation.Unsupported} {
		for _, fact := range list {
			if !bounded(fact.ID, fact.Kind, fact.Reason, fact.Source.Kind, fact.Source.ID, fact.Value.Access, fact.Value.Mode, fact.Value.LogicalLocation, fact.Value.RequirementID) {
				return false
			}
			if fact.Value.Identity != nil && !bounded(fact.Value.Identity.Source, fact.Value.Identity.RelativePath) {
				return false
			}
			if !bounded(fact.Value.Names...) {
				return false
			}
		}
	}
	for _, check := range checks {
		if !bounded(check.ID, check.Status, check.Code, check.Detail) {
			return false
		}
	}
	return true
}
func compatibility(version int) string {
	if version < 3 {
		return "legacy"
	}
	return "current"
}
func optionalOverlay(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func renderExplanation(output *bytes.Buffer, result explanationResult) {
	fmt.Fprintf(output, "Effective capability explanation for Profile %q (stored version %d)\nIntent: %s\nSemantic authority digest: %s\n", safeTerminalText(result.Profile.Name), result.Profile.StoredVersion, result.Intent.Recipe, result.Plan.AuthorityDigest)
	fmt.Fprintln(output, "Digest scope: semantic ACS authority and recipe requirements only; excluded local bindings are rechecked separately where execution requires it.")
	sections := []struct {
		name  string
		facts []authority.Fact
	}{{"Requested", result.Plan.Requested}, {"Target-added", result.Plan.TargetAdded}, {"Effective", result.Plan.Effective}, {"Unsupported or inert", result.Plan.Unsupported}}
	for _, section := range sections {
		fmt.Fprintln(output, "\n"+section.name+":")
		if len(section.facts) == 0 {
			fmt.Fprintln(output, "  (none)")
		}
		for _, fact := range section.facts {
			value := renderFactValue(fact.Value)
			if fact.Kind == "opaque-binding" {
				value += "; value omitted"
			}
			source := fact.Source.Kind + ":" + fact.Source.ID
			if fact.Source.Version != 0 {
				source += fmt.Sprintf("@v%d", fact.Source.Version)
			}
			fmt.Fprintf(output, "  %s [%s]: %s (reason=%s; source=%s)\n", safeTerminalText(fact.ID), safeTerminalText(fact.Kind), safeTerminalText(value), safeTerminalText(fact.Reason), safeTerminalText(source))
		}
	}
	fmt.Fprintln(output, "\nEvidence:")
	for _, check := range result.Checks {
		fmt.Fprintf(output, "  %s: %s (%s)\n    %s\n", check.ID, check.Status, check.Code, safeTerminalText(check.Detail))
	}
	fmt.Fprintln(output, "\nLimitations:")
	for _, limitation := range result.Limitations {
		fmt.Fprintf(output, "  %s: %s\n", limitation.Code, safeTerminalText(limitation.Detail))
	}
	fmt.Fprintln(output, "\nCurrent network authority is local-IP socket bind (not listen/inbound) plus coarse outbound IP and macOS DNS resolver access; no destination allowlist is enforced.")
	if result.Intent.Recipe == "codex" {
		fmt.Fprintln(output, "Codex danger-full-access and no-approval mode do not widen the outer ACS grants.")
	}
	platform, backend := explanationCheckByID(result.Checks, "native.platform"), explanationCheckByID(result.Checks, "native.backend")
	switch {
	case platform.Status == "unchecked" && backend.Status == "unchecked":
		fmt.Fprintln(output, "Native readiness: unchecked (not probed); this is not launch readiness.")
	case platform.Status == "pass" && backend.Status == "pass":
		fmt.Fprintln(output, "Native readiness: narrowly observed; supported platform and backend readiness passed. This is not launch readiness.")
	default:
		fmt.Fprintln(output, "Native readiness: narrowly observed; the requested platform/backend observation did not pass. This is not launch readiness.")
	}
}

func explanationCheckByID(checks []explanationCheck, id string) explanationCheck {
	for _, check := range checks {
		if check.ID == id {
			return check
		}
	}
	return explanationCheck{}
}

func renderFactValue(value authority.FactValue) string {
	parts := []string{}
	if value.Access != "" {
		parts = append(parts, "access="+value.Access)
	}
	if value.Mode != "" {
		parts = append(parts, "mode="+value.Mode)
	}
	if value.LogicalLocation != "" {
		parts = append(parts, "location="+value.LogicalLocation)
	}
	if value.RequirementID != "" {
		parts = append(parts, "requirement="+value.RequirementID)
	}
	if value.Identity != nil {
		parts = append(parts, "identity="+value.Identity.Source+":"+value.Identity.RelativePath)
	}
	if value.Count != nil {
		parts = append(parts, fmt.Sprintf("count=%d", *value.Count))
	}
	if len(value.Names) != 0 {
		parts = append(parts, "names="+strings.Join(value.Names, ","))
	}
	return strings.Join(parts, "; ")
}
