package diagnostics

import (
	"context"
	"fmt"
	"github.com/alcimerio/ai-config-selector/internal/instructions"
	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
)

// LaunchCheck combines only passive facts. It neither resolves runtime authority
// nor gains a credential, process, Session or persistence capability.
func LaunchCheck(ctx context.Context, name, target string, home func() (string, error)) Result {
	r, entry, directory := validateEntry(ctx, name, home)
	r.Operation, r.Target = "check", target
	r.Checks = append(r.Checks, Check{"native.readiness", "unchecked", "not_requested", "Use --check-native-readiness for the bounded native backend observation; launch enforcement remains unchecked."}, Check{"operation.completion", "pass", "completed", "Requested observations completed; unchecked facts are not launch readiness evidence."})
	inspectedTarget := target
	if target == "codex" {
		inspectedTarget = "codex-auth"
	}
	host := Doctor(inspectedTarget)
	for _, c := range host.Checks {
		if c.ID == "host.platform" || c.ID == "backend.file" || c.ID == "executable.availability" {
			r.SetFact(c.ID, c.Status, c.Code, c.NextStep)
		}
	}
	r.set("profile.overlays", "unchecked", "structure_required", "Correct the Profile structure before checking target compatibility.")
	if entry.Status == "valid" {
		selectOverlay(&r, entry, target)
		refs := []instructions.Reference{}

		for _, category := range entry.Categories {
			if category.ID == "exclusions" {
				if count, known := category.SelectionCount(); known && count > 0 {
					r.Checks = append(r.Checks, Check{"profile.exclusions", "unchecked", "launch_required", fmt.Sprintf("Configured exclusions: %d. Use explain for logical intent. Launch checks path identity, material/runtime conflicts and native enforcement.", count)})
				}
			}
			refs = append(refs, category.Instructions...)
		}
		if _, err := instructions.Resolve(directory, refs); err != nil {
			r.set("profile.sources", "fail", "selected_instructions_unresolved", "Restore the selected instruction files and check again.")
		}
	}
	if ctx.Err() != nil {
		r.set("operation.completion", "fail", "cancelled", "The check was cancelled; retry when ready.")
	}
	return r
}
func selectOverlay(r *Result, entry profileinspect.Entry, target string) {
	if entry.StoredVersion != nil && *entry.StoredVersion < 3 {
		if target == "sandbox" {
			r.set("profile.overlays", "pass", "legacy_common_only", "Sandbox consumes legacy common capabilities without selecting the implicit Devin overlay; legacy workspace write remains effective.")
		} else if target == "devin" {
			r.set("profile.overlays", "pass", "legacy_devin_binding", "Legacy v1/v2 Profiles remain bound to Devin.")
		} else {
			r.set("profile.overlays", "fail", "legacy_target_mismatch", "Explicitly migrate this legacy Devin Profile before selecting another target.")
		}
		return
	}
	if target == "sandbox" {
		r.set("profile.overlays", "pass", "common_only", "Sandbox consumes common capabilities without selecting a target overlay or account.")
		return
	}
	for _, overlay := range entry.Overlays {
		if overlay.ID != target {
			continue
		}
		if overlay.Support == "supported" {
			r.set("profile.overlays", "pass", "selected_overlay_supported", "The selected target overlay has supported structure; runtime projections remain unchecked.")
		} else {
			r.set("profile.overlays", "fail", "selected_overlay_unsupported", "Use a supported version and selection for the requested target overlay.")
		}
		return
	}
	r.set("profile.overlays", "fail", "selected_overlay_missing", "Add a supported overlay for the requested target or select sandbox for common-only execution.")
}

// SetFact replaces one fixed, ordered fact with a sanitized observation supplied
// by the optional-probe owner. Diagnostics itself never calls that owner.
func (r *Result) SetFact(id, status, code, next string) { r.set(id, status, code, next) }

// Passed reports whether a prerequisite was observed, rather than inferred.
func (r Result) Passed(id string) bool {
	for _, c := range r.Checks {
		if c.ID == id {
			return c.Status == "pass"
		}
	}
	return false
}
