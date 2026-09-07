package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/exchangefile"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/profileexchange"
	"github.com/alcimerio/ai-config-selector/internal/profilerepo"
)

type exchangeDiagnostic struct {
	FormatVersion          int    `json:"formatVersion"`
	Operation              string `json:"operation"`
	Status                 string `json:"status"`
	Code                   string `json:"code"`
	Structure              string `json:"structure"`
	Semantics              string `json:"semantics"`
	Bindings               string `json:"bindings"`
	Destination            string `json:"destination"`
	SourceAvailability     string `json:"sourceAvailability"`
	Authentication         string `json:"authentication"`
	Runtime                string `json:"runtime"`
	RequiredSources        int    `json:"requiredSources"`
	RequiredAuthentication int    `json:"requiredAuthentication"`
}

// RunProfileExchange is an early, non-runtime dispatch. It assembles only the
// strict Profile codec and opaque repository after syntax validation.
func (app App) RunProfileExchange(ctx context.Context, args []string, home func() (string, error)) (bool, int) {
	inv, problem := parseCommand(args)
	if inv.command.path != "profile export" && inv.command.path != "profile import" && inv.command.path != "profile import validate" {
		return false, 0
	}
	if problem != "" || inv.help {
		handled, code := app.RunInformational(args)
		return handled, code
	}
	if err := ctx.Err(); err != nil {
		return true, app.fail("Profile exchange was not started")
	}
	if app.Repository == nil || app.Categories == nil {
		existingHome, err := home()
		if err != nil {
			return true, app.fail("resolve user home for Profile exchange")
		}
		editor, err := devin.NewProfileEditor(existingHome)
		if err != nil {
			return true, app.fail("configure Profile exchange codec")
		}
		app.Repository = profilerepo.New(filepath.Join(existingHome, ".acs"))
		app.Categories = editor.Categories()
	}
	switch inv.command.path {
	case "profile export":
		return true, app.exportProfile(ctx, inv)
	case "profile import validate":
		return true, app.validateImport(inv)
	default:
		return true, app.importProfile(ctx, inv)
	}
}

func (app App) exportProfile(ctx context.Context, inv invocation) int {
	snapshot, err := app.Repository.Read(ctx, inv.operand)
	if err != nil || !snapshot.Exists {
		return app.fail("export Profile: stored Profile is unavailable or unsafe")
	}
	candidate, err := app.Categories.DecodeNamed(inv.operand, snapshot.Bytes)
	if err != nil {
		return app.fail("export Profile: stored Profile contains unsupported or invalid content")
	}
	document, report, err := profileexchange.Export(candidate)
	if err != nil {
		if candidate.SourceVersion < profile.CurrentVersion {
			return app.fail("export Profile: legacy Profile requires explicit acs profile migrate NAME before export")
		}
		return app.fail("export Profile: stored Profile contains unsupported or unclassified content")
	}
	if inv.value == "" {
		written, writeErr := app.Output.Write(document)
		if writeErr != nil || written != len(document) {
			return app.fail("export Profile: write exchange document")
		}
	} else {
		publisher := app.ExchangePublisher
		if publisher == nil {
			publisher = exchangefile.Publisher{}
		}
		outcome, publishErr := publisher.Publish(ctx, inv.value, document)
		if publishErr != nil {
			if outcome.Published {
				return app.fail("export Profile: exchange file was published, but durability or status reporting failed; inspect the destination before retrying")
			}
			return app.fail("export Profile: exchange file was not published")
		}
	}
	var classification bytes.Buffer
	fmt.Fprintf(&classification, "Profile exchange exported: %d source binding(s), %d authentication binding(s); source availability, authentication, and runtime unchecked.\n", report.SourceBindings, report.AuthenticationBindings)
	classification.WriteString("Classification: local name host-bound and omitted; envelope/common/overlay versions, workspace access, and source-relative Skill paths portable; Skill sources host-bound symbolic bindings; Codex authRef secret-reference symbolic binding.\n")
	classification.WriteString("Unsupported and excluded: Skill assets, provider records, secret values, resolved host paths/plans, repository metadata, Sessions, and runtime state.\n")
	if written, err := app.ErrorOutput.Write(classification.Bytes()); err != nil || written != classification.Len() {
		if inv.value != "" {
			return app.fail("export Profile: exchange file was published, but status reporting failed; inspect the destination before retrying")
		}
		return 1
	}
	return 0
}

func (app App) readExchangeInputs(exchangePath, bindingPath string) ([]byte, []byte, error) {
	reader := app.ReadProfileDocument
	if reader == nil {
		reader = readProfileDocument
	}
	document, err := reader(exchangePath)
	if err != nil {
		return nil, nil, err
	}
	if bindingPath == "" {
		return document, nil, nil
	}
	bindings, err := reader(bindingPath)
	if err != nil {
		return nil, nil, err
	}
	return document, bindings, nil
}

func (app App) decodeImport(inv invocation, name string) profileexchange.Result {
	bindingPath := inv.auxValue
	if inv.command.path == "profile import" {
		bindingPath = inv.thirdValue
	}
	document, bindings, err := app.readExchangeInputs(inv.value, bindingPath)
	if err != nil {
		return profileexchange.Result{Code: "input_unavailable", Bindings: "fail", SourceAvailability: "unchecked", Authentication: "unchecked", Runtime: "unchecked"}
	}
	return profileexchange.Decode(document, bindings, name)
}

func diagnosticFor(operation string, result profileexchange.Result) exchangeDiagnostic {
	status := "fail"
	structure, semantics := "fail", "unchecked"
	if result.Code == profileexchange.CodeValid {
		status = "valid"
		structure, semantics = "pass", "pass"
	} else if result.Code == profileexchange.CodeBindingRequired {
		status = "unresolved"
		structure, semantics = "pass", "pass"
	} else if result.Code == profileexchange.CodeBindingInvalid || result.Code == profileexchange.CodeBindingConflict {
		structure, semantics = "pass", "pass"
	} else if result.Code == profileexchange.CodeUnsupportedVersion || result.Code == profileexchange.CodeUnsupportedContent || result.Code == profileexchange.CodeUnsafePath {
		structure, semantics = "pass", "fail"
	}
	return exchangeDiagnostic{
		FormatVersion: 1, Operation: operation, Status: status, Code: string(result.Code), Structure: structure, Semantics: semantics,
		Bindings: result.Bindings, Destination: "unchecked", SourceAvailability: result.SourceAvailability, Authentication: result.Authentication,
		Runtime: result.Runtime, RequiredSources: result.RequiredSources, RequiredAuthentication: result.RequiredAuthentication,
	}
}

func (app App) validateImport(inv invocation) int {
	result := app.decodeImport(inv, "import-preview")
	diagnostic := diagnosticFor("profile.import.validate", result)
	if inv.enabled {
		encoded, _ := json.Marshal(diagnostic)
		encoded = append(encoded, '\n')
		if written, err := app.Output.Write(encoded); err != nil || written != len(encoded) {
			return 1
		}
	} else {
		var output bytes.Buffer
		fmt.Fprintf(&output, "Profile import validation: %s (%s)\nBindings: %s; source availability, authentication, and runtime: unchecked.\n", diagnostic.Status, diagnostic.Code, diagnostic.Bindings)
		if written, err := app.Output.Write(output.Bytes()); err != nil || written != output.Len() {
			return 1
		}
	}
	if result.Code == profileexchange.CodeValid {
		return 0
	}
	if result.Code == profileexchange.CodeBindingRequired {
		return 2
	}
	return 1
}

func (app App) importProfile(ctx context.Context, inv invocation) int {
	result := app.decodeImport(inv, inv.auxValue)
	if result.Code == profileexchange.CodeBindingRequired {
		fmt.Fprintln(app.Output, "Profile import preview: supported exchange intent; required symbolic bindings remain unresolved. Source availability, authentication, and runtime are unchecked. Nothing was published.")
		return 2
	}
	if result.Code != profileexchange.CodeValid || result.Candidate == nil {
		return app.fail("import Profile: exchange or binding document is invalid, unsafe, or unsupported; nothing was published")
	}
	candidate, canonical, err := profile.Canonicalize(app.Categories, *result.Candidate)
	if err != nil {
		return app.fail("import Profile: bound Profile intent is unsupported; nothing was published")
	}
	snapshot, err := app.Repository.Read(ctx, candidate.Name)
	if err != nil {
		return app.fail("import Profile: destination could not be safely proven absent; nothing was published")
	}
	if snapshot.Exists {
		return app.fail("import Profile: destination Profile is occupied; nothing was overwritten")
	}
	if inv.enabled {
		var preview bytes.Buffer
		fmt.Fprintf(&preview, "Profile import dry run for %q\nBindings: complete. Destination: absent. Source availability, authentication, and runtime: unchecked.\n\nExact canonical version-3 Profile JSON (including final newline):\n", candidate.Name)
		preview.Write(canonical)
		fmt.Fprintln(&preview, "\nNo Profile storage, lock, journal, Session, credential, input, or process was changed.")
		if written, err := app.Output.Write(preview.Bytes()); err != nil || written != preview.Len() {
			return app.fail("write Profile import preview")
		}
		return 0
	}
	expected, err := profilerepo.AbsentRevision(candidate.Name)
	if err != nil {
		return app.fail("import Profile: destination condition is invalid")
	}
	outcome, applyErr := app.Repository.Apply(ctx, profilerepo.HistoryRequest{Request: profilerepo.CreateRequest{Name: candidate.Name, Expected: expected, Bytes: canonical}, Operation: "import"})
	if applyErr != nil || outcome.State != profilerepo.Committed || outcome.RecoveryRequired {
		if applyErr == nil {
			applyErr = errors.New("Profile transaction requires outcome inspection")
		}
		return app.profileCreateError(candidate.Name, "import Profile", &profilerepo.OutcomeError{Outcome: outcome, Err: applyErr})
	}
	if _, err := fmt.Fprintf(app.Output, "Imported Profile %q. Bindings are complete; source availability, authentication, and runtime remain unchecked.\n", candidate.Name); err != nil {
		return app.profileCreateError(candidate.Name, "import Profile", &profilerepo.OutcomeError{Outcome: profilerepo.Outcome{State: profilerepo.Committed}, Err: err})
	}
	return 0
}
