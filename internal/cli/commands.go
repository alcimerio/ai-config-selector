package cli

import (
	"fmt"
	"github.com/alcimerio/ai-config-selector/internal/codexauth"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/runcommand"
	"strings"
)

// commandSpec is the public grammar. Command words precede flags; valued flags
// consume exactly one separate, nonempty token, and every flag occurs once.
type commandSpec struct {
	path, syntax, description, example string
	valueFlag, boolFlag                string
	secondBoolFlag                     string
	auxValueFlag                       string
	thirdValueFlag                     string
	group                              bool
	nameOperand                        bool
	optionalValue                      bool
	optionalAuxValue                   bool
	optionalThirdValue                 bool
}

var commands = []commandSpec{
	{path: "", syntax: "acs <command> [flags]", description: "Create capability Profiles and use the required native sandbox.", example: "acs devin create-profile --name backend-review", group: true},
	{path: "profile", syntax: "acs profile <command> [flags]", description: "Create, inspect, validate, exchange, edit, clone, rename or delete Profiles.", example: "acs profile create --file profile.json\n  acs profile show backend-review", group: true},
	{path: "profile list", syntax: "acs profile list [--json]", description: "List direct stored Profiles, including per-entry structural errors. Missing storage is empty.\nNo sources, targets, credentials or Sessions are accessed. No files are changed.", example: "acs profile list\n  acs profile list --json", boolFlag: "--json"},
	{path: "profile show", syntax: "acs profile show NAME [--json]", description: "Show persisted Profile versions and selections, even with missing Skill sources.\nSupported structure does not imply launch readiness. No files are changed.", example: "acs profile show backend-review\n  acs profile show --json backend-review", boolFlag: "--json", nameOperand: true},
	{path: "profile create", syntax: "acs profile create --file FILE [--dry-run]", description: "Create one machine-local Profile from a strict version-3 JSON document. The document supplies its validated name.\nMissing Skill material and named authentication remain unchecked. Existing Profiles are never overwritten.", example: "acs profile create --file profile.json\n  acs profile create --file profile.json --dry-run", valueFlag: "--file", boolFlag: "--dry-run"},
	{path: "profile edit", syntax: "acs profile edit NAME", description: "Edit stored selections interactively in the Profile Builder. Preview exact canonical bytes before saving.\nUnavailable selections remain selected until explicitly removed. No client, credentials or Session is needed.", example: "acs profile edit backend-review", nameOperand: true},
	{path: "profile clone", syntax: "acs profile clone NAME --name NEW", description: "Open a seeded Profile Builder under a new name. Preview and confirm before publication.\nThe source must remain unchanged and the destination must remain absent.", example: "acs profile clone backend-review --name frontend-review", nameOperand: true, valueFlag: "--name"},
	{path: "profile rename", syntax: "acs profile rename NAME --name NEW", description: "Preview and confirm coordinated filename and embedded-name changes interactively.\nAn occupied destination is never overwritten. Legacy conversion requires a canonical representation preview.", example: "acs profile rename backend-review --name service-review", nameOperand: true, valueFlag: "--name"},
	{path: "profile delete", syntax: "acs profile delete NAME [--confirm NAME]", description: "Delete only the named stored Profile at its captured revision.\nInteractive deletion requires typing the exact name; noninteractive use requires an exact --confirm NAME.\nSafely readable unsupported documents may be deleted. Identities, Sessions and other Profiles are unaffected.", example: "acs profile delete backend-review\n  acs profile delete backend-review --confirm backend-review", nameOperand: true, valueFlag: "--confirm", optionalValue: true},
	{path: "profile migrate", syntax: "acs profile migrate NAME", description: "Preview and explicitly migrate one legacy v1/v2 Profile to v3 through the revisioned repository.\nLegacy workspace write is preserved explicitly; common and target projection paths change only after confirmation.", example: "acs profile migrate backend-review", nameOperand: true},
	{path: "profile export", syntax: "acs profile export NAME [--file FILE]", description: "Export supported version-3 stored intent as deterministic sanitized exchange JSON.\nWithout --file, JSON is stdout and the classification report is stderr. Existing files are never replaced.", example: "acs profile export backend-review\n  acs profile export backend-review --file backend-review.acs-profile.json", nameOperand: true, valueFlag: "--file", optionalValue: true},
	{path: "profile import", syntax: "acs profile import --file FILE --as NAME [--bindings FILE] [--dry-run]", description: "Import one untrusted exchange document through bounded validation and conditional no-overwrite creation.\nAll symbolic bindings must be explicit; --dry-run is passive and publishes nothing.", example: "acs profile import --file shared.acs-profile.json --as backend-review --bindings local-bindings.json --dry-run", valueFlag: "--file", auxValueFlag: "--as", thirdValueFlag: "--bindings", optionalThirdValue: true, boolFlag: "--dry-run"},
	{path: "profile import validate", syntax: "acs profile import validate --file FILE [--bindings FILE] [--json]", description: "Passively validate one bounded exchange document and optional local bindings.\nThis does not change the existing acs profile validate NAME command and creates no storage or runtime state.", example: "acs profile import validate --file shared.acs-profile.json --json", valueFlag: "--file", auxValueFlag: "--bindings", optionalAuxValue: true, boolFlag: "--json"},
	{path: "explain", syntax: "acs explain <sandbox|devin|codex|run> [flags]", description: "Explain semantic Profile authority and registered execution requirements without creating a Session or starting a target.", example: "acs explain devin --profile backend-review\n  acs explain codex --profile backend-review --json", group: true},
	{path: "explain sandbox", syntax: "acs explain sandbox --profile NAME [--check-native-readiness] [--json]", description: "Explain the fixed sandbox-shell intent. Native readiness is unchecked unless explicitly requested.", example: "acs explain sandbox --profile backend-review --json", valueFlag: "--profile", boolFlag: "--json", secondBoolFlag: "--check-native-readiness"},
	{path: "explain devin", syntax: "acs explain devin --profile NAME [--check-native-readiness] [--json]", description: "Explain Devin authority, projection, configuration inheritance, and evidence without starting Devin.", example: "acs explain devin --profile backend-review", valueFlag: "--profile", boolFlag: "--json", secondBoolFlag: "--check-native-readiness"},
	{path: "explain codex", syntax: "acs explain codex --profile NAME [--auth REF] [--check-native-readiness] [--json]", description: "Explain Codex authority, fixed generated configuration, inheritance, and redacted named-auth selection without provider access.", example: "acs explain codex --profile backend-review --auth work --json", valueFlag: "--profile", auxValueFlag: "--auth", optionalAuxValue: true, boolFlag: "--json", secondBoolFlag: "--check-native-readiness"},
	{path: "explain run", syntax: "acs explain run --profile NAME [--check-native-readiness] [--json] -- COMMAND [ARG...]", description: "Explain one literal generic-command intent without starting the command. Argument values remain hidden.", example: "acs explain run --profile backend-review --json -- ./tool --flag", valueFlag: "--profile", boolFlag: "--json", secondBoolFlag: "--check-native-readiness"},

	{path: "doctor", syntax: "acs doctor [--target devin|sandbox|codex-auth] [--json]", description: "Inspect passive host and backend-file prerequisites. Optional targets check executable availability only.\nVersions, authentication and actual sandbox enforcement remain unchecked. No processes run or files change.\ncodex-auth describes named authentication workflows; use Codex dry-run to inspect a Profile launch plan.", example: "acs doctor\n  acs doctor --target devin --json", valueFlag: "--target", boolFlag: "--json", optionalValue: true},
	{path: "profile validate", syntax: "acs profile validate NAME [--json]", description: "Validate stored Profile structure and selected Skill-source resolution without a launch plan.\nPlatform, backend, executables, authentication and runtime remain unchecked. No files change.", example: "acs profile validate backend-review\n  acs profile validate --json backend-review", boolFlag: "--json", nameOperand: true},
	{path: "run", syntax: "acs run --profile <name> [--dry-run] [--expect-authority-digest DIGEST] -- COMMAND [ARG...]", description: "Run one literal argv with common Profile authority and the required native sandbox.\nNo shell, target overlay, credentials, or host PATH is inherited.", example: "acs run --profile backend-review -- /usr/bin/git status\n  acs run --dry-run --profile backend-review -- ./tool --flag", valueFlag: "--profile", boolFlag: "--dry-run", thirdValueFlag: "--expect-authority-digest", optionalThirdValue: true},
	{path: "devin", syntax: "acs devin --profile <name> [--dry-run] [--expect-authority-digest DIGEST]", description: "Launch Devin with a saved Profile. --dry-run inspects the plan without creating a Session.\nUse create-profile to open the interactive Profile Builder.", example: "acs devin --profile backend-review --dry-run\n  acs devin --profile backend-review", valueFlag: "--profile", boolFlag: "--dry-run", thirdValueFlag: "--expect-authority-digest", optionalThirdValue: true},
	{path: "devin create-profile", syntax: "acs devin create-profile --name <name>", description: "Create a new Profile using interactive stdin and stdout. Existing names are never overwritten.\nSelect Skills with Space/Enter; return with Left/Esc; choose Create Profile to save.\nCtrl+C cancels without saving (exit 130).", example: "acs devin create-profile --name backend-review", valueFlag: "--name"},
	{path: "sandbox", syntax: "acs sandbox --profile <name> [--dry-run] [--expect-authority-digest DIGEST]", description: "Open /bin/zsh -f in the Profile sandbox without Devin credentials.\n--dry-run inspects the plan without creating a Session or starting a shell.", example: "acs sandbox --dry-run --profile backend-review\n  acs sandbox --profile backend-review", valueFlag: "--profile", boolFlag: "--dry-run", thirdValueFlag: "--expect-authority-digest", optionalThirdValue: true},
	{path: "codex", syntax: "acs codex --profile <name> [--auth <ref>] [--dry-run] [--expect-authority-digest DIGEST]", description: "Launch interactive Codex with a common Profile and one ACS-owned named ChatGPT identity.\n--auth overrides the Profile authRef for this run. --dry-run validates syntax only and reports authentication unchecked.", example: "acs codex --profile backend-review --auth work --dry-run\n  acs codex --profile backend-review", valueFlag: "--profile", auxValueFlag: "--auth", optionalAuxValue: true, boolFlag: "--dry-run", thirdValueFlag: "--expect-authority-digest", optionalThirdValue: true},
	{path: "codex create-profile", syntax: "acs codex create-profile --name <name> [--auth <ref>]", description: "Create a common Profile with a supported Codex overlay through the interactive Profile Builder.\nWhen supplied, only the opaque named authentication reference is stored; credentials are never stored in a Profile.\nA Profile without authRef requires --auth on every real launch.", example: "acs codex create-profile --name backend-review --auth work", valueFlag: "--name", auxValueFlag: "--auth", optionalAuxValue: true},
	{path: "codex auth", syntax: "acs codex auth <command> [flags]", description: "Manage ACS-owned ChatGPT identities in the macOS Keychain.\nLogin and status require codex-cli 0.149.1 and the required sandbox.\nThese commands do not launch interactive Codex or use the global Codex login.", example: "acs codex auth login --name work\n  acs codex auth status --name work", group: true},
	{path: "codex auth login", syntax: "acs codex auth login --name <name> [--device-auth]", description: "Create a named ChatGPT identity; requires interactive stdin/stdout and codex-cli 0.149.1.\n--device-auth selects the device login flow. Existing names are never replaced.", example: "acs codex auth login --device-auth --name work", valueFlag: "--name", boolFlag: "--device-auth"},
	{path: "codex auth list", syntax: "acs codex auth list", description: "List non-secret metadata for ACS-owned identities in the macOS Keychain.", example: "acs codex auth list"},
	{path: "codex auth status", syntax: "acs codex auth status --name <name>", description: "Verify one named identity in a contained status Session using codex-cli 0.149.1.", example: "acs codex auth status --name work", valueFlag: "--name"},
	{path: "codex auth recover", syntax: "acs codex auth recover --name <name>", description: "Recover a quarantined identity after proving its protected Session is inactive.", example: "acs codex auth recover --name work", valueFlag: "--name"},
	{path: "codex auth logout", syntax: "acs codex auth logout --name <name>", description: "Remove an ACS-owned identity. An absent valid name succeeds; global Codex login is untouched.", example: "acs codex auth logout --name work", valueFlag: "--name"},
	{path: "version", syntax: "acs version", description: "Print the ACS build version.", example: "acs version"},
}

type invocation struct {
	command                      commandSpec
	value                        string
	auxValue                     string
	thirdValue                   string
	operand                      string
	enabled, secondEnabled, help bool
	arguments                    []string
}

func parseCommand(args []string) (inv invocation, problem string) {
	inv.command = commands[0]
	helpCommand := len(args) > 0 && args[0] == "help"
	if helpCommand {
		inv.help = true
		args = args[1:]
	}
	// Select the longest known command path before considering any flags.
	consumed := 0
	for _, command := range commands[1:] {
		words := strings.Fields(command.path)
		if len(words) <= len(args) && len(words) > consumed && strings.Join(args[:len(words)], " ") == command.path {
			inv.command = command
			consumed = len(words)
		}
	}
	args = args[consumed:]
	if (inv.command.path == "run" || inv.command.path == "explain run") && !helpCommand {
		boundary := -1
		for index, argument := range args {
			if argument == "--" {
				boundary = index
				break
			}
		}
		hasHelp := false
		for _, argument := range args {
			hasHelp = hasHelp || argument == "--help"
		}
		if boundary < 0 && !hasHelp {
			return inv, "missing required -- command boundary"
		}
		if boundary >= 0 {
			inv.arguments = append([]string(nil), args[boundary+1:]...)
			args = args[:boundary]
			if err := runcommand.ValidateSyntax(inv.arguments); err != nil {
				return inv, "invalid command after --"
			}
		}
	}
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !strings.HasPrefix(arg, "-") {
			if inv.command.nameOperand && !helpCommand && inv.operand == "" && arg != "" {
				inv.operand = arg
				continue
			}
			if helpCommand || consumed == 0 || inv.command.group || (i == 0 && inv.command.path == "devin") {
				return inv, "unknown command " + publicToken(arg)
			}
			return inv, "unsupported positional argument"
		}
		flag, _, hasEquals := strings.Cut(arg, "=")
		if helpCommand || (flag != "--help" && flag != inv.command.valueFlag && flag != inv.command.auxValueFlag && flag != inv.command.thirdValueFlag && flag != inv.command.boolFlag && flag != inv.command.secondBoolFlag) {
			return inv, "unsupported flag " + publicToken(flag)
		}
		if hasEquals {
			return inv, "flag " + publicToken(flag) + " requires separate arguments; '=' syntax is unsupported"
		}
		if seen[flag] {
			return inv, "duplicate flag " + publicToken(flag)
		}
		seen[flag] = true
		switch flag {
		case "--help":
			inv.help = true
		case inv.command.valueFlag:
			if i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
				return inv, "missing value for " + flag
			}
			i++
			inv.value = args[i]
		case inv.command.auxValueFlag:
			if i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
				return inv, "missing value for " + flag
			}
			i++
			inv.auxValue = args[i]
		case inv.command.thirdValueFlag:
			if i+1 >= len(args) || args[i+1] == "" || strings.HasPrefix(args[i+1], "-") {
				return inv, "missing value for " + flag
			}
			i++
			inv.thirdValue = args[i]
		case inv.command.boolFlag:
			inv.enabled = true
		case inv.command.secondBoolFlag:
			inv.secondEnabled = true
		}
	}
	if inv.command.path == "doctor" && inv.value != "" && inv.value != "devin" && inv.value != "sandbox" && inv.value != "codex-auth" {
		return inv, "target must be devin, sandbox or codex-auth"
	}
	if inv.help {
		return inv, ""
	}
	if inv.command.path == "profile create" && strings.IndexByte(inv.value, 0) >= 0 {
		return inv, "invalid file argument"
	}
	if inv.command.group {
		return inv, "missing command"
	}
	if inv.command.nameOperand && inv.operand == "" {
		return inv, "missing required name operand"
	}
	if inv.command.valueFlag != "" && !inv.command.optionalValue && inv.value == "" {
		return inv, "missing required flag " + inv.command.valueFlag
	}
	if inv.command.auxValueFlag != "" && !inv.command.optionalAuxValue && inv.auxValue == "" {
		return inv, "missing required flag " + inv.command.auxValueFlag
	}
	if inv.command.thirdValueFlag != "" && !inv.command.optionalThirdValue && inv.thirdValue == "" {
		return inv, "missing required flag " + inv.command.thirdValueFlag
	}
	if inv.command.auxValueFlag == "--auth" && inv.auxValue != "" {
		if _, err := codexauth.ParseCredentialRef(inv.auxValue); err != nil {
			return inv, "invalid Codex authentication reference"
		}
	}
	if inv.command.path == "run" && profile.ValidateName(inv.value) != nil {
		return inv, "invalid Profile name"
	}
	if strings.HasPrefix(inv.command.path, "explain ") && profile.ValidateName(inv.value) != nil {
		return inv, "invalid Profile name"
	}
	if inv.command.thirdValueFlag == "--expect-authority-digest" && inv.thirdValue != "" && !validAuthorityDigest(inv.thirdValue) {
		return inv, "invalid authority digest"
	}
	if isMutation(inv.command.path) {
		if profile.ValidateName(inv.operand) != nil {
			return inv, "invalid Profile name"
		}
		if inv.command.valueFlag == "--name" && profile.ValidateName(inv.value) != nil {
			return inv, "invalid destination Profile name"
		}
		if inv.command.valueFlag == "--confirm" && inv.value != "" && inv.value != inv.operand {
			return inv, "--confirm must match NAME exactly"
		}
		if inv.command.valueFlag == "--name" && strings.EqualFold(inv.operand, inv.value) {
			return inv, "source and destination must have distinct names (including case)"
		}
	}
	if inv.command.path == "profile export" && profile.ValidateName(inv.operand) != nil {
		return inv, "invalid Profile name"
	}
	if inv.command.path == "profile import" && profile.ValidateName(inv.auxValue) != nil {
		return inv, "invalid destination Profile name"
	}
	if (inv.command.path == "profile import" || inv.command.path == "profile import validate") && (strings.IndexByte(inv.value, 0) >= 0 || strings.IndexByte(inv.auxValue, 0) >= 0 || strings.IndexByte(inv.thirdValue, 0) >= 0) {
		return inv, "invalid file argument"
	}

	return inv, ""
}

func validAuthorityDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// GenericRunRequested identifies the validated command path so main can avoid
// assembling credential-backed targets for a generic run or dry-run.
func GenericRunRequested(args []string) bool {
	inv, problem := parseCommand(args)
	return problem == "" && !inv.help && inv.command.path == "run"
}

// CodexDryRunRequested identifies the already syntax-validated early path used
// by the executable to avoid constructing authentication/runtime dependencies.
func CodexDryRunRequested(args []string) bool {
	inv, problem := parseCommand(args)
	return problem == "" && !inv.help && inv.command.path == "codex" && inv.enabled
}

// ProfileCreateRequested identifies the syntax-validated declarative creation
// path so the executable can avoid assembling targets, credentials or runtime.
func ProfileCreateRequested(args []string) bool {
	inv, problem := parseCommand(args)
	return problem == "" && !inv.help && inv.command.path == "profile create"
}

// ProfileExchangeRequested identifies the syntax-validated early route so the
// executable does not assemble targets, credentials, Sessions, or runtime state.
func ProfileExchangeRequested(args []string) bool {
	inv, problem := parseCommand(args)
	return problem == "" && !inv.help && (inv.command.path == "profile export" || inv.command.path == "profile import" || inv.command.path == "profile import validate")
}

func ExplanationRequested(args []string) bool {
	inv, problem := parseCommand(args)
	return problem == "" && !inv.help && strings.HasPrefix(inv.command.path, "explain ")
}

// publicToken identifies command/flag spellings without echoing attached values,
// private paths, terminal controls, or arbitrary positional arguments.
func publicToken(token string) string {
	if len(token) == 0 || len(token) > 64 {
		return "(unrecognized spelling)"
	}
	for _, r := range token {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return "(unrecognized spelling)"
		}
	}
	return fmt.Sprintf("%q", token)
}

func helpPath(command commandSpec) string {
	if command.path == "" {
		return "acs help"
	}
	return "acs " + command.path + " --help"
}

func (app App) printHelp(command commandSpec) {
	fmt.Fprintf(app.Output, "Usage: %s\n\n%s\n", command.syntax, command.description)
	if command.group || command.path == "devin" || command.path == "codex" {
		fmt.Fprintln(app.Output, "\nCommands:")
		for _, child := range commands[1:] {
			if command.path == "" || strings.HasPrefix(child.path, command.path+" ") {
				fmt.Fprintf(app.Output, "  %s\n", child.syntax)
			}
		}
	}
	fmt.Fprintln(app.Output, "\nFlags:")
	if command.valueFlag != "" {
		if command.valueFlag == "--file" {
			if command.path == "profile export" {
				fmt.Fprintln(app.Output, "  --file FILE  Optional exclusive new output file")
			} else {
				fmt.Fprintln(app.Output, "  --file FILE  Required explicit JSON input file")
			}
		} else if command.valueFlag == "--confirm" {
			fmt.Fprintln(app.Output, "  --confirm NAME  Exact name confirmation for deliberate noninteractive deletion")
		} else if command.optionalValue {
			fmt.Fprintln(app.Output, "  --target devin|sandbox|codex-auth  Optional workflow; not a backend selector")
		} else {
			fmt.Fprintf(app.Output, "  %s <name>  Required name\n", command.valueFlag)
		}
	}
	if command.auxValueFlag != "" {
		requirement := "Required"
		if command.optionalAuxValue {
			requirement = "Optional"
		}
		if command.auxValueFlag == "--as" {
			fmt.Fprintf(app.Output, "  --as NAME  %s destination Profile name\n", requirement)
		} else if command.auxValueFlag == "--bindings" {
			fmt.Fprintf(app.Output, "  --bindings FILE  %s explicit local binding document\n", requirement)
		} else {
			fmt.Fprintf(app.Output, "  %s <ref>  %s canonical named authentication reference\n", command.auxValueFlag, requirement)
		}
	}
	if command.thirdValueFlag != "" {
		if command.thirdValueFlag == "--expect-authority-digest" {
			fmt.Fprintf(app.Output, "  %s DIGEST  Optional expected semantic authority digest\n", command.thirdValueFlag)
		} else {
			fmt.Fprintf(app.Output, "  %s FILE  Optional explicit local binding document\n", command.thirdValueFlag)
		}
	}
	if command.boolFlag != "" {
		description := map[string]string{"--dry-run": "Inspect without launching", "--device-auth": "Use device login", "--json": "Emit versioned JSON format 1"}[command.boolFlag]
		if command.path == "profile create" {
			description = "Validate and preview without changing Profile storage"
		} else if command.path == "profile import" {
			description = "Validate and preview without publishing a Profile"
		}
		fmt.Fprintf(app.Output, "  %s  %s\n", command.boolFlag, description)
	}
	if command.secondBoolFlag != "" {
		fmt.Fprintln(app.Output, "  --check-native-readiness  Run the bounded platform and native-backend readiness observation")
	}
	fmt.Fprintln(app.Output, "  --help  Show this help without runtime access")
	if command.path == "run" || command.path == "explain run" {
		fmt.Fprintln(app.Output, "\nGrammar: --profile and --dry-run may be reordered before exactly one required -- boundary.\nEverything after that boundary is one literal child argv; a later -- belongs to the child.\nNo target pass-through, backend selection, sandbox bypass, or implicit shell is supported.")
	} else if command.nameOperand {
		fmt.Fprintln(app.Output, "\nGrammar: command words first, then exactly one NAME and flags in any order. Values use a separate token.\nEach flag may occur once. No extra operands, '=' syntax, '--' separator,\ntarget pass-through, backend selection, or sandbox bypass is supported.")
	} else {
		fmt.Fprintln(app.Output, "\nGrammar: command words first, then flags in any order. Values use a separate token.\nEach flag may occur once. No positional arguments, '=' syntax, '--' separator,\ntarget pass-through, backend selection, or sandbox bypass is supported.")
		if command.path == "" || command.path == "profile" {
			fmt.Fprintln(app.Output, "Exception: Profile commands with NAME accept one operand before or after their flags; see acs profile --help.")
		}
	}
	fmt.Fprintf(app.Output, "\nExamples:\n  %s\n  %s\n", command.example, helpPath(command))
	if command.path == "" {
		fmt.Fprintln(app.Output, "\nFirst use: add name/SKILL.md under ~/.config/devin/skills or ~/.agents/skills,\nrun acs doctor --target devin, create a Profile, validate it with acs profile validate NAME,\ninspect it with --dry-run, then launch from your workspace.")
	}
}

// RunInformational handles help, usage failures, and version without runtime
// dependencies. The executable calls it before home discovery or adapter setup.
func (app App) RunInformational(args []string) (handled bool, code int) {
	inv, problem := parseCommand(args)
	if problem != "" {
		if strings.HasPrefix(inv.command.path, "explain ") && containsArgument(args, "--json") {
			return true, app.writeExplanationDiagnostic(inv, "invalid_invocation", "The explanation command syntax is invalid.")
		}
		code = app.fail("%s; try %s\nusage: %s", problem, helpPath(inv.command), inv.command.syntax)
		if inv.command.path == "" {
			fmt.Fprintln(app.ErrorOutput, "Use acs version to inspect the build.")
		}
		if inv.command.path == "devin" {
			fmt.Fprintln(app.ErrorOutput, "ACS will not start Devin without the required sandbox")
		}
		return true, code
	}
	if inv.help {
		app.printHelp(inv.command)
		return true, 0
	}
	if inv.command.path == "version" {
		version := app.Version
		if version == "" {
			version = "devel"
		}
		fmt.Fprintf(app.Output, "acs %s\n", safeTerminalText(version))
		return true, 0
	}
	return false, 0
}

func containsArgument(arguments []string, wanted string) bool {
	for _, argument := range arguments {
		if argument == wanted {
			return true
		}
	}
	return false
}

func isMutation(command string) bool {
	switch command {
	case "profile edit", "profile clone", "profile rename", "profile delete", "profile migrate":
		return true
	}
	return false
}
