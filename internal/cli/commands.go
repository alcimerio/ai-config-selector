package cli

import (
	"fmt"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"strings"
)

// commandSpec is the public grammar. Command words precede flags; valued flags
// consume exactly one separate, nonempty token, and every flag occurs once.
type commandSpec struct {
	path, syntax, description, example string
	valueFlag, boolFlag                string
	group                              bool
	nameOperand                        bool
	optionalValue                      bool
}

var commands = []commandSpec{
	{path: "", syntax: "acs <command> [flags]", description: "Create capability Profiles and use the required native sandbox.", example: "acs devin create-profile --name backend-review", group: true},
	{path: "profile", syntax: "acs profile <command> [flags]", description: "Inspect, validate, edit, clone, rename or delete stored Profiles.", example: "acs profile list\n  acs profile show backend-review", group: true},
	{path: "profile list", syntax: "acs profile list [--json]", description: "List direct stored Profiles, including per-entry structural errors. Missing storage is empty.\nNo sources, targets, credentials or Sessions are accessed. No files are changed.", example: "acs profile list\n  acs profile list --json", boolFlag: "--json"},
	{path: "profile show", syntax: "acs profile show NAME [--json]", description: "Show persisted Profile versions and selections, even with missing Skill sources.\nSupported structure does not imply launch readiness. No files are changed.", example: "acs profile show backend-review\n  acs profile show --json backend-review", boolFlag: "--json", nameOperand: true},
	{path: "profile edit", syntax: "acs profile edit NAME", description: "Edit stored selections interactively in the Profile Builder. Preview exact canonical bytes before saving.\nUnavailable selections remain selected until explicitly removed. No client, credentials or Session is needed.", example: "acs profile edit backend-review", nameOperand: true},
	{path: "profile clone", syntax: "acs profile clone NAME --name NEW", description: "Open a seeded Profile Builder under a new name. Preview and confirm before publication.\nThe source must remain unchanged and the destination must remain absent.", example: "acs profile clone backend-review --name frontend-review", nameOperand: true, valueFlag: "--name"},
	{path: "profile rename", syntax: "acs profile rename NAME --name NEW", description: "Preview and confirm coordinated filename and embedded-name changes interactively.\nAn occupied destination is never overwritten. Legacy conversion requires a canonical representation preview.", example: "acs profile rename backend-review --name service-review", nameOperand: true, valueFlag: "--name"},
	{path: "profile delete", syntax: "acs profile delete NAME [--confirm NAME]", description: "Delete only the named stored Profile at its captured revision.\nInteractive deletion requires typing the exact name; noninteractive use requires an exact --confirm NAME.\nSafely readable unsupported documents may be deleted. Identities, Sessions and other Profiles are unaffected.", example: "acs profile delete backend-review\n  acs profile delete backend-review --confirm backend-review", nameOperand: true, valueFlag: "--confirm", optionalValue: true},

	{path: "doctor", syntax: "acs doctor [--target devin|sandbox|codex-auth] [--json]", description: "Inspect passive host and backend-file prerequisites. Optional targets check executable availability only.\nVersions, authentication and actual sandbox enforcement remain unchecked. No processes run or files change.\ncodex-auth describes named authentication workflows; interactive Codex launch is not implemented.", example: "acs doctor\n  acs doctor --target devin --json", valueFlag: "--target", boolFlag: "--json", optionalValue: true},
	{path: "profile validate", syntax: "acs profile validate NAME [--json]", description: "Validate stored Profile structure and selected Skill-source resolution without a launch plan.\nPlatform, backend, executables, authentication and runtime remain unchecked. No files change.", example: "acs profile validate backend-review\n  acs profile validate --json backend-review", boolFlag: "--json", nameOperand: true},
	{path: "devin", syntax: "acs devin --profile <name> [--dry-run]", description: "Launch Devin with a saved Profile. --dry-run inspects the plan without creating a Session.\nUse create-profile to open the interactive Profile Builder.", example: "acs devin --profile backend-review --dry-run\n  acs devin --profile backend-review", valueFlag: "--profile", boolFlag: "--dry-run"},
	{path: "devin create-profile", syntax: "acs devin create-profile --name <name>", description: "Create a new Profile using interactive stdin and stdout. Existing names are never overwritten.\nSelect Skills with Space/Enter; return with Left/Esc; choose Create Profile to save.\nCtrl+C cancels without saving (exit 130).", example: "acs devin create-profile --name backend-review", valueFlag: "--name"},
	{path: "sandbox", syntax: "acs sandbox --profile <name> [--dry-run]", description: "Open /bin/zsh -f in the Profile sandbox without Devin credentials.\n--dry-run inspects the plan without creating a Session or starting a shell.", example: "acs sandbox --dry-run --profile backend-review\n  acs sandbox --profile backend-review", valueFlag: "--profile", boolFlag: "--dry-run"},
	{path: "codex", syntax: "acs codex auth <command> [flags]", description: "Manage named Codex authentication identities.", example: "acs codex auth list", group: true},
	{path: "codex auth", syntax: "acs codex auth <command> [flags]", description: "Manage ACS-owned ChatGPT identities in the macOS Keychain.\nLogin and status require codex-cli 0.149.1 and the required sandbox.\nThese commands do not launch interactive Codex or use the global Codex login.", example: "acs codex auth login --name work\n  acs codex auth status --name work", group: true},
	{path: "codex auth login", syntax: "acs codex auth login --name <name> [--device-auth]", description: "Create a named ChatGPT identity; requires interactive stdin/stdout and codex-cli 0.149.1.\n--device-auth selects the device login flow. Existing names are never replaced.", example: "acs codex auth login --device-auth --name work", valueFlag: "--name", boolFlag: "--device-auth"},
	{path: "codex auth list", syntax: "acs codex auth list", description: "List non-secret metadata for ACS-owned identities in the macOS Keychain.", example: "acs codex auth list"},
	{path: "codex auth status", syntax: "acs codex auth status --name <name>", description: "Verify one named identity in a contained status Session using codex-cli 0.149.1.", example: "acs codex auth status --name work", valueFlag: "--name"},
	{path: "codex auth recover", syntax: "acs codex auth recover --name <name>", description: "Recover a quarantined identity after proving its protected Session is inactive.", example: "acs codex auth recover --name work", valueFlag: "--name"},
	{path: "codex auth logout", syntax: "acs codex auth logout --name <name>", description: "Remove an ACS-owned identity. An absent valid name succeeds; global Codex login is untouched.", example: "acs codex auth logout --name work", valueFlag: "--name"},
	{path: "version", syntax: "acs version", description: "Print the ACS build version.", example: "acs version"},
}

type invocation struct {
	command       commandSpec
	value         string
	operand       string
	enabled, help bool
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
		if helpCommand || (flag != "--help" && flag != inv.command.valueFlag && flag != inv.command.boolFlag) {
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
		case inv.command.boolFlag:
			inv.enabled = true
		}
	}
	if inv.command.path == "doctor" && inv.value != "" && inv.value != "devin" && inv.value != "sandbox" && inv.value != "codex-auth" {
		return inv, "target must be devin, sandbox or codex-auth"
	}
	if inv.help {
		return inv, ""
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

	return inv, ""
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
	if command.group || command.path == "devin" {
		fmt.Fprintln(app.Output, "\nCommands:")
		for _, child := range commands[1:] {
			if command.path == "" || strings.HasPrefix(child.path, command.path+" ") {
				fmt.Fprintf(app.Output, "  %s\n", child.syntax)
			}
		}
	}
	fmt.Fprintln(app.Output, "\nFlags:")
	if command.valueFlag != "" {
		if command.valueFlag == "--confirm" {
			fmt.Fprintln(app.Output, "  --confirm NAME  Exact name confirmation for deliberate noninteractive deletion")
		} else if command.optionalValue {
			fmt.Fprintln(app.Output, "  --target devin|sandbox|codex-auth  Optional workflow; not a backend selector")
		} else {
			fmt.Fprintf(app.Output, "  %s <name>  Required name\n", command.valueFlag)
		}
	}
	if command.boolFlag != "" {
		fmt.Fprintf(app.Output, "  %s  %s\n", command.boolFlag, map[string]string{"--dry-run": "Inspect without launching", "--device-auth": "Use device login", "--json": "Emit versioned JSON format 1"}[command.boolFlag])
	}
	fmt.Fprintln(app.Output, "  --help  Show this help without runtime access")
	if command.nameOperand {
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

func isMutation(command string) bool {
	switch command {
	case "profile edit", "profile clone", "profile rename", "profile delete":
		return true
	}
	return false
}
