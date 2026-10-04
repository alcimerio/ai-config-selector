// Package codexcompat owns the exact reviewed target contract. Adding a version
// requires source review and locked native acceptance, never a caller override.
package codexcompat

import "strings"

const LegacyVersion = "0.149.1"
const CurrentVersion = "0.156.0"
const ExecutableRequirementID = "codex-cli-exact-0.149.1-or-0.156.0"

func AcceptsVersion(version string) bool {
	return version == LegacyVersion || version == CurrentVersion
}

// AcceptsOutput admits only the bounded version probe's complete output.
func AcceptsOutput(output string) bool {
	value := strings.TrimSpace(output)
	return value == "codex-cli "+LegacyVersion || value == "codex-cli "+CurrentVersion
}
