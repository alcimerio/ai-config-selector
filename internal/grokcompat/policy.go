// Package grokcompat owns the exact reviewed Grok Build CLI contract.
// Adding a version requires source review and a locked artifact, never a
// caller override.
package grokcompat

import "strings"

const Version = "1.0.62"
const ExecutableRequirementID = "grok-cli-exact-1.0.62"

// AcceptsOutput admits only the bounded version probe's complete output.
// The optional parenthesized suffix is the upstream commit, which is not pinned.
func AcceptsOutput(output string) bool {
	value := strings.TrimSpace(output)
	if value == "grok "+Version {
		return true
	}
	prefix := "grok " + Version + " ("
	if !strings.HasPrefix(value, prefix) || !strings.HasSuffix(value, ")") {
		return false
	}
	commit := value[len(prefix) : len(value)-1]
	if commit == "" {
		return false
	}
	for _, character := range commit {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}
