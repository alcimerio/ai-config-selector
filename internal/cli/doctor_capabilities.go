package cli

import (
	"context"

	"github.com/alcimerio/ai-config-selector/internal/diagnostics"
	"github.com/alcimerio/ai-config-selector/internal/linuxprobe"
)

// Keep active observations outside diagnostics' passive dependency boundary.
func linuxCapabilityDiagnostics(ctx context.Context, result diagnostics.Result) diagnostics.Result {
	return withLinuxCapabilities(result, linuxprobe.Probe(ctx))
}

func withLinuxCapabilities(result diagnostics.Result, report linuxprobe.Report) diagnostics.Result {
	for _, c := range report.Checks {
		result.Checks = append(result.Checks, diagnostics.Check{ID: c.ID, Status: c.Status, Code: c.Code, NextStep: c.NextStep})
		if c.ID == "linux.bwrap" {
			result.SetFact("backend.file", c.Status, c.Code, c.NextStep)
		}
	}
	// Do not replace host.platform or runtime.enforcement with feature results.
	return result
}
