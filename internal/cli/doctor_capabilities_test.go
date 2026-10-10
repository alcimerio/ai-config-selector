package cli

import (
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/diagnostics"
	"github.com/alcimerio/ai-config-selector/internal/linuxprobe"
)

func TestLinuxDoctorProbesCannotEnableLaunchReadiness(t *testing.T) {
	base := diagnostics.Result{FormatVersion: 1, Operation: "doctor", Checks: []diagnostics.Check{
		{ID: "host.platform", Status: "fail", Code: "unsupported_platform", NextStep: "Linux launches remain disabled."},
		{ID: "backend.file", Status: "unchecked"},
		{ID: "runtime.enforcement", Status: "unchecked", Code: "not_probed"},
		{ID: "authentication", Status: "unchecked", Code: "not_queried"},
	}}
	r := withLinuxCapabilities(base, linuxprobe.Report{Checks: []linuxprobe.Check{
		{ID: "linux.bwrap", Status: "pass", Code: "bwrap_trusted_identity", NextStep: "System identity observed."},
		{ID: "linux.seccomp", Status: "pass", Code: "seccomp_filter", NextStep: "Probe filter observed."},
	}})
	if r.ExitCode() != 1 || r.Passed("host.platform") || r.Passed("runtime.enforcement") || r.Passed("authentication") || !r.Passed("backend.file") {
		t.Fatalf("probes changed admission: %+v", r)
	}
}

func TestLinuxDoctorProbeFlagIsExplicit(t *testing.T) {
	for _, args := range [][]string{{"doctor"}, {"doctor", "--json"}, {"doctor", "--check-linux-capabilities"}, {"doctor", "--json", "--check-linux-capabilities", "--target", "sandbox"}} {
		inv, err := parseCommand(args)
		if err != "" {
			t.Fatal(err)
		}
		want := false
		for _, arg := range args {
			want = want || arg == "--check-linux-capabilities"
		}
		if inv.secondEnabled != want {
			t.Fatalf("unexpected probe opt-in: %+v", inv)
		}
	}
	for _, args := range [][]string{
		{"doctor", "--check-linux-capabilities", "--check-linux-capabilities"},
		{"profile", "validate", "example", "--check-linux-capabilities"},
	} {
		if _, err := parseCommand(args); err == "" {
			t.Fatalf("accepted %v", args)
		}
	}
}
