package diagnostics

import (
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestLinuxDoctorChecksFixedBashWithoutAdmittingHost(t *testing.T) {
	var requested string
	r := doctor("sandbox", func() (launch.Platform, error) { return launch.Platform{OS: "linux", Architecture: "amd64"}, nil },
		func() bool { t.Fatal("unsupported backend queried"); return false },
		func(path string) bool { requested = path; return true })
	if requested != "/bin/bash" || r.ExitCode() == 0 {
		t.Fatalf("Linux doctor: shell=%q result=%+v", requested, r)
	}
	for _, c := range r.Checks {
		if c.ID == "runtime.enforcement" && c.Status != "unchecked" {
			t.Fatal("passive doctor claimed enforcement")
		}
	}
}
