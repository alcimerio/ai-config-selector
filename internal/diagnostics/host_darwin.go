package diagnostics

import (
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"golang.org/x/sys/unix"
	"runtime"
)

// Native product version, without sw_vers or any subprocess.
func inspectPlatform() (launch.Platform, error) {
	release, err := unix.Sysctl("kern.osproductversion")
	return launch.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH, Release: release}, err
}
