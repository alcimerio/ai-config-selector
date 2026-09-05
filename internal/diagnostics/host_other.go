//go:build !darwin

package diagnostics

import (
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"runtime"
)

func inspectPlatform() (launch.Platform, error) {
	return launch.Platform{OS: runtime.GOOS, Architecture: runtime.GOARCH}, nil
}
