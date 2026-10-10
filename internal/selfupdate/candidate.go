package selfupdate

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"

	"github.com/alcimerio/ai-config-selector/internal/release/artifacts"
)

// Candidate updates never consult a Release endpoint or infer a version.
func runLinuxCandidate(ctx context.Context, current, pin string, check bool, cfg Config) (Result, error) {
	out := Result{Current: current, Target: pin}
	if cfg.PlatformOS != "linux" || cfg.PlatformArch != "amd64" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return out, errors.New("local candidate updates require native linux/amd64")
	}
	if pin == "" || !filepath.IsAbs(cfg.CandidateDirectory) || cfg.Executable == "" {
		return out, errors.New("local candidate updates require a version, absolute candidate directory and explicit executable")
	}
	old, err := ParseVersion(current)
	if err != nil {
		return out, err
	}
	next, err := ParseVersion(pin)
	if err != nil {
		return out, err
	}
	// Retain the exact validated bytes through replacement, even if the local
	// candidate files subsequently change. This also validates check-only runs.
	binary, err := artifacts.Read(cfg.CandidateDirectory, pin, true)
	if err != nil {
		return out, err
	}
	out.Available = Compare(old, next) < 0
	out.Downgrade = Compare(old, next) > 0
	if check {
		return out, nil
	}
	install, err := preflight(cfg.Executable, false)
	if err != nil {
		return out, err
	}
	out.Installation = install
	directory, err := pinDirectory(filepath.Dir(install))
	if err != nil {
		return out, err
	}
	defer directory.Close()
	original, hash, err := installedIdentity(directory, filepath.Base(install))
	if err != nil {
		return out, err
	}
	if err := replace(ctx, install, binary, original, hash, directory); err != nil {
		out.Changed = errors.Is(err, ErrPublishedUncertain)
		return out, err
	}
	out.Changed = true
	return out, nil
}
