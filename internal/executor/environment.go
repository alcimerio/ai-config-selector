package executor

import (
	"os"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/environmentresource"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

var (
	ErrEnvironmentUnavailable = environmentresource.ErrMissingValue
	ErrEnvironmentInvalid     = environmentresource.ErrInvalidValue
	ErrEnvironmentTooLarge    = environmentresource.ErrValueTooLarge
)

func hostEnvironmentLookup(name string) (string, bool) { return os.LookupEnv(name) }

func resolvePlanEnvironment(plan *authority.Plan, lookup environmentresource.Lookup) (*environmentresource.Lease, error) {
	if plan == nil || len(plan.EnvironmentIntents()) == 0 {
		return nil, nil
	}
	if lookup == nil {
		lookup = hostEnvironmentLookup
	}
	return environmentresource.Resolve(plan.EnvironmentIntents(), lookup)
}

// releaseEnvironmentAfterCleanup transfers release to the backend cleanup
// proof when one exists. Returning false leaves synchronous ownership with the
// caller for test/process implementations without an asynchronous phase.
func releaseEnvironmentAfterCleanup(process launch.Process, lease *environmentresource.Lease) bool {
	if process == nil || lease == nil {
		return false
	}
	cleanup, ok := process.(launch.ProcessCleanup)
	if !ok || cleanup.CleanupDone() == nil {
		return false
	}
	done := cleanup.CleanupDone()
	go func() {
		<-done
		lease.Release()
	}()
	return true
}
