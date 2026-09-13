//go:build darwin

package executor

import (
	"context"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

type nativeInstructionObserverSandbox struct {
	delegate launch.ProcessSandbox
	observe  func(*launch.ProcessRequest)
}

func (sandbox nativeInstructionObserverSandbox) Readiness(ctx context.Context) (launch.SandboxReadiness, error) {
	return sandbox.delegate.Readiness(ctx)
}

func (sandbox nativeInstructionObserverSandbox) Check(ctx context.Context, check launch.SandboxCheck) error {
	return sandbox.delegate.Check(ctx, check)
}

func (sandbox nativeInstructionObserverSandbox) Prepare(ctx context.Context, request launch.ProcessRequest) (launch.Process, error) {
	if sandbox.observe != nil {
		sandbox.observe(&request)
	}
	return sandbox.delegate.Prepare(ctx, request)
}

// NewNativeInstructionObserverForTest preserves the production native sandbox
// and exposes only a read-only test observation point before its Prepare call.
func NewNativeInstructionObserverForTest(observe func(*launch.ProcessRequest)) *Executor {
	return newExecutor(nativeInstructionObserverSandbox{delegate: launch.NewProcessSandbox(), observe: observe})
}
