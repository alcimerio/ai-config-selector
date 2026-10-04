package cli

import (
	"context"
	"errors"
	"github.com/alcimerio/ai-config-selector/internal/codexauth"
	"github.com/alcimerio/ai-config-selector/internal/diagnostics"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"testing"
)

type checkReadiness struct {
	calls int
	order *[]string
	ready bool
}

func (p *checkReadiness) Readiness(ctx context.Context) (launch.SandboxReadiness, error) {
	p.calls++
	*p.order = append(*p.order, "native")
	if _, ok := ctx.Deadline(); !ok {
		panic("unbounded probe")
	}
	return launch.SandboxReadiness{Supported: true, Ready: p.ready}, nil
}
func passiveCheckFacts() diagnostics.Result {
	r := diagnostics.Result{FormatVersion: 1, Operation: "check", Target: "codex", Checks: []diagnostics.Check{}}
	for _, id := range []string{"profile.structure", "profile.sources", "profile.overlays", "host.platform", "backend.file", "executable.availability"} {
		r.Checks = append(r.Checks, diagnostics.Check{ID: id, Status: "pass", Code: "observed", NextStep: "safe"})
	}
	for _, id := range []string{"executable.version", "authentication", "runtime.enforcement", "native.readiness"} {
		r.Checks = append(r.Checks, diagnostics.Check{ID: id, Status: "unchecked", Code: "not_requested", NextStep: "safe"})
	}
	r.Checks = append(r.Checks, diagnostics.Check{ID: "operation.completion", Status: "pass", Code: "completed", NextStep: "safe"})
	return r
}
func fact(t *testing.T, r diagnostics.Result, id, status, code string) {
	t.Helper()
	for _, c := range r.Checks {
		if c.ID == id {
			if c.Status != status || c.Code != code {
				t.Fatalf("%+v", c)
			}
			return
		}
	}
	t.Fatal("missing fact")
}
func TestCheckExplicitProbesAndVersionEvidence(t *testing.T) {
	for _, tc := range []struct {
		err                          error
		version, status, versionCode string
	}{
		{nil, "pass", "pass", "supported_status_version"},
		{codexauth.ErrUnsupportedVersion, "fail", "unchecked", "unsupported_status_version"},
		{errors.New("private credentials and control output"), "unchecked", "fail", "status_version_unconfirmed"},
		{codexauth.ErrBindingQuarantined, "unchecked", "fail", "status_version_unconfirmed"},
	} {
		order := []string{}
		native := &checkReadiness{order: &order, ready: true}
		app := App{NativeReadiness: native, CheckAuthentication: func(ctx context.Context, name string) (codexauth.IdentityStatus, error) {
			if name != "explicit" {
				t.Fatalf("inferred identity %q", name)
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("unbounded status")
			}
			order = append(order, "status")
			return codexauth.IdentityStatus{}, tc.err
		}}
		inv := invocation{secondEnabled: true, thirdEnabled: true, thirdValue: "explicit"}
		r := app.probeCheck(context.Background(), inv, passiveCheckFacts())
		if len(order) != 2 || order[0] != "native" || order[1] != "status" {
			t.Fatal(order)
		}
		fact(t, r, "runtime.enforcement", "unchecked", "not_requested")
		fact(t, r, "native.readiness", "pass", "native_backend_ready")
		fact(t, r, "executable.version", tc.version, tc.versionCode)
		wantCode := "named_status_failed"
		if tc.err == nil {
			wantCode = "named_status_passed"
		}
		if tc.err == codexauth.ErrUnsupportedVersion {
			wantCode = "version_required"
		}
		fact(t, r, "authentication", tc.status, wantCode)
	}
}
func TestCheckNeverProbesUnrequestedFailedOrCancelledPrerequisites(t *testing.T) {
	app := App{CheckAuthentication: func(context.Context, string) (codexauth.IdentityStatus, error) {
		t.Fatal("status called")
		return codexauth.IdentityStatus{}, nil
	}}
	r := app.probeCheck(context.Background(), invocation{}, passiveCheckFacts())
	fact(t, r, "authentication", "unchecked", "not_requested")
	r = passiveCheckFacts()
	r.SetFact("profile.overlays", "fail", "unsupported", "safe")
	r = app.probeCheck(context.Background(), invocation{thirdEnabled: true, thirdValue: "explicit"}, r)
	fact(t, r, "authentication", "unchecked", "prerequisites_required")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r = app.probeCheck(ctx, invocation{thirdEnabled: true, thirdValue: "explicit"}, passiveCheckFacts())
	fact(t, r, "operation.completion", "fail", "cancelled")
	fact(t, r, "runtime.enforcement", "unchecked", "not_requested")
	if r.ExitCode() != 1 {
		t.Fatal("cancelled success")
	}
	order := []string{}
	native := &checkReadiness{order: &order, ready: false}
	app.NativeReadiness = native
	r = app.probeCheck(context.Background(), invocation{secondEnabled: true, thirdEnabled: true, thirdValue: "explicit"}, passiveCheckFacts())
	fact(t, r, "native.readiness", "fail", "native_readiness_failed")
	fact(t, r, "runtime.enforcement", "unchecked", "not_requested")
	fact(t, r, "authentication", "unchecked", "prerequisites_required")
}
