package executor

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/runcommand"
)

func resolvedCommandPlan(t *testing.T) authority.Plan {
	t.Helper()
	plan, err := authority.New(nil, launch.WorkspaceAccessReadOnly, 3, "").ForCommand()
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func executableFixture(t *testing.T, workspace string) string {
	t.Helper()
	path := filepath.Join(workspace, "tool")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunCommandPreservesArgvAndUsesSharedLifecycle(t *testing.T) {
	workspace := t.TempDir()
	executableFixture(t, workspace)
	command, err := runcommand.Resolve(workspace, []string{"./tool", "space value", "", "--", "*.go", "$HOME"})
	if err != nil {
		t.Fatal(err)
	}
	process := &fakeProcess{}
	sandbox := &fakeSandbox{process: process}
	sessions := filepath.Join(t.TempDir(), "sessions")
	plan := resolvedCommandPlan(t)
	code, err := newExecutor(sandbox).RunCommand(context.Background(), CommandRequest{
		SessionsDirectory: sessions, WorkingDirectory: workspace, ResolvedPlan: &plan, Command: command,
	})
	if err != nil || code != 0 {
		t.Fatalf("RunCommand = (%d, %v)", code, err)
	}
	wantArguments := []string{"space value", "", "--", "*.go", "$HOME"}
	if !reflect.DeepEqual(sandbox.request.Arguments, wantArguments) {
		t.Fatalf("prepared arguments = %#v, want %#v", sandbox.request.Arguments, wantArguments)
	}
	if process.starts != 1 || process.waits != 1 || sandbox.prepares != 1 {
		t.Fatalf("lifecycle starts=%d waits=%d prepares=%d", process.starts, process.waits, sandbox.prepares)
	}
	if sandbox.check.WorkspaceAccess != launch.WorkspaceAccessReadOnly || sandbox.request.WorkspaceAccess != launch.WorkspaceAccessReadOnly {
		t.Fatal("resolved workspace authority drifted")
	}
	if entries, readErr := os.ReadDir(sessions); readErr != nil || len(entries) != 0 {
		t.Fatalf("settled Session was not removed: %v %v", entries, readErr)
	}
}

func TestRunCommandFailsClosedWhenExecutableChangesAfterCheck(t *testing.T) {
	workspace := t.TempDir()
	tool := executableFixture(t, workspace)
	command, err := runcommand.Resolve(workspace, []string{"./tool"})
	if err != nil {
		t.Fatal(err)
	}
	sandbox := &fakeSandbox{process: &fakeProcess{}, checkFn: func() error {
		replacement := filepath.Join(workspace, "replacement")
		if err := os.WriteFile(replacement, []byte("#!/bin/sh\nexit 99\n"), 0o700); err != nil {
			return err
		}
		return os.Rename(replacement, tool)
	}}
	sessions := filepath.Join(t.TempDir(), "sessions")
	plan := resolvedCommandPlan(t)
	code, err := newExecutor(sandbox).RunCommand(context.Background(), CommandRequest{
		SessionsDirectory: sessions, WorkingDirectory: workspace, ResolvedPlan: &plan, Command: command,
	})
	if code != 1 || err == nil || sandbox.prepares != 0 {
		t.Fatalf("drift result = (%d, %v), prepares=%d", code, err, sandbox.prepares)
	}
	if entries, readErr := os.ReadDir(sessions); readErr != nil || len(entries) != 0 {
		t.Fatalf("drift retained Session: %v %v", entries, readErr)
	}
}

func replaceWorkspace(t *testing.T, workspace string) {
	t.Helper()
	oldWorkspace := workspace + "-old"
	if err := os.Rename(workspace, oldWorkspace); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestRunCommandRejectsWorkspaceReplacementBeforeCheck(t *testing.T) {
	parent := t.TempDir()
	workspace := filepath.Join(parent, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	command, err := runcommand.Resolve(workspace, []string{"/usr/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	replaceWorkspace(t, workspace)
	sandbox := &fakeSandbox{process: &fakeProcess{}}
	plan := resolvedCommandPlan(t)
	code, err := newExecutor(sandbox).RunCommand(context.Background(), CommandRequest{
		SessionsDirectory: filepath.Join(t.TempDir(), "sessions"), WorkingDirectory: workspace,
		ResolvedPlan: &plan, Command: command,
	})
	if code != 1 || err == nil || sandbox.checks != 0 || sandbox.prepares != 0 {
		t.Fatalf("replacement result=(%d,%v) checks=%d prepares=%d", code, err, sandbox.checks, sandbox.prepares)
	}
}

func TestRunCommandRejectsWorkspaceReplacementAfterCheckBeforePrepare(t *testing.T) {
	parent := t.TempDir()
	workspace := filepath.Join(parent, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	command, err := runcommand.Resolve(workspace, []string{"/usr/bin/true"})
	if err != nil {
		t.Fatal(err)
	}
	sandbox := &fakeSandbox{process: &fakeProcess{}, checkFn: func() error {
		replaceWorkspace(t, workspace)
		return nil
	}}
	plan := resolvedCommandPlan(t)
	code, err := newExecutor(sandbox).RunCommand(context.Background(), CommandRequest{
		SessionsDirectory: filepath.Join(t.TempDir(), "sessions"), WorkingDirectory: workspace,
		ResolvedPlan: &plan, Command: command,
	})
	if code != 1 || err == nil || sandbox.checks != 1 || sandbox.prepares != 0 {
		t.Fatalf("replacement result=(%d,%v) checks=%d prepares=%d", code, err, sandbox.checks, sandbox.prepares)
	}
}

func TestRunCommandRejectsInvalidPreparedProcess(t *testing.T) {
	workspace := t.TempDir()
	executableFixture(t, workspace)
	command, err := runcommand.Resolve(workspace, []string{"./tool"})
	if err != nil {
		t.Fatal(err)
	}
	sessions := filepath.Join(t.TempDir(), "sessions")
	sandbox := &invalidPreparedProcessSandbox{}
	plan := resolvedCommandPlan(t)
	code, err := newExecutor(sandbox).RunCommand(context.Background(), CommandRequest{
		SessionsDirectory: sessions, WorkingDirectory: workspace, ResolvedPlan: &plan, Command: command,
	})
	if code != 1 {
		t.Fatalf("code = %d", code)
	}
	requireSandboxSetupFailure(t, err)
	if entries, readErr := os.ReadDir(sessions); readErr != nil || len(entries) != 0 {
		t.Fatalf("invalid process retained Session: %v %v", entries, readErr)
	}
}

func TestRunCommandMapsCancellationOnlyAfterWaitAndCleanup(t *testing.T) {
	workspace := t.TempDir()
	executableFixture(t, workspace)
	command, err := runcommand.Resolve(workspace, []string{"./tool"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	process := &fakeProcess{waitFn: func() error { cancel(); return nil }}
	sandbox := &fakeSandbox{process: process}
	plan := resolvedCommandPlan(t)
	code, err := newExecutor(sandbox).RunCommand(ctx, CommandRequest{
		SessionsDirectory: filepath.Join(t.TempDir(), "sessions"), WorkingDirectory: workspace,
		ResolvedPlan: &plan, Command: command,
	})
	if code != 130 || err != context.Canceled || process.starts != 1 || process.waits != 1 {
		t.Fatalf("cancellation result=(%d,%v) starts=%d waits=%d", code, err, process.starts, process.waits)
	}
}
