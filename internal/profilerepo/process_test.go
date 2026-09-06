package profilerepo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

const oldBytes = "original future-codec bytes\x00\xff"
const newBytes = "canonical destination identity supplied by caller\x00\xfe"

func operation(op string) Request {
	switch op {
	case "create":
		return CreateRequest{"destination", revision("destination", false, nil), []byte(newBytes)}
	case "replace":
		return ReplaceRequest{"source", revision("source", true, []byte(oldBytes)), []byte(newBytes)}
	case "clone":
		return CloneRequest{"source", "destination", revision("source", true, []byte(oldBytes)), revision("destination", false, nil), []byte(newBytes)}
	case "rename":
		return RenameRequest{"source", "destination", revision("source", true, []byte(oldBytes)), revision("destination", false, nil), []byte(newBytes)}
	case "delete":
		return DeleteRequest{"source", revision("source", true, []byte(oldBytes))}
	}
	panic(op)
}
func seeded(t *testing.T) *Repository {
	t.Helper()
	r := New(t.TempDir())
	dir := filepath.Join(r.acsHome, "profiles")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "source.json"), []byte(oldBytes), 0600); err != nil {
		t.Fatal(err)
	}
	return r
}
func helper(root, mode, op, point string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestRepositoryProcessHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "ACS_REPOSITORY_HELPER="+mode, "ACS_REPOSITORY_ROOT="+root, "ACS_REPOSITORY_OPERATION="+op, "ACS_REPOSITORY_KILL="+point, "GORACE=atexit_sleep_ms=0")
	return cmd
}
func TestRepositoryProcessHelper(t *testing.T) {
	mode := os.Getenv("ACS_REPOSITORY_HELPER")
	if mode == "" {
		return
	}
	r := New(os.Getenv("ACS_REPOSITORY_ROOT"))
	point := os.Getenv("ACS_REPOSITORY_KILL")
	r.hook = func(p string) error {
		if p == point {
			fmt.Fprintln(os.Stdout, "reached kill point")
			if err := syscall.Kill(os.Getpid(), syscall.SIGKILL); err != nil {
				panic(err)
			}
			select {}
		}
		return nil
	}
	ctx := context.Background()
	switch mode {
	case "canonical-create":
		expected, _ := AbsentRevision("destination")
		if _, err := r.Apply(ctx, CreateRequest{"destination", expected, []byte(`{"version":2,"name":"destination","target":"devin","categories":{}}`)}); err != nil {
			t.Fatal(err)
		}
	case "apply":
		out, err := r.Apply(ctx, operation(os.Getenv("ACS_REPOSITORY_OPERATION")))
		if errors.Is(err, ErrBusy) {
			os.Exit(20)
		}
		if errors.Is(err, ErrConflict) {
			os.Exit(21)
		}
		if err != nil {
			t.Fatalf("apply: %+v %v", out, err)
		}
	case "recover":
		if _, err := r.Recover(ctx); err != nil {
			t.Fatal(err)
		}
	case "hold":
		d, err := r.open(true)
		if err != nil {
			t.Fatal(err)
		}
		defer d.close()
		if err = d.lock(); err != nil {
			t.Fatal(err)
		}
		defer d.release()
		fmt.Fprintln(os.Stdout, "locked")
		_, _ = io.Copy(io.Discard, os.Stdin)
	case "exec-lock":
		d, err := r.open(true)
		if err != nil {
			t.Fatal(err)
		}
		if err = d.lock(); err != nil {
			t.Fatal(err)
		}
		env := os.Environ()
		for i, value := range env {
			if strings.HasPrefix(value, "ACS_REPOSITORY_HELPER=") {
				env[i] = "ACS_REPOSITORY_HELPER=recover"
			}
		}
		if err = syscall.Exec(os.Args[0], []string{os.Args[0], "-test.run=^TestRepositoryProcessHelper$", "-test.count=1"}, env); err != nil {
			t.Fatal(err)
		}
	case "occupy":
		if err := os.WriteFile(filepath.Join(r.acsHome, "profiles", "destination.json"), []byte(newBytes), 0600); err != nil {
			t.Fatal(err)
		}
	case "restricted":
		if _, err := r.Apply(ctx, operation("create")); err == nil {
			t.Fatal("restricted identity wrote repository")
		}
	default:
		t.Fatal("unknown helper")
	}
}
func runKilled(t *testing.T, r *Repository, mode, op, point string) {
	t.Helper()
	output, err := helper(r.acsHome, mode, op, point).CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || !strings.Contains(string(output), "reached kill point") {
		t.Fatalf("kill point %s not reached: %v %s", point, err, output)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("not SIGKILL: %v", err)
	}
}
func recoverFreshTwice(t *testing.T, r *Repository) {
	t.Helper()
	for i := 0; i < 2; i++ {
		if output, err := helper(r.acsHome, "recover", "", "").CombinedOutput(); err != nil {
			t.Fatalf("fresh recovery %d: %v %s", i, err, output)
		}
	}
}
func assertSettled(t *testing.T, r *Repository, op string) {
	t.Helper()
	s, err := r.Read(context.Background(), "source")
	if err != nil {
		t.Fatal(err)
	}
	d, err := r.Read(context.Background(), "destination")
	if err != nil {
		t.Fatal(err)
	}
	old := s.Exists && string(s.Bytes) == oldBytes && !d.Exists
	committed := false
	switch op {
	case "create", "clone":
		committed = s.Exists && string(s.Bytes) == oldBytes && d.Exists && string(d.Bytes) == newBytes
	case "replace":
		committed = s.Exists && string(s.Bytes) == newBytes && !d.Exists
	case "rename":
		committed = !s.Exists && d.Exists && string(d.Bytes) == newBytes
	case "delete":
		committed = !s.Exists && !d.Exists
	}
	if !old && !committed {
		t.Fatalf("unsettled %s: source present=%v destination present=%v", op, s.Exists, d.Exists)
	}
	entries, err := os.ReadDir(filepath.Join(r.acsHome, "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), artifactPrefix) && entry.Name() != leaf("lock") {
			t.Fatal("leftover transaction artifact", entry.Name())
		}
		info, err := entry.Info()
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("mode preservation", err)
		}
	}
}
func trace(t *testing.T, r *Repository, mode, op string) []string {
	t.Helper()
	var points []string
	r.hook = func(p string) error { points = append(points, p); return nil }
	var err error
	if mode == "apply" {
		_, err = r.Apply(context.Background(), operation(op))
	} else {
		_, err = r.Recover(context.Background())
	}
	r.hook = nil
	if err != nil {
		t.Fatal(err)
	}
	return points
}
func TestProcessCrashEveryBoundary(t *testing.T) {
	for _, op := range []string{"create", "replace", "clone", "rename", "delete"} {
		t.Run(op, func(t *testing.T) {
			points := trace(t, seeded(t), "apply", op)
			for _, point := range points {
				t.Run(point, func(t *testing.T) {
					r := seeded(t)
					runKilled(t, r, "apply", op, point)
					recoverFreshTwice(t, r)
					assertSettled(t, r, op)
				})
			}
		})
	}
}
func TestInterruptedRecoveryEveryBoundary(t *testing.T) {
	for _, op := range []string{"create", "replace", "clone", "rename", "delete"} {
		t.Run(op, func(t *testing.T) {
			baseline := seeded(t)
			runKilled(t, baseline, "apply", op, "decision.publish.after")
			points := trace(t, baseline, "recover", op)
			for _, point := range points {
				t.Run(point, func(t *testing.T) {
					r := seeded(t)
					runKilled(t, r, "apply", op, "decision.publish.after")
					runKilled(t, r, "recover", op, point)
					recoverFreshTwice(t, r)
					assertSettled(t, r, op)
				})
			}
		})
	}
}
func TestIndependentWritersAndLiveKernelOwnership(t *testing.T) {
	r := seeded(t)
	holder := helper(r.acsHome, "hold", "", "")
	stdin, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close(); _ = holder.Process.Kill(); _ = holder.Wait() }()
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || line != "locked\n" {
		t.Fatal("holder did not lock", err)
	}
	if err = holder.Process.Signal(syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Apply(context.Background(), operation("replace")); !errors.Is(err, ErrBusy) {
		t.Fatal("paused live ownership stolen", err)
	}
	if _, err = r.Recover(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal("recovery stole paused live ownership", err)
	}
	if _, err = r.Read(context.Background(), "source"); err != nil {
		t.Fatal("passive read acquired busy lock", err)
	}
	if err = holder.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = holder.Wait()
	// Two independent processes use the same exact stale condition. Retry only
	// Busy, preserving that condition, so precisely one writer can commit.
	commands := []*exec.Cmd{helper(r.acsHome, "apply", "replace", ""), helper(r.acsHome, "apply", "replace", "")}
	for _, cmd := range commands {
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}
	// Join both initial attempts before retrying Busy. A losing process can
	// return before the winner releases its lock; retrying during that interval
	// legitimately returns Busy again and does not indicate a storage failure.
	results := make([]error, len(commands))
	for index, cmd := range commands {
		results[index] = cmd.Wait()
	}
	committed, stale := 0, 0
	for _, result := range results {
		err = result
		if err == nil {
			committed++
			continue
		}
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		if exit.ExitCode() == 20 {
			err = helper(r.acsHome, "apply", "replace", "").Run()
			if err == nil {
				committed++
				continue
			}
			if !errors.As(err, &exit) {
				t.Fatal(err)
			}
		}
		if exit.ExitCode() != 21 {
			t.Fatal("unexpected writer failure", err)
		}
		stale++
	}
	if committed != 1 || stale != 1 {
		t.Fatalf("committed=%d stale=%d", committed, stale)
	}
	assertSettled(t, r, "replace")
}

func TestKernelLockDoesNotSurviveExec(t *testing.T) {
	r := seeded(t)
	if output, err := helper(r.acsHome, "exec-lock", "", "").CombinedOutput(); err != nil {
		t.Fatalf("CLOEXEC lock leaked across exec: %v %s", err, output)
	}
}
