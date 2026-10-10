package launch

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/linuxprobe"
	"golang.org/x/sys/unix"
)

// These are test executable entry points, never production re-exec switches.
func TestLinuxContainmentHelper(t *testing.T) {
	mode := os.Args[len(os.Args)-1]
	switch mode {
	case "acs-containment-ready":
		if _, err := os.NewFile(3, "ready").Write([]byte{'R'}); err != nil {
			t.Fatal(err)
		}
		for {
			time.Sleep(time.Hour)
		}
	case "acs-containment-idle":
		for {
			time.Sleep(time.Hour)
		}
	case "acs-containment-owner":
		client := os.NewFile(3, "owner")
		linuxTestByte(t, client, 'R')
		linuxTestWrite(t, client, 'S')
		linuxTestByte(t, client, 'E')
		if err := os.WriteFile(filepath.Join(os.Getenv("ACS_TEST_ROOT"), "owner-ready"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		for {
			time.Sleep(time.Hour)
		}
	case "acs-containment-init":
		transport := os.NewFile(3, "transport")
		w, env, err := linuxReadTransport(transport)
		_ = transport.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, "contained init: read launch transport:", err)
			os.Exit(125)
		}
		if err := linuxRunContainedInit(w, env, os.NewFile(4, "report"), os.NewFile(5, "control")); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(125)
		}
	case "acs-containment-supervisor":
		root := os.Getenv("ACS_TEST_ROOT")
		f := linuxNewNativeFixture(t, true)
		f.wire.Argv = []string{f.wire.Executable, "-test.run=^TestLinuxContainmentTarget$", "--", "acs-containment-target"}
		if err := os.WriteFile(filepath.Join(root, "base"), []byte(f.base), 0600); err != nil {
			t.Fatal(err)
		}
		lease := linuxTestLease(t, map[string]string{"PROBE_ROOT": f.base, "PROBE_MODE": "detach"})
		status, report, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		control, gate, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		self, err := os.Open("/proc/self/exe")
		if err != nil {
			t.Fatal(err)
		}
		defer self.Close()
		input, err := os.Open("/dev/null")
		if err != nil {
			t.Fatal(err)
		}
		defer input.Close()
		output, err := os.Create(filepath.Join(root, "target-log"))
		if err != nil {
			t.Fatal(err)
		}
		defer output.Close()
		prepared, err := linuxPrepareBwrap(context.Background(), f.plan, f.wire, lease, self, report, control,
			[3]*os.File{input, output, output}, []string{"-test.run=^TestLinuxContainmentHelper$", "--", "acs-containment-init"})
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.close()
		session, err := CreateProtectedSession(filepath.Join(root, "sessions"))
		if err != nil {
			t.Fatal(err)
		}
		challenge := bytes.Repeat([]byte{0x91}, RecoveryProofChallengeSize)
		if PrepareSessionCleanupProof(session.RootDir, challenge) != nil {
			t.Fatal("prepare cleanup challenge")
		}
		cleanup, err := linuxPrepareCleanup(session, challenge, nil)
		if err != nil {
			t.Fatal(err)
		}
		if os.WriteFile(filepath.Join(root, "session-root"), []byte(session.RootDir), 0600) != nil {
			t.Fatal("record Session location")
		}
		owner := os.NewFile(3, "owner")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if os.Getenv("ACS_TEST_SCENARIO") == "cancel" {
			go func() {
				for {
					if _, err := os.Stat(filepath.Join(root, "cancel")); err == nil {
						cancel()
						return
					}
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Millisecond):
					}
				}
			}()
		}
		result, runErr := linuxSuperviseSession(ctx, owner, linuxSupervisedCommand{
			command: prepared.command, status: status, control: gate, childEnds: []*os.File{report, control}, cleanup: cleanup,
		})
		if runErr != nil {
			fmt.Fprintf(os.Stderr, "Session supervisor: result=%+v error=%v\n", result, runErr)
		}
		data, _ := json.Marshal(struct {
			Result linuxSessionResult
			Failed bool
		}{result, runErr != nil})
		if err := os.WriteFile(filepath.Join(root, "result"), data, 0600); err != nil {
			t.Fatal(err)
		}
		if !result.Settled {
			t.Error("native Session settlement unproven")
		}
	}
}

func TestLinuxContainmentTarget(t *testing.T) {
	mode := os.Args[len(os.Args)-1]
	if !strings.HasPrefix(mode, "acs-containment-") {
		return
	}
	base := os.Getenv("PROBE_ROOT")
	if mode == "acs-containment-leaf" {
		path := filepath.Join(base, "output", "leaf-"+strconv.Itoa(os.Getpid()))
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
		for {
			time.Sleep(time.Hour)
		}
	}
	startLeaf := func() *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^TestLinuxContainmentTarget$", "--", "acs-containment-leaf")
		cmd.Env = os.Environ()
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		return cmd
	}
	if mode == "acs-containment-double-fork" {
		_ = startLeaf()
		os.Exit(0)
	}
	// No migration path or host /proc handle may survive the private mount view.
	if os.Getenv("PROBE_MODE") == "detach" {
		if f, err := os.OpenFile("/sys/fs/cgroup/cgroup.procs", os.O_WRONLY, 0); err == nil {
			_ = f.Close()
			t.Fatal("cgroup migration handle reachable")
		}
		for range 3 {
			_ = startLeaf()
		}
		detached := exec.Command(os.Args[0], "-test.run=^TestLinuxContainmentTarget$", "--", "acs-containment-double-fork")
		detached.Env = os.Environ()
		detached.Stdin, detached.Stdout, detached.Stderr = os.Stdin, os.Stdout, os.Stderr
		detached.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		if err := detached.Run(); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(base, "output", "target-ready"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("PROBE_MODE") == "exit" {
		os.Exit(37)
	}
	for {
		time.Sleep(time.Hour)
	}
}

func linuxNativeWaitFile(t *testing.T, path string, diagnostics ...func() string) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, err := os.Stat(path); err == nil {
			return
		}
	}
	for _, diagnostic := range diagnostics {
		t.Log(diagnostic())
	}
	t.Fatalf("missing native marker %s", filepath.Base(path))
}

func linuxNativeStartHelper(t *testing.T, mode string, files []*os.File, env []string) (*linuxNativeProcess, int) {
	t.Helper()
	fd := -1
	cmd := exec.Command("/proc/self/exe", "-test.run=^TestLinuxContainmentHelper$", "--", mode)
	cmd.Env = append([]string{"LANG=C", "LC_ALL=C"}, env...)
	cmd.ExtraFiles = files
	cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &fd}
	process := linuxNativeStartCommand(t, cmd, func() string {
		for _, value := range env {
			if root, ok := strings.CutPrefix(value, "ACS_TEST_ROOT="); ok {
				return linuxNativeReadLogs(filepath.Join(root, "target-log"))
			}
		}
		return ""
	})
	if fd < 0 {
		_ = cmd.Process.Kill()
		_ = process.Wait()
		linuxNativeUnavailable(t, "atomic CLONE_PIDFD")
	}
	t.Cleanup(func() { _ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); _ = process.Wait(); _ = unix.Close(fd) })
	return process, fd
}

func TestLinuxNativePidfdDoesNotSignalUnrelatedProcess(t *testing.T) {
	probe, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		linuxNativeUnavailable(t, "pidfd_open")
	}
	if err := unix.PidfdSendSignal(probe, 0, nil, 0); err != nil {
		_ = unix.Close(probe)
		linuxNativeUnavailable(t, "pidfd_send_signal")
	}
	_ = unix.Close(probe)
	first, fd := linuxNativeStartHelper(t, "acs-containment-idle", nil, nil)
	_, other := linuxNativeStartHelper(t, "acs-containment-idle", nil, nil)
	if err := unix.PidfdSendSignal(fd, unix.SIGTERM, nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := first.Wait(); err == nil {
		t.Fatal("signal did not terminate owned process")
	}
	if dead, err := linuxPidfdDead(fd); err != nil || !dead {
		t.Fatalf("pidfd death: %t %v", dead, err)
	}
	if err := unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); err != unix.ESRCH {
		t.Fatalf("stale pidfd: %v", err)
	}
	if err := unix.PidfdSendSignal(other, 0, nil, 0); err != nil {
		t.Fatal("unrelated process was killed")
	}
}

// Regresses pre-start cgroup.kill followed by CLONE_INTO_CGROUP on Linux 6.17:
// the Session child must survive allocation's kill preflight and reach userland.
func TestLinuxNativeSessionCgroupStartup(t *testing.T) {
	parent, err := linuxprobe.OpenDelegatedCgroup()
	if err != nil {
		linuxNativeUnavailable(t, "owned cgroup delegation")
	}
	g, err := linuxCreateSessionCgroup(parent)
	if err != nil {
		t.Fatal(err)
	}
	removed := false
	t.Cleanup(func() {
		defer g.close()
		if !removed {
			_ = g.terminate()
			if err := g.remove(); err != nil {
				t.Errorf("cleanup regression cgroup: %v", err)
			}
		}
	})
	ready, report := linuxTestSocketpair(t)
	pidfd := -1
	cmd := exec.Command("/proc/self/exe", "-test.run=^TestLinuxContainmentHelper$", "--", "acs-containment-ready")
	cmd.ExtraFiles = []*os.File{report}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(g.directory.Fd()), PidFD: &pidfd}
	process := linuxNativeStartCommand(t, cmd)
	defer func() {
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
	}()
	_ = report.Close()
	linuxTestByte(t, ready, 'R', process.diagnostics)
	if pidfd < 0 || g.contains(cmd.Process.Pid) != nil {
		t.Fatal("ready helper lacks atomic pidfd/cgroup membership")
	}
	if empty, err := g.empty(); err != nil || empty {
		t.Fatalf("live helper missing from cgroup: empty=%t error=%v", empty, err)
	}
	if err := g.terminate(); err != nil {
		t.Fatal(err)
	}
	if err := process.Wait(); err == nil {
		t.Fatal("cgroup.kill did not terminate helper")
	}
	status := cmd.ProcessState.Sys().(syscall.WaitStatus)
	if !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("cgroup.kill exit: %v", status)
	}
	if dead, err := linuxPidfdDead(pidfd); err != nil || !dead {
		t.Fatalf("cgroup.kill pidfd: dead=%t error=%v", dead, err)
	}
	if err := g.remove(); err != nil {
		t.Fatal(err)
	}
	removed = true
}

func TestLinuxNativeContainedInitGateSignalsAndExit(t *testing.T) {
	linuxNativePrerequisites(t)
	for _, mode := range []string{"abort", "exit", "signal"} {
		t.Run(mode, func(t *testing.T) {
			f := linuxNewNativeFixture(t, false)
			f.wire.Argv = []string{f.wire.Executable, "-test.run=^TestLinuxContainmentTarget$", "--", "acs-containment-target"}
			transport, err := linuxWriteTransport(f.wire, linuxTestLease(t, map[string]string{"PROBE_ROOT": f.base, "PROBE_MODE": mode}))
			if err != nil {
				t.Fatal(err)
			}
			defer transport.Close()
			status, report := linuxTestSocketpair(t)
			control, gate := linuxTestSocketpair(t)
			input, err := os.Open("/dev/null")
			if err != nil {
				t.Fatal(err)
			}
			defer input.Close()
			output, err := os.CreateTemp(t.TempDir(), "log")
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			fd := -1
			cmd := exec.Command("/proc/self/exe", "-test.run=^TestLinuxContainmentHelper$", "--", "acs-containment-init")
			cmd.Env = []string{"LANG=C", "LC_ALL=C"}
			cmd.ExtraFiles = []*os.File{transport, report, control}
			cmd.Stdin, cmd.Stdout, cmd.Stderr = input, output, output
			cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &fd}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0); _ = cmd.Wait(); _ = unix.Close(fd) })
			_ = report.Close()
			_ = control.Close()
			linuxTestByte(t, status, 'R')
			if _, err := os.Stat(filepath.Join(f.base, "output", "target-ready")); !os.IsNotExist(err) {
				t.Fatal("target passed closed gate")
			}
			if mode == "abort" {
				_ = gate.Close()
				if cmd.Wait() == nil {
					t.Fatal("gate EOF succeeded")
				}
				if _, err := os.Stat(filepath.Join(f.base, "output", "target-ready")); !os.IsNotExist(err) {
					t.Fatal("abort executed target")
				}
				return
			}
			linuxTestWrite(t, gate, 'S')
			linuxTestByte(t, status, 'E')
			linuxNativeWaitFile(t, filepath.Join(f.base, "output", "target-ready"))
			if mode == "signal" {
				linuxTestWrite(t, gate, byte(unix.SIGTERM))
			}
			var frame [5]byte
			if _, err := io.ReadFull(status, frame[:]); err != nil {
				t.Fatal(err)
			}
			wait := unix.WaitStatus(binary.LittleEndian.Uint32(frame[1:]))
			if frame[0] != 'X' || mode == "exit" && (!wait.Exited() || wait.ExitStatus() != 37) || mode == "signal" && (!wait.Signaled() || wait.Signal() != unix.SIGTERM) {
				t.Fatalf("target status lost: %x", frame)
			}
			if err := cmd.Wait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLinuxNativeMissingDelegationRefusesAllocation(t *testing.T) {
	parent, err := linuxprobe.OpenDelegatedCgroup()
	if err == nil {
		_ = parent.Close()
		// A delegated host exercises allocation and abort in the composition
		// test; there is no unavailable prerequisite on this negative path.
		return
	}
	if g, err := linuxNewSessionCgroup(); g != nil || !errors.Is(err, errLinuxContainment) {
		t.Fatal("missing delegation did not reject Session allocation")
	}
}

func TestLinuxNativeSessionContainment(t *testing.T) {
	linuxNativePrerequisites(t)
	report := linuxprobe.Probe(context.Background())
	if !report.PrerequisitesPassed() {
		var missing []string
		for _, c := range report.Checks {
			if c.Status != "pass" {
				missing = append(missing, c.ID+":"+c.Code)
			}
		}
		linuxNativeUnavailable(t, strings.Join(missing, ", "))
	}
	for _, scenario := range []string{"abort", "signal-and-forks", "owner-loss", "cancel", "supervisor-loss"} {
		t.Run(scenario, func(t *testing.T) { linuxNativeSessionScenario(t, scenario) })
	}
}

func linuxNativeSessionScenario(t *testing.T, scenario string) {
	root := t.TempDir()
	parent, err := linuxprobe.OpenDelegatedCgroup()
	if err != nil {
		t.Fatal("delegation disappeared after prerequisite check")
	}
	t.Cleanup(func() { _ = parent.Close() })
	readGroups := func() map[string]bool {
		names, err := os.ReadDir("/proc/self/fd/" + strconv.Itoa(int(parent.Fd())))
		if err != nil {
			t.Fatal(err)
		}
		result := make(map[string]bool)
		for _, e := range names {
			if strings.HasPrefix(e.Name(), "acs-session-") {
				result[e.Name()] = true
			}
		}
		return result
	}
	before := readGroups()
	server, client := linuxTestSocketpair(t)
	// An unrelated process remains alive across all Session cleanup paths.
	_, unrelated := linuxNativeStartHelper(t, "acs-containment-idle", nil, nil)
	supervisor, supervisorFD := linuxNativeStartHelper(t, "acs-containment-supervisor", []*os.File{server}, []string{"ACS_TEST_ROOT=" + root, "ACS_TEST_SCENARIO=" + scenario})
	_ = server.Close()
	var owner *linuxNativeProcess
	ownerFD := -1
	if scenario == "owner-loss" {
		owner, ownerFD = linuxNativeStartHelper(t, "acs-containment-owner", []*os.File{client}, []string{"ACS_TEST_ROOT=" + root})
		_ = client.Close()
		linuxNativeWaitFile(t, filepath.Join(root, "owner-ready"), supervisor.diagnostics, owner.diagnostics)
	} else {
		linuxTestByte(t, client, 'R', supervisor.diagnostics)
	}
	var group string
	for name := range readGroups() {
		if !before[name] {
			if group != "" {
				t.Fatal("multiple Session groups allocated")
			}
			group = name
		}
	}
	if group == "" {
		t.Fatal("missing per-Session cgroup")
	}
	fd, err := unix.Openat(int(parent.Fd()), group, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		t.Fatal(err)
	}
	groupFile := os.NewFile(uintptr(fd), "native-group")
	t.Cleanup(func() { _ = groupFile.Close() })
	// If an assertion fails, terminate only the pinned test-created group. A
	// successful test must show that the supervisor removed it without help.
	t.Cleanup(func() {
		if _, remains := readGroups()[group]; !remains {
			return
		}
		kill, err := unix.Openat(fd, "cgroup.kill", unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err == nil {
			_, _ = unix.Write(kill, []byte("1"))
			_ = unix.Close(kill)
		}
		for deadline := time.Now().Add(linuxContainmentTimeout); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if unix.Unlinkat(int(parent.Fd()), group, unix.AT_REMOVEDIR) == nil {
				return
			}
		}
		t.Error("test cgroup retained after failed native assertion")
	})
	baseBytes, err := os.ReadFile(filepath.Join(root, "base"))
	if err != nil {
		t.Fatal(err)
	}
	base := string(baseBytes)
	var memberPidfds []int
	if scenario == "abort" {
		if _, err := os.Stat(filepath.Join(base, "output", "target-ready")); !os.IsNotExist(err) {
			t.Fatal("contained target ran before start authorization")
		}
	}
	if scenario != "abort" {
		if owner == nil {
			linuxTestWrite(t, client, 'S')
			linuxTestByte(t, client, 'E', supervisor.diagnostics)
		}
		linuxNativeWaitFile(t, filepath.Join(base, "output", "target-ready"))
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			leaves, _ := filepath.Glob(filepath.Join(base, "output", "leaf-*"))
			if len(leaves) == 4 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("fork/setsid descendants did not start")
			}
		}
		procs, err := os.ReadFile("/proc/self/fd/" + strconv.Itoa(fd) + "/cgroup.procs")
		if err != nil || len(strings.Fields(string(procs))) < 5 {
			t.Fatal("descendants escaped membership")
		}
		selfDepth := len(linuxNativeNamespacePIDs(t, "self"))
		contained := make(map[string]bool)
		for _, pid := range strings.Fields(string(procs)) {
			membership, err := os.ReadFile("/proc/" + pid + "/cgroup")
			if err != nil || !strings.Contains(string(membership), "/"+group+"\n") {
				t.Fatal("inconsistent cgroup membership")
			}
			namespacePIDs := linuxNativeNamespacePIDs(t, pid)
			if len(namespacePIDs) > selfDepth {
				contained[namespacePIDs[len(namespacePIDs)-1]] = true
			}
			pidNumber, err := strconv.Atoi(pid)
			if err != nil {
				t.Fatal(err)
			}
			memberFD, err := unix.PidfdOpen(pidNumber, 0)
			if err != nil {
				t.Fatal("pin contained member:", err)
			}
			memberPidfds = append(memberPidfds, memberFD)
			t.Cleanup(func() { _ = unix.Close(memberFD) })
		}
		leaves, err := filepath.Glob(filepath.Join(base, "output", "leaf-*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, leaf := range leaves {
			if !contained[strings.TrimPrefix(filepath.Base(leaf), "leaf-")] {
				t.Fatal("fork/setsid descendant escaped its Session cgroup")
			}
		}
		targetPID, err := os.ReadFile(filepath.Join(base, "output", "target-ready"))
		if err != nil || !contained[string(targetPID)] {
			t.Fatal("target escaped its Session cgroup")
		}
	}
	switch scenario {
	case "abort":
		_ = client.Close()
	case "signal-and-forks":
		linuxTestWrite(t, client, byte(unix.SIGTERM))
		linuxTestByte(t, client, 'X', supervisor.diagnostics)
	case "owner-loss":
		// The last owner endpoint disappears through actual process death.
		if err := unix.PidfdSendSignal(ownerFD, unix.SIGKILL, nil, 0); err != nil {
			t.Fatal(err)
		}
		_ = owner.Wait()
	case "cancel":
		if err := os.WriteFile(filepath.Join(root, "cancel"), nil, 0600); err != nil {
			t.Fatal(err)
		}
	case "supervisor-loss":
		if err := unix.PidfdSendSignal(supervisorFD, unix.SIGKILL, nil, 0); err != nil {
			t.Fatal(err)
		}
		if err := supervisor.Wait(); err == nil {
			t.Fatal("killed supervisor reported success")
		}
		sessionRoot, err := os.ReadFile(filepath.Join(root, "session-root"))
		if err != nil {
			t.Fatal(err)
		}
		recovered, exists, err := RecoverSession(filepath.Dir(string(sessionRoot)), filepath.Base(string(sessionRoot)))
		if err != nil || !exists {
			t.Fatalf("lost supervisor did not retain Session: %t, %v", exists, err)
		}
		defer recovered.Preserve()
		if proven, err := VerifySessionCleanupProof(recovered.RootDir, bytes.Repeat([]byte{0x91}, RecoveryProofChallengeSize)); err != nil || proven {
			t.Fatalf("lost supervisor forged proof: %t, %v", proven, err)
		}
		if err := unix.PidfdSendSignal(unrelated, 0, nil, 0); err != nil {
			t.Fatal("unrelated process was killed")
		}
		return
	}
	if err := supervisor.Wait(); err != nil {
		t.Fatalf("%v\n%s", err, supervisor.diagnostics())
	}
	data, err := os.ReadFile(filepath.Join(root, "result"))
	if err != nil {
		t.Fatal(err)
	}
	var outcome struct {
		Result linuxSessionResult
		Failed bool
	}
	if json.Unmarshal(data, &outcome) != nil || !outcome.Result.Settled {
		t.Fatalf("settlement failed: %s", data)
	}
	if scenario == "signal-and-forks" {
		if outcome.Failed || !outcome.Result.Exited || !outcome.Result.Status.Signaled() || outcome.Result.Status.Signal() != unix.SIGTERM {
			t.Fatalf("signal result: %s", data)
		}
	} else if !outcome.Failed || outcome.Result.Exited {
		t.Fatalf("owner loss forged target success: %s", data)
	}
	if readGroups()[group] {
		t.Fatal("Session cgroup leaked")
	}
	sessionRoot, err := os.ReadFile(filepath.Join(root, "session-root"))
	if err != nil {
		t.Fatal(err)
	}
	recovered, exists, err := RecoverSession(filepath.Dir(string(sessionRoot)), filepath.Base(string(sessionRoot)))
	if err != nil || !exists {
		t.Fatalf("recover settled Session: exists=%t err=%v", exists, err)
	}
	defer recovered.Preserve()
	if proven, err := VerifySessionCleanupProof(recovered.RootDir, bytes.Repeat([]byte{0x91}, RecoveryProofChallengeSize)); err != nil || !proven {
		t.Fatalf("native settlement proof: proven=%t err=%v", proven, err)
	}
	if err := recovered.Remove(); err != nil {
		t.Fatal(err)
	}
	for _, memberFD := range memberPidfds {
		if dead, err := linuxPidfdDead(memberFD); err != nil || !dead {
			t.Fatal("observed Session member survived cleanup")
		}
	}
	if err := unix.PidfdSendSignal(unrelated, 0, nil, 0); err != nil {
		t.Fatal("unrelated process was killed")
	}
}

func linuxNativeNamespacePIDs(t *testing.T, pid string) []string {
	t.Helper()
	data, err := os.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "NSpid:") {
			return strings.Fields(line)[1:]
		}
	}
	t.Fatal("missing PID namespace membership")
	return nil
}
