//go:build darwin

package launch

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	seatbeltHelperArgument            = "--acs-internal-seatbelt-supervisor-v1"
	seatbeltHelperEnvironment         = "ACS_INTERNAL_SEATBELT_SUPERVISOR_FD"
	seatbeltStatusProxyArgument       = "--acs-internal-seatbelt-status-proxy-v1"
	seatbeltStatusProxyEnvironmentKey = "ACS_INTERNAL_SEATBELT_STATUS_PROXY_FD"
	seatbeltStatusProxyControlFD      = 4
	seatbeltProofMagic                = "ACS-SEATBELT-CLEANUP"
	seatbeltProofVersion              = 1
	seatbeltChallengeSize             = 32
	seatbeltCleanupDeadline           = 2 * time.Second
	seatbeltDescriptorSealAttempts    = 8
	seatbeltStatusPacketSize          = 2
	seatbeltStatusExit                = 'E'
	seatbeltStatusSignal              = 'S'
)

type seatbeltCleanupProof struct {
	Magic           string `json:"magic"`
	Version         int    `json:"version"`
	Challenge       string `json:"challenge"`
	ZeroLiveTargets bool   `json:"zero_live_targets"`
	NoTargetStarted bool   `json:"no_target_started,omitempty"`
	TargetExited    bool   `json:"target_exited"`
	TargetExitCode  int    `json:"target_exit_code,omitempty"`
	TargetSignal    int    `json:"target_signal,omitempty"`
}

func init() {
	if len(os.Args) >= 4 && os.Args[1] == seatbeltStatusProxyArgument && os.Args[2] == "--" {
		statusFD, err := strconv.Atoi(os.Getenv(seatbeltStatusProxyEnvironmentKey))
		if err != nil || statusFD != 3 {
			os.Exit(125)
		}
		os.Exit(runSeatbeltStatusProxy(statusFD, seatbeltStatusProxyControlFD, os.Args[3], os.Args[4:]))
	}
	if len(os.Args) < 4 || os.Args[1] != seatbeltHelperArgument || os.Args[2] != "--" {
		return
	}
	fd, err := strconv.Atoi(os.Getenv(seatbeltHelperEnvironment))
	if err != nil || fd < 3 {
		os.Exit(125)
	}
	os.Exit(runSeatbeltSupervisor(fd, os.Args[3], os.Args[4:]))
}

// runSeatbeltStatusProxy is the direct child of ACS. sandbox-exec does not
// consistently preserve a signaled descendant's wait status on macOS 26, so
// the parent approves an authenticated target result only after the contained
// supervisor has proved cleanup. The proxy then exits with that exact result.
func runSeatbeltStatusProxy(statusFD, controlFD int, executable string, arguments []string) int {
	if executable == "" || statusFD < 3 || controlFD < 3 || statusFD == controlFD {
		return 125
	}
	unix.CloseOnExec(statusFD)
	unix.CloseOnExec(controlFD)
	status := os.NewFile(uintptr(statusFD), "acs-seatbelt-status-control")
	control := os.NewFile(uintptr(controlFD), "acs-seatbelt-helper-control")
	if status == nil || control == nil {
		if status != nil {
			_ = status.Close()
		}
		if control != nil {
			_ = control.Close()
		}
		return 125
	}
	defer status.Close()
	defer control.Close()

	command := exec.Command(executable, arguments...)
	command.Env = seatbeltSupervisorEnvironment(os.Environ())
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.ExtraFiles = []*os.File{control}
	if err := command.Start(); err != nil {
		return 125
	}
	_ = control.Close()
	_ = command.Wait()

	packet := make([]byte, seatbeltStatusPacketSize)
	if _, err := io.ReadFull(status, packet); err != nil {
		return 125
	}
	return seatbeltStatusProxyExit(packet)
}

func seatbeltStatusProxyExit(packet []byte) int {
	if len(packet) != seatbeltStatusPacketSize {
		return 125
	}
	switch packet[0] {
	case seatbeltStatusExit:
		return int(packet[1])
	case seatbeltStatusSignal:
		if packet[1] == 0 || packet[1] > 127 {
			return 125
		}
		deathSignal := syscall.Signal(packet[1])
		signal.Reset(deathSignal)
		_ = syscall.Kill(os.Getpid(), deathSignal)
		return 128 + int(packet[1])
	default:
		return 125
	}
}

func runSeatbeltSupervisor(controlFD int, target string, arguments []string) int {
	return runSeatbeltSupervisorWithDescriptorSealer(controlFD, target, arguments, sealSeatbeltTargetDescriptors)
}

// runSeatbeltSupervisorWithDescriptorSealer keeps the no-target proof path
// testable without mutable process-wide hooks.
func runSeatbeltSupervisorWithDescriptorSealer(controlFD int, target string, arguments []string, seal func(seatbeltDescriptorEnumerator) error) int {
	unix.CloseOnExec(controlFD)
	control := os.NewFile(uintptr(controlFD), "acs-seatbelt-control")
	if control == nil {
		return 125
	}
	defer control.Close()
	challenge := make([]byte, seatbeltChallengeSize)
	if _, err := io.ReadFull(control, challenge); err != nil {
		return 125
	}
	api, err := loadSeatbeltProcAPI()
	if err != nil {
		return seatbeltNoTargetFailure(control, challenge)
	}
	if err := seal(api); err != nil {
		return seatbeltNoTargetFailure(control, challenge)
	}

	command := exec.Command(target, arguments...)
	command.Env = seatbeltTargetEnvironment(os.Environ())
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.ExtraFiles = nil
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	terminalFD, foregroundGroup := seatbeltHelperTerminal()
	if terminalFD >= 0 {
		command.SysProcAttr.Foreground = true
		command.SysProcAttr.Ctty = terminalFD
	}
	if err := command.Start(); err != nil {
		return seatbeltNoTargetFailure(control, challenge)
	}
	targetPID := command.Process.Pid
	targetGroup := targetPID
	identities := newSeatbeltIdentityLedger()
	if info, err := api.info(targetPID); err == nil {
		identities.record(targetPID, info)
	}
	stopObserver := make(chan struct{})
	observerDone := make(chan struct{})
	go observeSeatbeltTargets(api, os.Getpid(), identities, stopObserver, observerDone)

	controlClosed := make(chan struct{})
	go forwardSeatbeltControl(control, targetGroup, controlClosed)

	waitErr := command.Wait()
	close(stopObserver)
	<-observerDone
	if terminalFD >= 0 {
		_ = setSeatbeltForegroundProcessGroup(os.Stdin, foregroundGroup)
	}
	if err := identities.failure(); err != nil {
		return 125
	}
	if err := settleSeatbeltInstance(api, identities, os.Getpid(), targetPID, time.Now().Add(seatbeltCleanupDeadline)); err != nil {
		return 125
	}

	proof := seatbeltCleanupProof{
		Magic: seatbeltProofMagic, Version: seatbeltProofVersion,
		Challenge: hex.EncodeToString(challenge), ZeroLiveTargets: true,
	}
	if waitErr == nil {
		proof.TargetExited = true
	} else if exitError, ok := waitErr.(*exec.ExitError); ok {
		if status, ok := exitError.Sys().(syscall.WaitStatus); ok {
			if status.Exited() {
				proof.TargetExited = true
				proof.TargetExitCode = status.ExitStatus()
			} else if status.Signaled() {
				proof.TargetSignal = int(status.Signal())
			}
		}
	}
	if err := json.NewEncoder(control).Encode(proof); err != nil {
		return 125
	}
	_ = control.Close()
	select {
	case <-controlClosed:
	default:
	}
	if proof.TargetSignal != 0 {
		deathSignal := syscall.Signal(proof.TargetSignal)
		signal.Reset(deathSignal)
		_ = syscall.Kill(os.Getpid(), deathSignal)
		return 128 + proof.TargetSignal
	}
	if proof.TargetExited {
		return proof.TargetExitCode
	}
	return 125
}

func seatbeltNoTargetFailure(control *os.File, challenge []byte) int {
	proof := seatbeltCleanupProof{
		Magic: seatbeltProofMagic, Version: seatbeltProofVersion,
		Challenge: hex.EncodeToString(challenge), ZeroLiveTargets: true, NoTargetStarted: true,
	}
	if err := json.NewEncoder(control).Encode(proof); err != nil {
		return 125
	}
	return 125
}

type seatbeltDescriptorEnumerator interface {
	descriptors(int) ([]int, error)
}

func sealSeatbeltTargetDescriptors(api seatbeltDescriptorEnumerator) error {
	for attempt := 0; attempt < seatbeltDescriptorSealAttempts; attempt++ {
		expected, err := seatbeltDescriptorSnapshot(api)
		if err != nil {
			return err
		}
		unstable, err := sealSeatbeltDescriptorSnapshot(expected)
		if err != nil {
			return err
		}
		if unstable {
			continue
		}

		observed, err := seatbeltDescriptorSnapshot(api)
		if err != nil {
			return err
		}
		if !slices.Equal(expected, observed) {
			continue
		}
		unstable, err = verifySeatbeltDescriptorSnapshot(observed)
		if err != nil {
			return err
		}
		if unstable {
			continue
		}

		verified, err := seatbeltDescriptorSnapshot(api)
		if err != nil {
			return err
		}
		if !slices.Equal(observed, verified) {
			continue
		}
		unstable, err = verifySeatbeltDescriptorSnapshot(verified)
		if err != nil {
			return err
		}
		if !unstable {
			return nil
		}
	}
	return errors.New("seal supervisor descriptors did not converge")
}

func seatbeltDescriptorSnapshot(api seatbeltDescriptorEnumerator) ([]int, error) {
	descriptors, err := api.descriptors(os.Getpid())
	if err != nil {
		return nil, errors.New("enumerate supervisor descriptors")
	}
	sort.Ints(descriptors)
	snapshot := descriptors[:0]
	for _, fd := range descriptors {
		if fd < 0 {
			return nil, errors.New("enumerate supervisor descriptors")
		}
		if len(snapshot) == 0 || snapshot[len(snapshot)-1] != fd {
			snapshot = append(snapshot, fd)
		}
	}
	return snapshot, nil
}

func sealSeatbeltDescriptorSnapshot(descriptors []int) (bool, error) {
	for _, fd := range descriptors {
		if fd <= 2 {
			continue
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if errors.Is(err, syscall.EBADF) {
			return true, nil
		}
		if err != nil {
			return false, errors.New("inspect supervisor descriptors")
		}
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil {
			if errors.Is(err, syscall.EBADF) {
				return true, nil
			}
			return false, errors.New("seal supervisor descriptors")
		}
	}
	return false, nil
}

func verifySeatbeltDescriptorSnapshot(descriptors []int) (bool, error) {
	for _, fd := range descriptors {
		if fd <= 2 {
			continue
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if errors.Is(err, syscall.EBADF) {
			return true, nil
		}
		if err != nil {
			return false, errors.New("inspect supervisor descriptors")
		}
		if flags&unix.FD_CLOEXEC == 0 {
			return true, nil
		}
	}
	return false, nil
}

func seatbeltTargetEnvironment(environment []string) []string {
	return seatbeltEnvironmentWithoutReservedDescriptors(environment)
}

func seatbeltStatusProxyEnvironment(environment []string) []string {
	clean := seatbeltEnvironmentWithoutReservedDescriptors(environment)
	return append(clean, seatbeltStatusProxyEnvironmentKey+"=3")
}

func seatbeltSupervisorEnvironment(environment []string) []string {
	clean := seatbeltEnvironmentWithoutReservedDescriptors(environment)
	return append(clean, seatbeltHelperEnvironment+"=3")
}

func seatbeltEnvironmentWithoutReservedDescriptors(environment []string) []string {
	clean := make([]string, 0, len(environment))
	for _, value := range environment {
		if !strings.HasPrefix(value, seatbeltHelperEnvironment+"=") &&
			!strings.HasPrefix(value, seatbeltStatusProxyEnvironmentKey+"=") {
			clean = append(clean, value)
		}
	}
	return clean
}

func seatbeltTargetStatus(data []byte) ([]byte, error) {
	var proof seatbeltCleanupProof
	if err := json.Unmarshal(data, &proof); err != nil {
		return nil, errors.New("decode Seatbelt target status proof")
	}
	if proof.NoTargetStarted {
		return []byte{seatbeltStatusExit, 125}, nil
	}
	if proof.TargetExited {
		return []byte{seatbeltStatusExit, byte(proof.TargetExitCode)}, nil
	}
	if proof.TargetSignal != 0 {
		return []byte{seatbeltStatusSignal, byte(proof.TargetSignal)}, nil
	}
	return nil, errors.New("Seatbelt target status is unavailable")
}

func seatbeltHelperTerminal() (int, int) {
	fd := int(os.Stdin.Fd())
	foreground, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil {
		return -1, 0
	}
	return fd, foreground
}

func forwardSeatbeltControl(control *os.File, targetGroup int, done chan<- struct{}) {
	defer close(done)
	packet := make([]byte, 2)
	for {
		if _, err := io.ReadFull(control, packet); err != nil {
			_ = syscall.Kill(-targetGroup, syscall.SIGKILL)
			return
		}
		if packet[0] != 'S' || packet[1] == 0 {
			_ = syscall.Kill(-targetGroup, syscall.SIGKILL)
			return
		}
		_ = syscall.Kill(-targetGroup, syscall.Signal(packet[1]))
	}
}

type seatbeltProcessEnumerator interface {
	allPIDs() ([]int, error)
	info(int) (seatbeltBSDInfo, error)
}

// errSeatbeltProcessSnapshotUnstable marks a single process-table entry that
// changed while proc_pidinfo was reading it. A transient entry cannot prove
// cleanup, but it must not permanently poison the observer: the settling pass
// rechecks it until it is either stable or the fixed cleanup deadline expires.
var errSeatbeltProcessSnapshotUnstable = errors.New("Seatbelt process snapshot is unstable")

type seatbeltIdentity struct {
	second      uint64
	microsecond uint64
}

type seatbeltIdentityLedger struct {
	sync.Mutex
	identities map[int]seatbeltIdentity
	err        error
}

func newSeatbeltIdentityLedger() *seatbeltIdentityLedger {
	return &seatbeltIdentityLedger{identities: make(map[int]seatbeltIdentity)}
}

func (ledger *seatbeltIdentityLedger) record(pid int, info seatbeltBSDInfo) {
	ledger.Lock()
	ledger.identities[pid] = seatbeltIdentity{second: info.StartSecond, microsecond: info.StartMicrosecond}
	ledger.Unlock()
}

func (ledger *seatbeltIdentityLedger) contains(pid int, info seatbeltBSDInfo) bool {
	if ledger == nil {
		return false
	}
	ledger.Lock()
	defer ledger.Unlock()
	identity, ok := ledger.identities[pid]
	return ok && identity.second == info.StartSecond && identity.microsecond == info.StartMicrosecond
}

func (ledger *seatbeltIdentityLedger) containsPID(pid int) bool {
	if ledger == nil {
		return false
	}
	ledger.Lock()
	defer ledger.Unlock()
	_, ok := ledger.identities[pid]
	return ok
}

func (ledger *seatbeltIdentityLedger) fail(err error) {
	ledger.Lock()
	if ledger.err == nil {
		ledger.err = err
	}
	ledger.Unlock()
}

func (ledger *seatbeltIdentityLedger) failure() error {
	ledger.Lock()
	defer ledger.Unlock()
	return ledger.err
}

func observeSeatbeltTargets(api seatbeltProcessEnumerator, self int, ledger *seatbeltIdentityLedger, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := recordSeatbeltTargets(api, self, ledger); err != nil && !errors.Is(err, errSeatbeltProcessSnapshotUnstable) {
			ledger.fail(err)
			return
		}
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
	}
}

func recordSeatbeltTargets(api seatbeltProcessEnumerator, self int, ledger *seatbeltIdentityLedger) error {
	pids, err := api.allPIDs()
	if err != nil {
		return err
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	for _, pid := range pids {
		if pid <= 0 || pid == self {
			continue
		}
		info, err := api.info(pid)
		if err != nil {
			if errors.Is(err, syscall.ESRCH) || errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
				continue
			}
			if errors.Is(syscall.Kill(pid, 0), syscall.EPERM) && ledger.containsPID(pid) {
				return errors.New("tracked target enumeration is ambiguous")
			}
			return errSeatbeltProcessSnapshotUnstable
		}
		if info.Status == seatbeltProcStatusZombie {
			continue
		}
		if !seatbeltProcessSnapshotMatchesPID(pid, info) {
			return errSeatbeltProcessSnapshotUnstable
		}
		probeErr := syscall.Kill(pid, 0)
		if probeErr == nil {
			if !seatbeltCredentialsMatch(info, uid, gid) {
				return errors.New("same-sandbox target changed credentials")
			}
			ledger.record(pid, info)
			continue
		}
		if errors.Is(probeErr, syscall.EPERM) && ledger.contains(pid, info) {
			return errors.New("tracked target credential identity is ambiguous")
		}
	}
	return nil
}

func settleSeatbeltInstance(api seatbeltProcessEnumerator, ledger *seatbeltIdentityLedger, self, leader int, deadline time.Time) error {
	stable := 0
	for stable < 2 {
		if time.Now().After(deadline) {
			return errors.New("Seatbelt quiescence did not converge")
		}
		changed, err := stopSeatbeltPass(api, ledger, self, leader)
		if errors.Is(err, errSeatbeltProcessSnapshotUnstable) {
			// A changing snapshot is not a zero-target observation. Force the
			// existing bounded settling cadence to obtain a fresh snapshot.
			changed = 1
		} else if err != nil {
			return err
		}
		if changed == 0 {
			stable++
		} else {
			stable = 0
		}
		time.Sleep(seatbeltSettlementRetryDelay)
	}
	for {
		if time.Now().After(deadline) {
			return errors.New("Seatbelt termination did not converge")
		}
		live, err := killSeatbeltPass(api, ledger, self, leader)
		if errors.Is(err, errSeatbeltProcessSnapshotUnstable) {
			// Do not declare cleanup complete until a later pass has a stable
			// process-table view.
			live = 1
		} else if err != nil {
			return err
		}
		if live == 0 {
			return nil
		}
		time.Sleep(seatbeltSettlementRetryDelay)
	}
}

func stopSeatbeltPass(api seatbeltProcessEnumerator, ledger *seatbeltIdentityLedger, self, leader int) (int, error) {
	changed := 0
	err := visitLiveSeatbeltTargets(api, ledger, self, leader, func(pid int, info seatbeltBSDInfo) error {
		if info.Status == seatbeltProcStatusStop {
			return nil
		}
		matched, err := sameSeatbeltProcessIdentity(api, pid, info)
		if err != nil || !matched {
			return err
		}
		if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return nil
			}
			return errors.New("stop same-sandbox target: authorization failed")
		}
		changed++
		return nil
	})
	return changed, err
}

func killSeatbeltPass(api seatbeltProcessEnumerator, ledger *seatbeltIdentityLedger, self, leader int) (int, error) {
	live := 0
	err := visitLiveSeatbeltTargets(api, ledger, self, leader, func(pid int, info seatbeltBSDInfo) error {
		live++
		matched, err := sameSeatbeltProcessIdentity(api, pid, info)
		if err != nil || !matched {
			return err
		}
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			return errors.New("kill same-sandbox target: authorization failed")
		}
		return nil
	})
	return live, err
}

func visitLiveSeatbeltTargets(api seatbeltProcessEnumerator, ledger *seatbeltIdentityLedger, self, leader int, visit func(int, seatbeltBSDInfo) error) error {
	pids, err := api.allPIDs()
	if err != nil {
		return err
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	for _, pid := range pids {
		if pid <= 0 || pid == self {
			continue
		}
		info, infoErr := api.info(pid)
		if infoErr != nil {
			if errors.Is(infoErr, syscall.ESRCH) {
				continue
			}
			probeErr := syscall.Kill(pid, 0)
			if errors.Is(probeErr, syscall.ESRCH) {
				continue
			}
			if errors.Is(probeErr, syscall.EPERM) {
				if pid == leader || ledger.containsPID(pid) {
					return errors.New("target credential identity is ambiguous")
				}
				continue
			}
			return errSeatbeltProcessSnapshotUnstable
		}
		if info.Status == seatbeltProcStatusZombie {
			continue
		}
		if !seatbeltProcessSnapshotMatchesPID(pid, info) {
			return errSeatbeltProcessSnapshotUnstable
		}
		if err := syscall.Kill(pid, 0); err != nil {
			if errors.Is(err, syscall.EPERM) && (pid == leader || ledger.contains(pid, info)) {
				return errors.New("target credential identity is ambiguous")
			}
			continue
		}
		if !seatbeltCredentialsMatch(info, uid, gid) {
			return errors.New("same-sandbox target changed credentials")
		}
		ledger.record(pid, info)
		if err := visit(pid, info); err != nil {
			return err
		}
	}
	return nil
}

func seatbeltProcessSnapshotMatchesPID(pid int, info seatbeltBSDInfo) bool {
	// SIDL is a kernel transition state. proc_pidinfo may retain the PID while
	// credentials have already been cleared on the path to a zombie; it cannot
	// authorize a target operation or prove that the target is gone.
	return info.PID == uint32(pid) && info.Status != 0 && info.Status != seatbeltProcStatusIdle
}

func seatbeltCredentialsMatch(info seatbeltBSDInfo, uid, gid uint32) bool {
	return info.UID == uid && info.RUID == uid && info.SVUID == uid && info.GID == gid && info.RGID == gid && info.SVGID == gid
}

func sameSeatbeltProcessIdentity(api seatbeltProcessEnumerator, pid int, before seatbeltBSDInfo) (bool, error) {
	after, err := api.info(pid)
	if err != nil {
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			return false, nil
		}
		return false, errors.New("revalidate process identity: enumeration failed")
	}
	return before.StartSecond == after.StartSecond && before.StartMicrosecond == after.StartMicrosecond, nil
}

func validateSeatbeltCleanupProof(data, challenge []byte) error {
	var proof seatbeltCleanupProof
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return errors.New("invalid Seatbelt cleanup proof")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("invalid Seatbelt cleanup proof framing")
	}
	gotChallenge, err := hex.DecodeString(proof.Challenge)
	if err != nil || len(gotChallenge) != len(challenge) || subtle.ConstantTimeCompare(gotChallenge, challenge) != 1 {
		return errors.New("unauthenticated Seatbelt cleanup proof")
	}
	if proof.Magic != seatbeltProofMagic || proof.Version != seatbeltProofVersion || !proof.ZeroLiveTargets {
		return errors.New("negative Seatbelt cleanup proof")
	}
	if proof.NoTargetStarted {
		if proof.TargetExited || proof.TargetExitCode != 0 || proof.TargetSignal != 0 {
			return errors.New("invalid Seatbelt no-target proof")
		}
		return nil
	}
	if proof.TargetExited == (proof.TargetSignal != 0) || proof.TargetExitCode < 0 || proof.TargetExitCode > 255 || proof.TargetSignal < 0 || proof.TargetSignal > 127 {
		return errors.New("invalid Seatbelt target status proof")
	}
	return nil
}
