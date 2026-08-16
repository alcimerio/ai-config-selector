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
	seatbeltHelperArgument         = "--acs-internal-seatbelt-supervisor-v1"
	seatbeltHelperEnvironment      = "ACS_INTERNAL_SEATBELT_SUPERVISOR_FD"
	seatbeltProofMagic             = "ACS-SEATBELT-CLEANUP"
	seatbeltProofVersion           = 1
	seatbeltChallengeSize          = 32
	seatbeltCleanupDeadline        = 2 * time.Second
	seatbeltDescriptorSealAttempts = 8
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
	if len(os.Args) < 4 || os.Args[1] != seatbeltHelperArgument || os.Args[2] != "--" {
		return
	}
	fd, err := strconv.Atoi(os.Getenv(seatbeltHelperEnvironment))
	if err != nil || fd < 3 {
		os.Exit(125)
	}
	os.Exit(runSeatbeltSupervisor(fd, os.Args[3], os.Args[4:]))
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
	clean := make([]string, 0, len(environment))
	prefix := seatbeltHelperEnvironment + "="
	for _, value := range environment {
		if !strings.HasPrefix(value, prefix) {
			clean = append(clean, value)
		}
	}
	return clean
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
		if err := recordSeatbeltTargets(api, self, ledger); err != nil {
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
			if !errors.Is(err, syscall.ESRCH) && ledger.containsPID(pid) {
				return errors.New("tracked target enumeration is ambiguous")
			}
			continue
		}
		if info.Status == seatbeltProcStatusZombie {
			continue
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
		if err != nil {
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
		if err != nil {
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
			if errors.Is(probeErr, syscall.ESRCH) || errors.Is(probeErr, syscall.EPERM) {
				if (pid == leader || ledger.containsPID(pid)) && !errors.Is(probeErr, syscall.ESRCH) {
					return errors.New("target credential identity is ambiguous")
				}
				continue
			}
			return errors.New("inspect live process: enumeration failed")
		}
		if info.Status == seatbeltProcStatusZombie {
			continue
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
