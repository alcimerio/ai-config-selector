//go:build darwin

package launch

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/ebitengine/purego"
)

// Each launch grants lookup of one fresh, unregistered Mach service name.
// Querying that rule identifies the inherited policy even after reparenting or
// setsid. The denied control name distinguishes it from an unsandboxed process.
// Neither name is registered with bootstrap or passed to the target environment.
type seatbeltSessionProcesses struct {
	seatbeltProcessEnumerator
	member func(int) (bool, error)
	ledger *seatbeltIdentityLedger
}

func newSeatbeltSessionProcesses() (*seatbeltSessionProcesses, string, error) {
	api, err := loadSeatbeltProcAPI()
	if err != nil {
		return nil, "", err
	}
	check, filter, err := loadSeatbeltSessionAPI()
	if err != nil {
		return nil, "", err
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, "", err
	}
	name := "com.alcimerio.acs.session." + hex.EncodeToString(nonce[:])
	operation := append([]byte("mach-lookup"), 0)
	allowed := append([]byte(name), 0)
	denied := append([]byte(name+".control"), 0)
	query := func(pid int, value []byte) (bool, error) {
		return checkSeatbeltSessionPolicy(api, check, pid, operation, filter, value)
	}
	processes := &seatbeltSessionProcesses{seatbeltProcessEnumerator: api, ledger: newSeatbeltIdentityLedger()}
	processes.member = func(pid int) (bool, error) {
		matches, err := query(pid, allowed)
		if err != nil || !matches {
			return false, err
		}
		control, err := query(pid, denied)
		return !control && err == nil, err
	}
	return processes, fmt.Sprintf("\n(allow mach-lookup (global-name %q))\n", name), nil
}

func checkSeatbeltSessionPolicy(api seatbeltProcAPI, check uintptr, pid int, operation []byte, filter uintptr, value []byte) (bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	errno := (*int32)(api.errno())
	*errno = 0
	var result uintptr
	if runtime.GOARCH == "arm64" {
		// sandbox_check(pid_t, const char *, enum sandbox_filter_type, ...)
		// takes the service name as a C variadic argument. Apple's ARM64 ABI
		// puts variadic arguments on the stack, even with free registers.
		// Purego's SyscallN (and RegisterFunc's ...any) uses fixed arguments:
		// fill x3-x7 so the ninth argument lands in the first stack slot.
		// https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms
		result, _, _ = purego.SyscallN(check, uintptr(pid), uintptr(unsafe.Pointer(&operation[0])), filter,
			0, 0, 0, 0, 0, uintptr(unsafe.Pointer(&value[0])))
	} else {
		result, _, _ = purego.SyscallN(check, uintptr(pid), uintptr(unsafe.Pointer(&operation[0])), filter, uintptr(unsafe.Pointer(&value[0])))
	}
	// Read thread-local errno before any other foreign call can replace it.
	queryErrno := syscall.Errno(*errno)
	runtime.KeepAlive(operation)
	runtime.KeepAlive(value)
	switch int32(result) {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		if queryErrno != 0 {
			return false, fmt.Errorf("inspect Seatbelt Session policy: %w", queryErrno)
		}
		return false, fmt.Errorf("inspect Seatbelt Session policy: unexpected result %d without errno", int32(result))
	}
}

func (processes *seatbeltSessionProcesses) allPIDs() ([]int, error) {
	pids, err := processes.seatbeltProcessEnumerator.allPIDs()
	if err != nil {
		return nil, err
	}
	members := make([]int, 0)
	var snapshotErr error
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		matched, err := processes.member(pid)
		if errors.Is(err, syscall.ESRCH) {
			continue
		}
		if err != nil {
			snapshotErr = errors.Join(snapshotErr, err)
			continue
		}
		if matched {
			// Record membership even before BSD info is available, so an
			// inaccessible member cannot be mistaken for a host process.
			if processes.ledger != nil && !processes.ledger.containsPID(pid) {
				processes.ledger.record(pid, seatbeltBSDInfo{})
			}
			members = append(members, pid)
		}
	}
	// Settle every identified member first, but never report an empty Session
	// while any policy query is inconclusive.
	if len(members) > 0 {
		return members, nil
	}
	return members, snapshotErr
}

func (processes *seatbeltSessionProcesses) info(pid int) (seatbeltBSDInfo, error) {
	before, err := processes.seatbeltProcessEnumerator.info(pid)
	if err != nil {
		return seatbeltBSDInfo{}, err
	}
	matched, err := processes.member(pid)
	if err != nil {
		return seatbeltBSDInfo{}, err
	}
	if !matched {
		return seatbeltBSDInfo{}, errSeatbeltProcessSnapshotUnstable
	}
	after, err := processes.seatbeltProcessEnumerator.info(pid)
	if err != nil {
		return seatbeltBSDInfo{}, err
	}
	if before.PID != after.PID || before.StartSecond != after.StartSecond || before.StartMicrosecond != after.StartMicrosecond {
		return seatbeltBSDInfo{}, errSeatbeltProcessSnapshotUnstable
	}
	if processes.ledger != nil {
		processes.ledger.record(pid, after)
	}
	return after, nil
}

func (process *seatbeltProcess) verifySessionIdentity() error {
	if process.sessionProcesses == nil {
		return nil
	}
	pids, err := process.sessionProcesses.allPIDs()
	if err != nil {
		return err
	}
	for _, pid := range pids {
		info, err := process.sessionProcesses.info(pid)
		if err != nil {
			return err
		}
		if info.PPID == uint32(process.command.Process.Pid) && seatbeltProcessSnapshotMatchesPID(pid, info) &&
			seatbeltCredentialsMatch(info, uint32(os.Geteuid()), uint32(os.Getegid())) {
			process.sessionIdentityVerified = true
			return nil
		}
	}
	return errors.New("Seatbelt Session policy identity is unavailable")
}

func (process *seatbeltProcess) settleSession() error {
	if process.sessionProcesses == nil || !process.sessionIdentityVerified {
		return errors.New("Seatbelt Session policy identity was not verified")
	}
	if process.sessionProcesses.ledger == nil {
		process.sessionProcesses.ledger = newSeatbeltIdentityLedger()
	}
	var proofErr error
	if process.recoveryRoot != "" {
		proofErr = clearSessionCleanupProof(process.recoveryRoot)
	}
	cleanupErr := settleSeatbeltInstance(process.sessionProcesses, process.sessionProcesses.ledger, os.Getpid(), 0, time.Now().Add(seatbeltCleanupDeadline))
	if err := errors.Join(proofErr, cleanupErr); err != nil {
		return err
	}
	if process.recoveryRoot != "" {
		return recordSessionCleanupProof(process.recoveryRoot, process.challenge)
	}
	return nil
}

var (
	loadSeatbeltSessionOnce sync.Once
	seatbeltSessionCheck    uintptr
	seatbeltSessionFilter   uintptr
	loadSeatbeltSessionErr  error
)

func loadSeatbeltSessionAPI() (uintptr, uintptr, error) {
	loadSeatbeltSessionOnce.Do(func() {
		library, err := purego.Dlopen("/usr/lib/libsandbox.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			loadSeatbeltSessionErr = err
			return
		}
		seatbeltSessionCheck, err = purego.Dlsym(library, "sandbox_check")
		if err != nil {
			loadSeatbeltSessionErr = err
			return
		}
		noReport, err := purego.Dlsym(library, "SANDBOX_CHECK_NO_REPORT")
		if err != nil {
			loadSeatbeltSessionErr = err
			return
		}
		copyMemory, err := purego.Dlsym(library, "memcpy")
		if err != nil {
			loadSeatbeltSessionErr = err
			return
		}
		var flag uint32
		purego.SyscallN(copyMemory, uintptr(unsafe.Pointer(&flag)), noReport, unsafe.Sizeof(flag))
		// SANDBOX_FILTER_GLOBAL_NAME is 2 in <sandbox/private.h>.
		seatbeltSessionFilter = uintptr(2 | flag)
	})
	if loadSeatbeltSessionErr != nil {
		return 0, 0, loadSeatbeltSessionErr
	}
	if seatbeltSessionCheck == 0 || seatbeltSessionFilter == 0 {
		return 0, 0, errors.New("Seatbelt Session policy API is unavailable")
	}
	return seatbeltSessionCheck, seatbeltSessionFilter, loadSeatbeltSessionErr
}
