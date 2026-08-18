//go:build darwin

package launch

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/ebitengine/purego"
)

const (
	seatbeltProcPIDListFDs   = 1
	seatbeltProcPIDTBSDInfo  = 3
	seatbeltProcStatusIdle   = 1
	seatbeltProcStatusStop   = 4
	seatbeltProcStatusZombie = 5
)

// seatbeltBSDInfo mirrors the public proc_bsdinfo structure from
// <sys/proc_info.h>. Keep the reserved and name fields: proc_pidinfo requires
// the exact public ABI size.
type seatbeltBSDInfo struct {
	Flags            uint32
	Status           uint32
	XStatus          uint32
	PID              uint32
	PPID             uint32
	UID              uint32
	GID              uint32
	RUID             uint32
	RGID             uint32
	SVUID            uint32
	SVGID            uint32
	Reserved         uint32
	Command          [16]byte
	Name             [32]byte
	NFiles           uint32
	ProcessGroup     uint32
	JobControl       uint32
	Terminal         uint32
	TerminalGroup    uint32
	Nice             int32
	StartSecond      uint64
	StartMicrosecond uint64
}

type seatbeltFDInfo struct {
	Descriptor int32
	Type       uint32
}

type seatbeltProcAPI struct {
	listAll uintptr
	pidInfo uintptr
	errno   func() unsafe.Pointer
}

var (
	loadSeatbeltProcOnce sync.Once
	loadedSeatbeltProc   seatbeltProcAPI
	loadSeatbeltProcErr  error
)

func loadSeatbeltProcAPI() (seatbeltProcAPI, error) {
	if unsafe.Sizeof(seatbeltBSDInfo{}) != 136 {
		return seatbeltProcAPI{}, errors.New("public process ABI has an unexpected layout")
	}
	loadSeatbeltProcOnce.Do(func() {
		library, err := purego.Dlopen("/usr/lib/libSystem.B.dylib", purego.RTLD_NOW|purego.RTLD_LOCAL)
		if err != nil {
			loadSeatbeltProcErr = err
			return
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				loadSeatbeltProcErr = fmt.Errorf("load public process API: %v", recovered)
			}
		}()
		loadedSeatbeltProc.listAll, err = purego.Dlsym(library, "proc_listallpids")
		if err != nil {
			loadSeatbeltProcErr = err
			return
		}
		loadedSeatbeltProc.pidInfo, err = purego.Dlsym(library, "proc_pidinfo")
		if err != nil {
			loadSeatbeltProcErr = err
			return
		}
		purego.RegisterLibFunc(&loadedSeatbeltProc.errno, library, "__error")
	})
	if loadSeatbeltProcErr != nil {
		return seatbeltProcAPI{}, loadSeatbeltProcErr
	}
	if loadedSeatbeltProc.listAll == 0 || loadedSeatbeltProc.pidInfo == 0 || loadedSeatbeltProc.errno == nil {
		return seatbeltProcAPI{}, errors.New("public process API is unavailable")
	}
	return loadedSeatbeltProc, nil
}

func (api seatbeltProcAPI) allPIDs() ([]int, error) {
	estimateValue, _, estimateErrno := purego.SyscallN(api.listAll, 0, 0)
	estimate := int(int32(estimateValue))
	if estimate < 1 {
		return nil, fmt.Errorf("enumerate processes: size query failed: %w", syscall.Errno(estimateErrno))
	}
	capacity := estimate + 256
	for attempt := 0; attempt < 4; attempt++ {
		pids := make([]int32, capacity)
		countValue, _, errno := purego.SyscallN(api.listAll, uintptr(unsafe.Pointer(&pids[0])), uintptr(capacity*4))
		count := int(int32(countValue))
		if count < 0 {
			return nil, fmt.Errorf("enumerate processes: snapshot failed: %w", syscall.Errno(errno))
		}
		if count < capacity {
			result := make([]int, 0, count)
			for _, pid := range pids[:count] {
				if pid > 0 {
					result = append(result, int(pid))
				}
			}
			return result, nil
		}
		capacity *= 2
	}
	return nil, errors.New("enumerate processes: snapshot did not stabilize")
}

func (api seatbeltProcAPI) descriptors(pid int) ([]int, error) {
	const initialCapacity = 16
	const attempts = 8
	recordSize := int(unsafe.Sizeof(seatbeltFDInfo{}))
	if recordSize != 8 {
		return nil, errors.New("public descriptor ABI has an unexpected layout")
	}
	capacity := initialCapacity
	for attempt := 0; attempt < attempts; attempt++ {
		records := make([]seatbeltFDInfo, capacity)
		runtime.LockOSThread()
		errnoPointer := (*int32)(api.errno())
		*errnoPointer = 0
		gotValue, _, _ := purego.SyscallN(api.pidInfo, uintptr(pid), seatbeltProcPIDListFDs, 0, uintptr(unsafe.Pointer(&records[0])), uintptr(capacity*recordSize))
		errno := uintptr(*errnoPointer)
		runtime.UnlockOSThread()
		got := int(int32(gotValue))
		if got <= 0 {
			if errno == 0 {
				return nil, errors.New("enumerate descriptors: public process API returned no descriptors")
			}
			return nil, fmt.Errorf("enumerate descriptors: public process API failed: %w", syscall.Errno(errno))
		}
		if got%recordSize != 0 {
			return nil, errors.New("enumerate descriptors: public process API returned incomplete data")
		}
		count := got / recordSize
		if count == capacity {
			capacity *= 2
			continue
		}
		descriptors := make([]int, 0, count)
		for _, record := range records[:count] {
			if record.Descriptor < 0 {
				return nil, errors.New("enumerate descriptors: public process API returned an invalid descriptor")
			}
			descriptors = append(descriptors, int(record.Descriptor))
		}
		return descriptors, nil
	}
	return nil, errors.New("enumerate descriptors: public process API snapshot did not stabilize")
}

func (api seatbeltProcAPI) info(pid int) (seatbeltBSDInfo, error) {
	var info seatbeltBSDInfo
	size := int32(unsafe.Sizeof(info))
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	errnoPointer := (*int32)(api.errno())
	*errnoPointer = 0
	gotValue, _, _ := purego.SyscallN(api.pidInfo, uintptr(pid), seatbeltProcPIDTBSDInfo, 0, uintptr(unsafe.Pointer(&info)), uintptr(size))
	if got := int(int32(gotValue)); got != int(size) {
		errno := uintptr(*errnoPointer)
		if errno == 0 {
			return seatbeltBSDInfo{}, errors.New("inspect process: public process API returned incomplete data")
		}
		return seatbeltBSDInfo{}, fmt.Errorf("inspect process: public process API failed: %w", syscall.Errno(errno))
	}
	return info, nil
}
