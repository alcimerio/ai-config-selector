package launch

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const linuxCleanupBindingFile = ".acs-linux-cleanup-v1"

// The binding never contains the challenge or a settlement MAC. Copying the
// binding into the proof file cannot turn an active Session into a settled one.
// These files are outside the target's filesystem view, alongside the existing
// cleanup proof. The shared operation capability owns the secret challenge.
type linuxCleanupBinding struct {
	Version                   int
	Generation, Boot          string
	RootDevice, RootInode     uint64
	ParentDevice, ParentInode uint64
	CgroupDevice, CgroupInode uint64
	CgroupName                string
}

type linuxCleanupEvidence struct {
	Binding linuxCleanupBinding
	MAC     string
}

// This object is owned only by the dedicated outer supervisor. Its reference
// keeps both the Session lease and terminal pins alive when proof is lost.
type linuxSessionCleanup struct {
	lease          *SessionLease
	root           *os.File
	challenge      []byte
	binding        linuxCleanupBinding
	terminal       *linuxTerminalState
	done, unproven chan struct{}
	once           sync.Once
	err            error
}

var linuxCleanupQuarantine = struct {
	sync.Mutex
	sessions map[*linuxSessionCleanup]struct{}
}{sessions: make(map[*linuxSessionCleanup]struct{})}

func (c *linuxSessionCleanup) CleanupDone() <-chan struct{}     { return c.done }
func (c *linuxSessionCleanup) CleanupUnproven() <-chan struct{} { return c.unproven }

// No production entry point calls this yet. Require the existing prepared
// challenge and sole lease ownership, then durably revoke the no-target proof
// before any child can start. Recovery protection precedes that revocation.
func linuxPrepareCleanup(lease *SessionLease, challenge []byte, terminal *os.File) (*linuxSessionCleanup, error) {
	if lease == nil || len(challenge) != RecoveryProofChallengeSize {
		return nil, errLinuxSettlement
	}
	lease.mutex.Lock()
	defer lease.mutex.Unlock()
	if lease.guard == nil || lease.references != 1 || lease.removeRequested {
		return nil, errLinuxSettlement
	}
	if ok, err := verifyLegacySessionCleanupProof(lease.RootDir, challenge); err != nil || !ok {
		return nil, errLinuxSettlement
	}
	root, err := linuxOpenCleanupRoot(lease.RootDir)
	if err != nil {
		return nil, err
	}
	c := &linuxSessionCleanup{lease: lease, root: root, challenge: append([]byte(nil), challenge...), done: make(chan struct{}), unproven: make(chan struct{})}
	keep := false
	defer func() {
		if !keep {
			_ = root.Close()
			if c.terminal != nil {
				c.terminal.close()
			}
		}
	}()
	var stat unix.Stat_t
	if unix.Fstat(int(root.Fd()), &stat) != nil {
		return nil, errLinuxSettlement
	}
	boot, err := linuxBootID()
	if err != nil {
		return nil, err
	}
	var generation [32]byte
	if _, err := rand.Read(generation[:]); err != nil {
		return nil, errLinuxSettlement
	}
	c.binding = linuxCleanupBinding{Version: 1, Generation: hex.EncodeToString(generation[:]), Boot: boot, RootDevice: uint64(stat.Dev), RootInode: stat.Ino}
	c.terminal, err = linuxCaptureTerminal(terminal)
	if err != nil {
		return nil, err
	}
	if !lease.recoveryProtected {
		if createRecoveryProtection(lease.recoveryPath) != nil {
			return nil, errLinuxSettlement
		}
		lease.recoveryProtected = true
	}
	if c.write(linuxCleanupBindingFile, "binding") != nil || unix.Unlinkat(int(root.Fd()), sessionCleanupProofFile, 0) != nil || root.Sync() != nil {
		return nil, errLinuxSettlement
	}
	lease.references++
	keep = true
	return c, nil
}

func (c *linuxSessionCleanup) bindCgroup(g *linuxSessionCgroup) error {
	if c.current() != nil || c.binding.CgroupName != "" || g.identity() != nil {
		return errLinuxSettlement
	}
	var parent unix.Stat_t
	if unix.Fstat(int(g.parent.Fd()), &parent) != nil {
		return errLinuxSettlement
	}
	c.binding.ParentDevice, c.binding.ParentInode = uint64(parent.Dev), parent.Ino
	c.binding.CgroupDevice, c.binding.CgroupInode, c.binding.CgroupName = g.device, g.inode, g.name
	return c.write(linuxCleanupBindingFile, "binding")
}

// settled means the dedicated supervisor has already proved empty membership,
// pidfd death and ECHILD, and removed the original cgroup. A failure is terminal:
// no timer, cancellation, missing path, or later callback may release the lease.
func (c *linuxSessionCleanup) finish(settled bool) error {
	c.once.Do(func() {
		c.err = errLinuxSettlement
		if settled && c.current() == nil && (c.terminal == nil || c.terminal.restore() == nil) && c.write(sessionCleanupProofFile, "settled") == nil {
			if c.terminal != nil {
				c.terminal.close()
			}
			_ = c.root.Close()
			clear(c.challenge)
			c.err = c.lease.releaseReference()
			close(c.done)
			return
		}
		linuxCleanupQuarantine.Lock()
		linuxCleanupQuarantine.sessions[c] = struct{}{}
		linuxCleanupQuarantine.Unlock()
		close(c.unproven)
	})
	return c.err
}

func (c *linuxSessionCleanup) current() error {
	if linuxCleanupRootIdentity(c.root, c.lease.RootDir, c.binding) != nil {
		return errLinuxSettlement
	}
	boot, err := linuxBootID()
	if err != nil || boot != c.binding.Boot {
		return errLinuxSettlement
	}
	e, err := linuxReadCleanupEvidence(c.root, linuxCleanupBindingFile)
	if err != nil || e.Binding != c.binding || !linuxAuthenticateCleanup(e, c.challenge, "binding") {
		return errLinuxSettlement
	}
	return nil
}

func (c *linuxSessionCleanup) write(name, purpose string) error {
	if linuxCleanupRootIdentity(c.root, c.lease.RootDir, c.binding) != nil {
		return errLinuxSettlement
	}
	data, err := json.Marshal(linuxCleanupEvidence{c.binding, linuxCleanupMAC(c.binding, c.challenge, purpose)})
	if err != nil {
		return errLinuxSettlement
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errLinuxSettlement
	}
	tmp := ".acs-linux-proof-" + hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(int(c.root.Fd()), tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return errLinuxSettlement
	}
	f := os.NewFile(uintptr(fd), "linux-cleanup-proof")
	defer f.Close()
	defer unix.Unlinkat(int(c.root.Fd()), tmp, 0)
	if n, err := f.Write(data); err != nil || n != len(data) || f.Sync() != nil || f.Close() != nil ||
		unix.Renameat(int(c.root.Fd()), tmp, int(c.root.Fd()), name) != nil || c.root.Sync() != nil {
		return errLinuxSettlement
	}
	return linuxCleanupRootIdentity(c.root, c.lease.RootDir, c.binding)
}

func linuxCleanupMAC(binding linuxCleanupBinding, challenge []byte, purpose string) string {
	data, _ := json.Marshal(binding)
	m := hmac.New(sha256.New, challenge)
	_, _ = m.Write([]byte("ACS-LINUX-CLEANUP-V1/" + purpose + "\n"))
	_, _ = m.Write(data)
	return hex.EncodeToString(m.Sum(nil))
}

func linuxAuthenticateCleanup(e linuxCleanupEvidence, challenge []byte, purpose string) bool {
	return len(challenge) == RecoveryProofChallengeSize && hmac.Equal([]byte(e.MAC), []byte(linuxCleanupMAC(e.Binding, challenge, purpose)))
}

func linuxOpenCleanupRoot(path string) (*os.File, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
	if err != nil {
		return nil, errLinuxSettlement
	}
	f := os.NewFile(uintptr(fd), "linux-cleanup-root")
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil || s.Uid != uint32(os.Geteuid()) || s.Mode&0777 != 0700 {
		_ = f.Close()
		return nil, errLinuxSettlement
	}
	return f, nil
}

func linuxCleanupRootIdentity(root *os.File, path string, b linuxCleanupBinding) error {
	var pinned, named unix.Stat_t
	if unix.Fstat(int(root.Fd()), &pinned) != nil || unix.Lstat(path, &named) != nil || named.Mode&unix.S_IFMT != unix.S_IFDIR ||
		uint64(pinned.Dev) != b.RootDevice || pinned.Ino != b.RootInode || pinned.Nlink == 0 ||
		named.Dev != pinned.Dev || named.Ino != pinned.Ino || named.Uid != uint32(os.Geteuid()) || named.Mode&0777 != 0700 {
		return errLinuxSettlement
	}
	return nil
}

func linuxBootID() (string, error) {
	data, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	id := strings.TrimSpace(string(data))
	decoded, decodeErr := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if err != nil || len(id) != 36 || decodeErr != nil || len(decoded) != 16 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		return "", errLinuxSettlement
	}
	return id, nil
}

func linuxReadCleanupEvidence(root *os.File, name string) (linuxCleanupEvidence, error) {
	var e linuxCleanupEvidence
	fd, err := unix.Openat(int(root.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return e, err
	}
	f := os.NewFile(uintptr(fd), "linux-cleanup-evidence")
	defer f.Close()
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil || s.Mode&unix.S_IFMT != unix.S_IFREG || s.Mode&0777 != 0600 || s.Nlink != 1 || s.Uid != uint32(os.Geteuid()) || s.Size > 8192 {
		return e, errLinuxSettlement
	}
	data, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil || len(data) > 8192 {
		return e, errLinuxSettlement
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&e) != nil || d.Decode(new(any)) != io.EOF || e.Binding.Version != 1 || len(e.Binding.Generation) != 64 || e.Binding.RootInode == 0 || f.Sync() != nil {
		return e, errLinuxSettlement
	}
	return e, nil
}

// Recovery only consumes an authenticated completed generation. It never
// infers settlement from an absent cgroup, PID, or supervisor, even after boot.
// Legacy no-target proofs remain usable before the Linux supervisor is armed.
func VerifySessionCleanupProof(sessionRoot string, challenge []byte) (bool, error) {
	if _, err := os.Lstat(filepath.Join(sessionRoot, linuxCleanupBindingFile)); os.IsNotExist(err) {
		return verifyLegacySessionCleanupProof(sessionRoot, challenge)
	} else if err != nil {
		return false, errLinuxSettlement
	}
	root, err := linuxOpenCleanupRoot(sessionRoot)
	if err != nil {
		return false, err
	}
	defer root.Close()
	binding, err := linuxReadCleanupEvidence(root, linuxCleanupBindingFile)
	if err != nil || !linuxAuthenticateCleanup(binding, challenge, "binding") || linuxCleanupRootIdentity(root, sessionRoot, binding.Binding) != nil {
		return false, errLinuxSettlement
	}
	boot, err := linuxBootID()
	if err != nil || binding.Binding.Boot != boot {
		return false, errLinuxSettlement
	}
	proof, err := linuxReadCleanupEvidence(root, sessionCleanupProofFile)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil || proof.Binding != binding.Binding || !linuxAuthenticateCleanup(proof, challenge, "settled") || root.Sync() != nil {
		return false, errLinuxSettlement
	}
	return true, nil
}
