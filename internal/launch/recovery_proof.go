package launch

import (
	"crypto/subtle"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

const RecoveryProofChallengeSize = 32

const sessionCleanupProofFile = ".acs-cleanup-proof-v1"
const sessionCleanupProofMagic = "ACS-CLEANUP-PROOF-V1\n"

func clearSessionCleanupProof(sessionRoot string) error {
	if err := os.Remove(filepath.Join(sessionRoot, sessionCleanupProofFile)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDirectoryPath(sessionRoot)
}

// PrepareSessionCleanupProof durably records authenticated evidence that no
// subprocess has started. A native supervisor must clear it after receiving
// the challenge and before starting a target, then replace it only after
// proving that the complete target tree is gone.
func PrepareSessionCleanupProof(sessionRoot string, challenge []byte) error {
	return recordSessionCleanupProof(sessionRoot, challenge)
}

func recordSessionCleanupProof(sessionRoot string, challenge []byte) error {
	if len(challenge) != RecoveryProofChallengeSize {
		return errors.New("invalid Session cleanup proof challenge")
	}
	temporary, err := os.CreateTemp(sessionRoot, ".acs-cleanup-proof-*")
	if err != nil {
		return err
	}
	path := temporary.Name()
	defer func() {
		_ = temporary.Close()
		_ = os.Remove(path)
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	contents := append([]byte(sessionCleanupProofMagic), challenge...)
	if _, err := temporary.Write(contents); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(path, filepath.Join(sessionRoot, sessionCleanupProofFile)); err != nil {
		return err
	}
	path = ""
	return syncDirectoryPath(sessionRoot)
}

// VerifySessionCleanupProof validates evidence written only after the native
// supervisor has proved that the contained process tree is gone.
func VerifySessionCleanupProof(sessionRoot string, challenge []byte) (bool, error) {
	if len(challenge) != RecoveryProofChallengeSize {
		return false, errors.New("invalid Session cleanup proof challenge")
	}
	path := filepath.Join(sessionRoot, sessionCleanupProofFile)
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, syscall.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = syscall.Close(descriptor)
		return false, errors.New("inspect Session cleanup proof")
	}
	defer file.Close()
	info, err := file.Stat()
	wantSize := int64(len(sessionCleanupProofMagic) + RecoveryProofChallengeSize)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() != wantSize {
		return false, errors.New("invalid Session cleanup proof")
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Uid != uint32(os.Geteuid()) || native.Nlink != 1 {
		return false, errors.New("invalid Session cleanup proof")
	}
	contents, err := io.ReadAll(io.LimitReader(file, wantSize+1))
	if err != nil || int64(len(contents)) != wantSize {
		return false, errors.New("invalid Session cleanup proof")
	}
	want := append([]byte(sessionCleanupProofMagic), challenge...)
	if subtle.ConstantTimeCompare(contents, want) != 1 {
		return false, errors.New("invalid Session cleanup proof")
	}
	return true, nil
}
