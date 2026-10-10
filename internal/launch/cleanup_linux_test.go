package launch

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func linuxCleanupFixture(t *testing.T) *linuxSessionCleanup {
	t.Helper()
	linuxCleanupPrerequisites(t)
	lease, err := CreateProtectedSession(filepath.Join(t.TempDir(), "sessions"))
	if err != nil {
		t.Fatal(err)
	}
	challenge := bytes.Repeat([]byte{0xa3}, RecoveryProofChallengeSize)
	if err := PrepareSessionCleanupProof(lease.RootDir, challenge); err != nil {
		t.Fatal(err)
	}
	c, err := linuxPrepareCleanup(lease, challenge, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		// Test-only disposal of intentionally quarantined fixtures. Production
		// never closes these pins or releases this reference on lost proof.
		linuxCleanupQuarantine.Lock()
		_, quarantined := linuxCleanupQuarantine.sessions[c]
		delete(linuxCleanupQuarantine.sessions, c)
		linuxCleanupQuarantine.Unlock()
		if quarantined {
			_ = c.root.Close()
			if c.terminal != nil {
				c.terminal.close()
			}
			_ = lease.releaseReference()
		} else {
			select {
			case <-c.done:
			default:
				_ = c.root.Close()
				_ = lease.releaseReference()
			}
		}
		_ = lease.Remove()
	})
	return c
}

// These tests mock process settlement, but their durable IO still needs
// openat2 and the real boot identity. Do not mistake unavailable primitives
// for either successful proof or a mandatory-native pass.
func linuxCleanupPrerequisites(t *testing.T) {
	t.Helper()
	fd, err := unix.Openat2(unix.AT_FDCWD, t.TempDir(), &unix.OpenHow{
		Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err == nil {
		_ = unix.Close(fd)
		_, err = linuxBootID()
	}
	if err != nil {
		reason := "openat2 directory pinning and kernel boot identity: " + err.Error()
		if _, required := os.LookupEnv("ACS_LINUX_NATIVE_REQUIRED"); required {
			t.Fatal("required native Linux prerequisite unavailable: " + reason)
		}
		t.Skip("native Linux prerequisite unavailable: " + reason + "; set ACS_LINUX_NATIVE_REQUIRED=1 to require it")
	}
}

func TestLinuxCleanupRevokesPreparedProofAndRetainsLease(t *testing.T) {
	c := linuxCleanupFixture(t)
	if proven, err := VerifySessionCleanupProof(c.lease.RootDir, c.challenge); err != nil || proven {
		t.Fatalf("armed proof = %t, %v", proven, err)
	}
	if err := c.lease.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.lease.RootDir); err != nil {
		t.Fatal("deleted before settlement")
	}
	if err := c.finish(false); !errors.Is(err, errLinuxSettlement) {
		t.Fatalf("unproven finish: %v", err)
	}
	select {
	case <-c.unproven:
	default:
		t.Fatal("quarantine did not notify waiters")
	}
	select {
	case <-c.done:
		t.Fatal("unproven cleanup closed CleanupDone")
	default:
	}
	if err := c.finish(true); !errors.Is(err, errLinuxSettlement) {
		t.Fatal("late callback escaped quarantine")
	}
	if _, exists, err := RecoverSession(filepath.Dir(c.lease.RootDir), filepath.Base(c.lease.RootDir)); !exists || !errors.Is(err, ErrSessionStillActive) {
		t.Fatalf("quarantine lost lease: exists=%t err=%v", exists, err)
	}
	other, err := CreateSession(filepath.Dir(c.lease.RootDir))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Remove()
	if _, err := os.Stat(c.lease.RootDir); err != nil {
		t.Fatal("startup reclaimed quarantine")
	}
}

func TestLinuxCleanupProofAuthenticatesGenerationAndSurvivesRecovery(t *testing.T) {
	c := linuxCleanupFixture(t)
	challenge := append([]byte(nil), c.challenge...)
	// Mock the cgroup identity, not the durable IO, challenge or lease.
	c.binding.CgroupName = "acs-session-fixture"
	c.binding.CgroupDevice, c.binding.CgroupInode = 17, 19
	c.binding.ParentDevice, c.binding.ParentInode = 17, 18
	if err := c.write(linuxCleanupBindingFile, "binding"); err != nil {
		t.Fatal(err)
	}
	if err := c.finish(true); err != nil {
		t.Fatal(err)
	}
	if proven, err := VerifySessionCleanupProof(c.lease.RootDir, challenge); err != nil || !proven {
		t.Fatalf("durable proof = %t, %v", proven, err)
	}
	if proven, err := VerifySessionCleanupProof(c.lease.RootDir, bytes.Repeat([]byte{0xb4}, RecoveryProofChallengeSize)); proven || err == nil {
		t.Fatal("another generation's challenge accepted")
	}
	if err := c.lease.PreserveForRecovery(); err != nil {
		t.Fatal(err)
	}
	recovered, exists, err := RecoverSession(filepath.Dir(c.lease.RootDir), filepath.Base(c.lease.RootDir))
	if err != nil || !exists {
		t.Fatalf("recovery: exists=%t err=%v", exists, err)
	}
	defer recovered.Preserve()
	if proven, err := VerifySessionCleanupProof(recovered.RootDir, challenge); err != nil || !proven {
		t.Fatalf("recovery proof = %t, %v", proven, err)
	}
	if err := recovered.Remove(); err != nil {
		t.Fatal(err)
	}
}

func TestLinuxCleanupStaleProofRejectedEvenWithReusedChallenge(t *testing.T) {
	c := linuxCleanupFixture(t)
	challenge := append([]byte(nil), c.challenge...)
	if err := c.finish(true); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(c.lease.RootDir, sessionCleanupProofFile)
	old, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := PrepareSessionCleanupProof(c.lease.RootDir, challenge); err != nil {
		t.Fatal(err)
	}
	next, err := linuxPrepareCleanup(c.lease, challenge, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := next.finish(true); err != nil {
			t.Error(err)
		}
	}()
	if c.binding.Generation == next.binding.Generation {
		t.Fatal("generation reused")
	}
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	if proven, err := VerifySessionCleanupProof(c.lease.RootDir, challenge); err == nil || proven {
		t.Fatal("stale proof accepted")
	}
}

func TestLinuxCleanupRejectsMissingOrTamperedEvidence(t *testing.T) {
	for _, damage := range []string{"proof-lost", "binding-lost", "copy-binding", "tamper-cgroup", "reboot", "symlink", "hardlink", "mode", "truncated"} {
		t.Run(damage, func(t *testing.T) {
			c := linuxCleanupFixture(t)
			challenge := append([]byte(nil), c.challenge...)
			if damage == "reboot" {
				c.binding.Boot = "00000000-0000-0000-0000-000000000000"
				if err := c.write(linuxCleanupBindingFile, "binding"); err != nil {
					t.Fatal(err)
				}
				if err := c.write(sessionCleanupProofFile, "settled"); err != nil {
					t.Fatal(err)
				}
				defer c.finish(false)
			} else if err := c.finish(true); err != nil {
				t.Fatal(err)
			}
			proof := filepath.Join(c.lease.RootDir, sessionCleanupProofFile)
			binding := filepath.Join(c.lease.RootDir, linuxCleanupBindingFile)
			var err error
			switch damage {
			case "proof-lost":
				err = os.Remove(proof)
			case "binding-lost":
				err = os.Remove(binding)
			case "copy-binding":
				var data []byte
				data, err = os.ReadFile(binding)
				if err == nil {
					err = os.WriteFile(proof, data, 0600)
				}
			case "tamper-cgroup":
				var data []byte
				data, err = os.ReadFile(proof)
				if err == nil {
					err = os.WriteFile(proof, bytes.Replace(data, []byte(`"CgroupInode":0`), []byte(`"CgroupInode":1`), 1), 0600)
				}
			case "symlink":
				err = os.Rename(proof, proof+".saved")
				if err == nil {
					err = os.Symlink(proof+".saved", proof)
				}
			case "hardlink":
				err = os.Link(proof, proof+".copy")
			case "mode":
				err = os.Chmod(proof, 0644)
			case "truncated":
				err = os.Truncate(proof, 8)
			}
			if err != nil {
				t.Fatal(err)
			}
			if proven, _ := VerifySessionCleanupProof(c.lease.RootDir, challenge); proven {
				t.Fatal("lost or tampered evidence authorized removal")
			}
		})
	}
}

func TestLinuxCleanupPersistenceFailureQuarantines(t *testing.T) {
	c := linuxCleanupFixture(t)
	if err := os.Mkdir(filepath.Join(c.lease.RootDir, sessionCleanupProofFile), 0700); err != nil {
		t.Fatal(err)
	}
	if err := c.finish(true); !errors.Is(err, errLinuxSettlement) {
		t.Fatalf("proof persistence failure: %v", err)
	}
	if err := c.lease.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(c.lease.RootDir); err != nil {
		t.Fatal("proof failure deleted state")
	}
}

func TestLinuxTerminalRestoreFailureRetainsProofAndPins(t *testing.T) {
	c := linuxCleanupFixture(t)
	file, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	c.terminal = &linuxTerminalState{file: file, group: unix.Getpgrp()}
	if err := c.finish(true); !errors.Is(err, errLinuxSettlement) {
		t.Fatal("failed terminal restoration published proof")
	}
	if proven, err := VerifySessionCleanupProof(c.lease.RootDir, c.challenge); err != nil || proven {
		t.Fatalf("terminal failure proof = %t, %v", proven, err)
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("quarantined terminal pin closed")
	}
}

func TestLinuxRecoveryRetainsAbandonedSessionWithoutProof(t *testing.T) {
	c := linuxCleanupFixture(t)
	challenge := append([]byte(nil), c.challenge...)
	if err := c.finish(true); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(c.lease.RootDir, sessionCleanupProofFile)); err != nil {
		t.Fatal(err)
	}
	if err := c.lease.PreserveForRecovery(); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(c.lease.RootDir)
	recovered, exists, err := RecoverSession(directory, filepath.Base(c.lease.RootDir))
	if err != nil || !exists {
		t.Fatalf("acquire abandoned Session: %t, %v", exists, err)
	}
	if proven, err := VerifySessionCleanupProof(recovered.RootDir, challenge); err != nil || proven {
		t.Fatalf("missing proof = %t, %v", proven, err)
	}
	recovered.Preserve()
	other, err := CreateSession(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Remove()
	if _, err := os.Stat(c.lease.RootDir); err != nil {
		t.Fatal("startup deleted an abandoned Session without proof")
	}
}

func TestLinuxCleanupRejectsReplacedRootAndConcurrentGeneration(t *testing.T) {
	c := linuxCleanupFixture(t)
	if _, err := linuxPrepareCleanup(c.lease, c.challenge, nil); !errors.Is(err, errLinuxSettlement) {
		t.Fatal("overlapping generation admitted")
	}
	root := c.lease.RootDir
	if err := os.Rename(root, root+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	if err := c.finish(true); !errors.Is(err, errLinuxSettlement) {
		t.Fatal("replaced root accepted")
	}
	if _, err := os.Stat(filepath.Join(root, sessionCleanupProofFile)); !errors.Is(err, unix.ENOENT) {
		t.Fatal("stale owner wrote proof into replacement")
	}
}
