package launch

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSessionCleanupProofRequiresExactSupervisorChallenge(t *testing.T) {
	root := t.TempDir()
	challenge := bytes.Repeat([]byte{0x5a}, RecoveryProofChallengeSize)
	if err := recordSessionCleanupProof(root, challenge); err != nil {
		t.Fatal(err)
	}
	if proven, err := VerifySessionCleanupProof(root, challenge); err != nil || !proven {
		t.Fatalf("valid proof = (%v, %v)", proven, err)
	}
	wrong := bytes.Repeat([]byte{0x6b}, RecoveryProofChallengeSize)
	if proven, err := VerifySessionCleanupProof(root, wrong); err == nil || proven {
		t.Fatalf("wrong challenge proof = (%v, %v)", proven, err)
	}
}

func TestSessionCleanupProofIsClearedBeforeTheNextProcess(t *testing.T) {
	root := t.TempDir()
	challenge := bytes.Repeat([]byte{0x7c}, RecoveryProofChallengeSize)
	if err := recordSessionCleanupProof(root, challenge); err != nil {
		t.Fatal(err)
	}
	if err := clearSessionCleanupProof(root); err != nil {
		t.Fatal(err)
	}
	if proven, err := VerifySessionCleanupProof(root, challenge); err != nil || proven {
		t.Fatalf("cleared proof = (%v, %v)", proven, err)
	}
}

func TestSessionCleanupProofRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("untrusted"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, sessionCleanupProofFile)); err != nil {
		t.Fatal(err)
	}
	challenge := bytes.Repeat([]byte{0x8d}, RecoveryProofChallengeSize)
	if proven, err := VerifySessionCleanupProof(root, challenge); err == nil || proven {
		t.Fatalf("symlink proof = (%v, %v)", proven, err)
	}
}
