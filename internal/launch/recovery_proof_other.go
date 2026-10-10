//go:build !linux

package launch

// VerifySessionCleanupProof validates the native supervisor's cleanup proof.
func VerifySessionCleanupProof(sessionRoot string, challenge []byte) (bool, error) {
	return verifyLegacySessionCleanupProof(sessionRoot, challenge)
}
