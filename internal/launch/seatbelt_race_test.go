//go:build darwin && race

package launch

import "testing"

func skipSeatbeltNativeTestBinaryUnderRace(t *testing.T) {
	t.Helper()
	t.Skip("ThreadSanitizer cannot initialize inside the production Seatbelt policy")
}
