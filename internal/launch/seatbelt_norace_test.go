//go:build darwin && !race

package launch

import "testing"

func skipSeatbeltNativeTestBinaryUnderRace(t *testing.T) {
	t.Helper()
}
