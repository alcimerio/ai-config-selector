//go:build darwin && !race

package sandboxshell

import "testing"

func skipNativeShellTestBinaryUnderRace(t *testing.T) {
	t.Helper()
}
