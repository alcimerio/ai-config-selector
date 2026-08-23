//go:build darwin && race

package sandboxshell

import "testing"

func skipNativeShellTestBinaryUnderRace(t *testing.T) {
	t.Helper()
	t.Skip("ThreadSanitizer cannot initialize inside the production Seatbelt policy")
}
