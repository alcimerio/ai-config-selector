package launch

import (
	"strings"

	"golang.org/x/sys/unix"
)

// amd64 registers the qualified Bubblewrap backend. Every other Linux
// architecture stays closed and has no direct-exec fallback.
func nativeSandboxBackends() map[string]sandboxBackend { return linuxNativeSandboxBackends() }

func currentLinuxRelease() (string, error) {
	var name unix.Utsname
	if err := unix.Uname(&name); err != nil {
		return "", err
	}
	release := unix.ByteSliceToString(name.Release[:])
	if release == "" || strings.ContainsAny(release, " \t\r\n") {
		return "", unix.EINVAL
	}
	return release, nil
}
