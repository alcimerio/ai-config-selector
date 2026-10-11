//go:build !linux

package linuxprobe

import "context"

func probe(context.Context) Report {
	return Report{Checks: []Check{{"linux.capabilities", "fail", "not_linux", "Linux capability probes require a native Linux host; no probe ran."}}}
}
