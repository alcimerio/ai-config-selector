//go:build darwin

package launch

import "syscall"

func statChangeNanos(stat *syscall.Stat_t) int64 { return stat.Ctimespec.Nano() }
