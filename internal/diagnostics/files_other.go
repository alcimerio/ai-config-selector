//go:build !darwin && !linux

package diagnostics

import "os"

func readableExecutable(string) bool { return false }
func rootOwned(os.FileInfo) bool     { return false }
