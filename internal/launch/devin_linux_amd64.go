package launch

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"

	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"golang.org/x/sys/unix"
)

// The locked Linux bundle contains one static PIE and documentation. No host
// library, loader, documentation directory, shell or PATH lookup is needed for
// these preflights. Other Devin versions must be qualified separately.
func linuxDevinRuntime(executable string) ([]linuxRuntimeFile, error) {
	file, canonical, err := linuxOpenRuntime(executable)
	if err != nil {
		return nil, errLinuxRecipe
	}
	defer file.Close()
	node, err := linuxRuntimeNodeLimit(file, devinruntime.LinuxAMD64BinarySize)
	if err != nil || node.identity.mode.Perm()&0111 == 0 || node.identity.mode.Perm()&0022 != 0 ||
		linuxVerifyDevinELF(file, devinruntime.LinuxAMD64BinarySize, devinruntime.LinuxAMD64BinarySHA256) != nil {
		return nil, errLinuxRecipe
	}
	return []linuxRuntimeFile{{canonical, canonical, node}}, nil
}

func linuxVerifyDevinELF(file *os.File, size int64, digest string) error {
	var before, after unix.Stat_t
	if unix.Fstat(int(file.Fd()), &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size != size {
		return errLinuxRecipe
	}
	interpreter, needed, err := linuxELFDependencies(file)
	if err != nil || interpreter != "" || len(needed) != 0 {
		return errLinuxRecipe
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.NewSectionReader(file, 0, size+1))
	if err != nil || n != size || hex.EncodeToString(hash.Sum(nil)) != digest ||
		unix.Fstat(int(file.Fd()), &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino ||
		before.Size != after.Size || before.Mode != after.Mode || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return errLinuxRecipe
	}
	return nil
}

func linuxDevinArguments(arguments []string) bool {
	// Qualification probes only. Full Devin Sessions (including protected MCP
	// basename enforcement and interactive use) remain a separate admission gate.
	for _, fixed := range [][]string{
		{"--version"}, {"auth", "status"}, {"skills", "list", "--json"}, {"mcp", "list"},
	} {
		if len(arguments) != len(fixed) {
			continue
		}
		match := true
		for i := range fixed {
			match = match && arguments[i] == fixed[i]
		}
		if match {
			return true
		}
	}
	return false
}
