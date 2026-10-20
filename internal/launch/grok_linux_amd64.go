package launch

import (
	"github.com/alcimerio/ai-config-selector/internal/grokcompat"
)

// The locked Linux CLI is one static PIE. No host loader, library, or PATH
// lookup is admitted. Other Grok versions and linux/arm64 stay closed.
func linuxGrokRuntime(executable string) ([]linuxRuntimeFile, error) {
	file, canonical, err := linuxOpenRuntime(executable)
	if err != nil {
		return nil, errLinuxRecipe
	}
	defer file.Close()
	node, err := linuxRuntimeNodeLimit(file, grokcompat.LinuxAMD64BinarySize)
	if err != nil || node.identity.mode.Perm()&0111 == 0 || node.identity.mode.Perm()&0022 != 0 ||
		linuxVerifyLockedELF(file, grokcompat.LinuxAMD64BinarySize, grokcompat.LinuxAMD64BinarySHA256) != nil {
		return nil, errLinuxRecipe
	}
	return []linuxRuntimeFile{{canonical, canonical, node}}, nil
}

// ACS launches only the contained version probe and the interactive process.
// Extra flags, including trust and login, are not admitted.
func linuxGrokArguments(arguments []string, interactive bool) bool {
	if interactive {
		return len(arguments) == 0
	}
	return len(arguments) == 1 && arguments[0] == "--version"
}
