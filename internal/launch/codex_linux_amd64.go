package launch

import (
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/codexcompat"
)

// linuxCodexRuntime admits an exact CLI/companion pair by bytes, never by an
// uncontained --version subprocess. No directory or bundled bwrap is imported.
func linuxCodexRuntime(executable string) ([]linuxRuntimeFile, error) {
	return linuxCodexRuntimePairs(executable, codexcompat.LinuxAMD64Pairs())
}

func linuxCodexRuntimePairs(executable string, pairs []codexcompat.LinuxPair) ([]linuxRuntimeFile, error) {
	cli, canonical, err := linuxOpenRuntime(executable)
	if err != nil {
		return nil, errLinuxRecipe
	}
	defer cli.Close()
	info, err := cli.Stat()
	if err != nil {
		return nil, errLinuxRecipe
	}
	for _, pair := range pairs {
		if info.Size() != pair.CLIBytes {
			continue
		}
		// Carry the identity captured before hashing through later mount pinning.
		cliNode, err := linuxRuntimeNodeLimit(cli, pair.CLIBytes)
		if err != nil || cliNode.identity.mode.Perm()&0111 == 0 || cliNode.identity.mode.Perm()&0022 != 0 ||
			linuxVerifyLockedELF(cli, pair.CLIBytes, pair.CLISHA256) != nil {
			continue
		}
		companionPath := filepath.Join(filepath.Dir(canonical), "codex-code-mode-host")
		companion, resolved, err := linuxOpenRuntime(companionPath)
		if err != nil {
			return nil, errLinuxRecipe
		}
		defer companion.Close()
		// Symlinks to other installs must not substitute an unrelated companion.
		hostNode, err := linuxRuntimeNodeLimit(companion, pair.CompanionBytes)
		if err != nil || resolved != companionPath || hostNode.identity.mode.Perm()&0111 == 0 || hostNode.identity.mode.Perm()&0022 != 0 ||
			linuxVerifyLockedELF(companion, pair.CompanionBytes, pair.CompanionSHA256) != nil {
			return nil, errLinuxRecipe
		}
		return []linuxRuntimeFile{{canonical, canonical, cliNode}, {companionPath, companionPath, hostNode}}, nil
	}
	return nil, errLinuxRecipe
}
