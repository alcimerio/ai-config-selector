package launch

import (
	"path/filepath"
	"sort"

	"github.com/alcimerio/ai-config-selector/internal/codexcompat"
)

// Empty selection is the only MCP mode admitted by this experimental recipe.
// An empty -c table merges with, rather than removes, lower-precedence tables.
// Replace the user config in the private mount view and omit project configs
// instead of relying on CLI precedence or the target's project-trust handling.
const linuxCodexEmptyConfig = "mcp_servers = {}\n"

func linuxCodexConfigurationRequest(request validatedProcessRequest, tree linuxFilesystemSnapshot) (validatedProcessRequest, error) {
	request.filesystemExclusions = append([]FilesystemExclusion(nil), request.filesystemExclusions...)
	for directory := request.workspace; directory != "/"; directory = filepath.Dir(directory) {
		if !linuxCanonicalPlanPath(directory) {
			return validatedProcessRequest{}, errLinuxRecipe
		}
		path := filepath.Join(directory, ".codex", "config.toml")
		_, exists := tree[path]
		if _, captured := tree[directory]; !captured && !exists {
			// Unbound ancestors are synthetic directories in the private root.
			continue
		}
		witness, firstMissing := path, ""
		for {
			if node, captured := tree[witness]; captured {
				if firstMissing != "" && !node.identity.mode.IsDir() {
					return validatedProcessRequest{}, errLinuxRecipe
				}
				request.filesystemExclusions = append(request.filesystemExclusions, FilesystemExclusion{
					path: path, logicalPath: path, exists: exists, firstMissing: firstMissing,
					witness: FilesystemGrant{path: witness, identity: node.identity},
				})
				break
			}
			if witness == "/" {
				return validatedProcessRequest{}, errLinuxRecipe
			}
			firstMissing, witness = witness, filepath.Dir(witness)
		}
	}
	return request, nil
}

func linuxAddCodexConfiguration(plan *linuxFilesystemPlan, home string) {
	// The Session HOME is owned by this launch. Bubblewrap can create the
	// mountpoints there without creating placeholders in the host workspace.
	// Keep the rest of .codex writable, including atomic auth.json refreshes.
	plan.mounts = append(plan.mounts[:len(plan.mounts)-1],
		linuxMount{kind: linuxMountDirectory, destination: filepath.Join(home, ".codex")},
		linuxMount{kind: linuxMountEmptyCodexConfig, destination: filepath.Join(home, ".codex", "config.toml")})
	sort.Slice(plan.mounts, func(i, j int) bool { return plan.mounts[i].destination < plan.mounts[j].destination })
	plan.mounts = append(plan.mounts, linuxMount{kind: linuxMountSealRoot, destination: "/"})
}

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
