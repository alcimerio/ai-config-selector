package launch

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"

	"github.com/alcimerio/ai-config-selector/internal/environmentintent"
	"golang.org/x/sys/unix"
)

// MCPRecipe contains only a selected executable identity and typed references.
// It deliberately contains no environment values or arbitrary literal argv.
type MCPRecipe struct {
	ID                     string              `json:"id"`
	SessionHome            string              `json:"sessionHome"`
	ExecutableLogicalPath  string              `json:"executableLogicalPath"`
	Executable             string              `json:"executable"`
	ExecutableSHA256       string              `json:"executableSHA256"`
	ExecutableIdentity     MCPRecipeIdentity   `json:"executableIdentity"`
	ExecutableWitness      []MCPRecipeIdentity `json:"executableWitness"`
	WorkspacePath          string              `json:"workspacePath,omitempty"`
	WorkspaceCanonicalPath string              `json:"workspaceCanonicalPath,omitempty"`
	WorkspaceIdentity      MCPRecipeIdentity   `json:"workspaceIdentity,omitempty"`
	WorkspaceWitness       []MCPRecipeIdentity `json:"workspaceWitness,omitempty"`
	Arguments              []MCPRecipeArgument `json:"arguments"`
	EnvNames               []string            `json:"environmentNames"`
	Disabled               []string            `json:"disabledTools"`
}

type MCPRecipeArgument struct {
	Kind                   string              `json:"kind"`
	Value                  string              `json:"value"`
	LogicalPath            string              `json:"logicalPath,omitempty"`
	Identity               MCPRecipeIdentity   `json:"identity,omitempty"`
	Witness                []MCPRecipeIdentity `json:"witness,omitempty"`
	WorkspacePath          string              `json:"workspacePath,omitempty"`
	WorkspaceCanonicalPath string              `json:"workspaceCanonicalPath,omitempty"`
	WorkspaceIdentity      MCPRecipeIdentity   `json:"workspaceIdentity,omitempty"`
	WorkspaceWitness       []MCPRecipeIdentity `json:"workspaceWitness,omitempty"`
}

type MCPRecipeIdentity struct {
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Mode   uint64 `json:"mode"`
	Links  uint64 `json:"links,omitempty"`
	Size   int64  `json:"size,omitempty"`
	Mtime  int64  `json:"mtime,omitempty"`
}

func recipeIdentity(value pathIdentity) MCPRecipeIdentity {
	return MCPRecipeIdentity{Device: value.device, Inode: value.inode, Mode: uint64(value.mode), Links: value.links, Size: value.size, Mtime: value.modifiedNanos}
}

func recipeWitness(values []pathIdentity) []MCPRecipeIdentity {
	result := make([]MCPRecipeIdentity, len(values))
	for index, value := range values {
		result[index] = recipeIdentity(value)
	}
	return result
}

// CompileMCPRecipes resolves logical IDs against the exact grants compiled for
// the same Session process. Environment values remain in the attached process
// tree; argv recipes retain only destination names for runtime lookup.
func CompileMCPRecipes(servers []MCPServerIntent, executables []ExecutableGrant, paths []FilesystemGrant, environments []EnvironmentIntent) ([]MCPRecipe, error) {
	executableByID := make(map[string]ExecutableGrant, len(executables))
	for _, grant := range executables {
		executableByID[grant.ID] = grant
	}
	pathByID := make(map[string]FilesystemGrant, len(paths))
	for _, grant := range paths {
		// Ineffective means no additional Seatbelt clause was needed because
		// existing workspace/parent authority already covers this grant. Its
		// identity was still validated and it remains a valid logical binding.
		pathByID[grant.ID] = grant
	}
	environmentByID := make(map[string]EnvironmentIntent, len(environments))
	for _, intent := range environments {
		environmentByID[intent.ID] = intent
	}
	result := make([]MCPRecipe, 0, len(servers))
	for _, server := range servers {
		binary, ok := executableByID[server.ExecutableRef]
		if !ok || binary.path == "" || server.Transport != "stdio" {
			return nil, errors.New("MCP executable grant is unavailable")
		}
		recipe := MCPRecipe{ID: server.ID, ExecutableLogicalPath: binary.logicalPath, Executable: binary.path, ExecutableSHA256: hex.EncodeToString(binary.digest[:]), ExecutableIdentity: recipeIdentity(binary.identity), ExecutableWitness: recipeWitness(binary.logicalWitness), Arguments: make([]MCPRecipeArgument, 0, len(server.Arguments)), EnvNames: []string{}, Disabled: append([]string{}, server.DisabledTools...)}
		if binary.workspaceRelative {
			recipe.WorkspacePath, recipe.WorkspaceCanonicalPath, recipe.WorkspaceIdentity, recipe.WorkspaceWitness = binary.workspaceLogicalPath, binary.workspacePath, recipeIdentity(binary.workspaceIdentity), recipeWitness(binary.workspaceLogicalWitness)
		}
		for _, argument := range server.Arguments {
			switch argument.Kind {
			case "path":
				grant, found := pathByID[argument.Ref]
				if !found || grant.path == "" {
					return nil, errors.New("MCP input grant is unavailable")
				}
				argumentRecipe := MCPRecipeArgument{Kind: "path", Value: grant.path, LogicalPath: grant.logicalPath, Identity: recipeIdentity(grant.identity), Witness: recipeWitness(grant.logicalWitness)}
				if grant.workspaceRelative {
					argumentRecipe.WorkspacePath, argumentRecipe.WorkspaceCanonicalPath, argumentRecipe.WorkspaceIdentity, argumentRecipe.WorkspaceWitness = grant.workspaceLogicalPath, grant.workspacePath, recipeIdentity(grant.workspaceIdentity), recipeWitness(grant.workspaceLogicalWitness)
				}
				recipe.Arguments = append(recipe.Arguments, argumentRecipe)
			case "environment":
				intent, found := environmentByID[argument.Ref]
				if !found || intent.Classification != environmentintent.ClassificationNonSecret || !environmentintent.ValidName(intent.Destination) {
					return nil, errors.New("MCP argv environment reference is unavailable")
				}
				recipe.Arguments = append(recipe.Arguments, MCPRecipeArgument{Kind: "environment", Value: intent.Destination})
				recipe.EnvNames = append(recipe.EnvNames, intent.Destination)
			default:
				return nil, errors.New("MCP argv reference kind is unsupported")
			}
		}
		for _, id := range server.EnvironmentRefs {
			intent, found := environmentByID[id]
			if !found || !environmentintent.ValidName(intent.Destination) {
				return nil, errors.New("MCP environment reference is unavailable")
			}
			recipe.EnvNames = append(recipe.EnvNames, intent.Destination)
		}
		sort.Strings(recipe.EnvNames)
		recipe.EnvNames = compactRecipeStrings(recipe.EnvNames)
		result = append(result, recipe)
	}
	return result, nil
}

func compactRecipeStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	write := 1
	for read := 1; read < len(values); read++ {
		if values[read] == values[write-1] {
			continue
		}
		values[write] = values[read]
		write++
	}
	return values[:write]
}

// WriteMCPRecipes creates one private, dedicated directory under the selected
// Session HOME. The caller must pass the directory as a recursive typed
// mutation protection to every process that can load the target projection.
func WriteMCPRecipes(home string, recipes []MCPRecipe) (string, error) {
	if len(recipes) == 0 || !filepath.IsAbs(home) {
		return "", errors.New("MCP recipe input is invalid")
	}
	canonicalHome, err := filepath.EvalSymlinks(filepath.Clean(home))
	if err != nil {
		return "", errors.New("MCP recipe Session HOME is unavailable")
	}
	info, err := os.Stat(canonicalHome)
	if err != nil || !info.IsDir() {
		return "", errors.New("MCP recipe Session HOME is unavailable")
	}
	canonicalHome = filepath.Clean(canonicalHome)
	root := filepath.Join(canonicalHome, ".acs", "mcp")
	for _, directory := range []string{filepath.Join(canonicalHome, ".acs"), root} {
		if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", errors.New("MCP recipe directory could not be created")
		}
		info, err := os.Lstat(directory)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("MCP recipe directory could not be verified")
		}
	}
	for index := range recipes {
		recipes[index].SessionHome = canonicalHome
	}
	encoded, err := json.Marshal(recipes)
	if err != nil || len(encoded)+1 > 1<<20 {
		return "", errors.New("MCP recipes could not be encoded")
	}
	path := filepath.Join(root, "recipes.json")
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return "", errors.New("MCP recipes could not be created")
	}
	file := os.NewFile(uintptr(fd), path)
	_, writeErr := file.Write(append(encoded, '\n'))
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(path)
		return "", errors.New("MCP recipes could not be persisted")
	}
	return root, nil
}

// RunMCPHelper is the in-place target child entrypoint. It accepts only a
// server ID and reads the fixed protected Session recipe; host values are
// resolved from the already-selected child environment.
func RunMCPHelper(arguments []string) (bool, error) {
	if len(arguments) == 0 || arguments[0] != "--acs-mcp-launch" {
		return false, nil
	}
	if len(arguments) != 3 || !filepath.IsAbs(arguments[1]) || arguments[2] == "" {
		return true, mcpFailure("invalid-invocation", "MCP launcher invocation is invalid")
	}
	home := os.Getenv("HOME")
	if !filepath.IsAbs(home) || filepath.Clean(home) != filepath.Clean(arguments[1]) {
		return true, mcpFailure("session-home-unavailable", "MCP launcher Session HOME is unavailable")
	}
	path := filepath.Join(filepath.Clean(home), ".acs", "mcp", "recipes.json")
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return true, mcpFailure("recipe-unavailable", "MCP launcher recipe is unavailable")
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		_ = file.Close()
		return true, mcpFailure("recipe-invalid", "MCP launcher recipe is invalid")
	}
	encoded, readErr := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return true, mcpFailure("recipe-invalid", "MCP launcher recipe is invalid")
	}
	recipes, err := decodeMCPRecipes(encoded)
	if err != nil || len(recipes) == 0 {
		return true, mcpFailure("recipe-invalid", "MCP launcher recipe is invalid")
	}
	var selected *MCPRecipe
	for index := range recipes {
		if recipes[index].ID == arguments[2] {
			if selected != nil {
				return true, mcpFailure("recipe-invalid", "MCP launcher recipe is invalid")
			}
			selected = &recipes[index]
		}
	}
	if selected == nil || !filepath.IsAbs(selected.Executable) || len(selected.Arguments) > 128 {
		return true, mcpFailure("recipe-invalid", "MCP launcher recipe is invalid")
	}
	if selected.SessionHome != filepath.Clean(home) || len(selected.ExecutableWitness) == 0 {
		return true, mcpFailure("recipe-invalid", "MCP launcher recipe identity is invalid")
	}
	executable, witness, identity, digest, err := inspectExecutableGrant(selected.ExecutableLogicalPath)
	if err != nil || executable != selected.Executable || identity != selected.ExecutableIdentity.pathIdentity() || !equalPathWitness(witness, recipePathWitness(selected.ExecutableWitness)) || hex.EncodeToString(digest[:]) != selected.ExecutableSHA256 {
		if err != nil {
			if diagnostic := mcpPathOpenFailureDiagnostic(err, "executable"); diagnostic != nil {
				return true, diagnostic
			}
		}
		return true, mcpFailure("executable-identity", "MCP executable identity changed")
	}
	if selected.WorkspacePath != "" && !recipeWorkspaceIdentityMatches(selected.WorkspacePath, selected.WorkspaceCanonicalPath, selected.WorkspaceIdentity, selected.WorkspaceWitness) {
		return true, mcpFailure("workspace-identity", "MCP executable workspace identity changed")
	}
	argv := []string{executable}
	for _, argument := range selected.Arguments {
		switch argument.Kind {
		case "path":
			if !filepath.IsAbs(argument.Value) || argument.LogicalPath == "" {
				return true, mcpFailure("path-argument", "MCP path argument is invalid")
			}
			kind := PathTypeFile
			if os.FileMode(argument.Identity.Mode).IsDir() {
				kind = PathTypeDirectory
			}
			canonical, pathWitness, pathIdentityValue, pathErr := inspectGrantPath(argument.LogicalPath, kind, PathAccessReadOnly)
			if pathErr != nil || canonical != argument.Value || pathIdentityValue != argument.Identity.pathIdentity() || !equalPathWitness(pathWitness, recipePathWitness(argument.Witness)) {
				if pathErr != nil {
					if diagnostic := mcpPathOpenFailureDiagnostic(pathErr, "path"); diagnostic != nil {
						return true, diagnostic
					}
				}
				return true, mcpFailure("path-argument", "MCP path argument identity changed")
			}
			if argument.WorkspacePath != "" && !recipeWorkspaceIdentityMatches(argument.WorkspacePath, argument.WorkspaceCanonicalPath, argument.WorkspaceIdentity, argument.WorkspaceWitness) {
				return true, mcpFailure("workspace-identity", "MCP input workspace identity changed")
			}
			argv = append(argv, argument.Value)
		case "environment":
			if !environmentintent.ValidName(argument.Value) {
				return true, mcpFailure("selected-argument", "MCP environment argument is invalid")
			}
			value, ok := os.LookupEnv(argument.Value)
			if !ok {
				return true, mcpFailure("selected-argument", "MCP selected argument is unavailable")
			}
			argv = append(argv, value)
		default:
			return true, mcpFailure("recipe-invalid", "MCP argument recipe is invalid")
		}
	}
	// Recipe descriptors are closed before exec; stdin/stdout/stderr stay
	// attached so the target's MCP stdio protocol remains unchanged.
	if err := syscall.Exec(executable, argv, os.Environ()); err != nil {
		return true, mcpFailure("exec-failed", "MCP server could not be started")
	}
	return true, nil
}

type mcpHelperDiagnostic struct {
	category string
	message  string
}

func (diagnostic *mcpHelperDiagnostic) Error() string { return diagnostic.message }

func mcpFailure(category, message string) error {
	return &mcpHelperDiagnostic{category: category, message: message}
}

func mcpPathOpenFailureDiagnostic(err error, subject string) error {
	var failure *pathOpenFailure
	if !errors.As(err, &failure) {
		return nil
	}
	if subject != "path" && subject != "executable" {
		return mcpFailure("launch-failed", "MCP launcher failed")
	}
	stage := "other"
	switch failure.stage {
	case "root", "ancestor", "leaf", "logical-root", "logical-metadata", "logical-ancestor":
		stage = failure.stage
	}
	errnoName := "other"
	switch {
	case errors.Is(failure.cause, syscall.EACCES):
		errnoName = "eacces"
	case errors.Is(failure.cause, syscall.EPERM):
		errnoName = "eperm"
	case errors.Is(failure.cause, syscall.ENOENT):
		errnoName = "enoent"
	case errors.Is(failure.cause, syscall.ELOOP):
		errnoName = "eloop"
	case errors.Is(failure.cause, syscall.ENOTDIR):
		errnoName = "enotdir"
	}
	return mcpFailure(subject+"-open-"+stage+"-"+errnoName, "MCP "+subject+" traversal open failed")
}

// MCPHelperFailureCategory returns a stable, sanitized diagnostic label. It
// deliberately does not expose the underlying error, which could contain a
// path or another selected reference.
func MCPHelperFailureCategory(err error) string {
	if err == nil {
		return "unknown"
	}
	var diagnostic *mcpHelperDiagnostic
	if !errors.As(err, &diagnostic) {
		return "launch-failed"
	}
	return safeMCPHelperCategory(diagnostic.category)
}

func safeMCPHelperCategory(category string) string {
	switch category {
	case "invalid-invocation", "session-home-unavailable", "recipe-unavailable", "recipe-invalid", "executable-identity", "workspace-identity", "path-argument", "selected-argument", "exec-failed":
		return category
	}
	for _, subject := range []string{"path", "executable"} {
		for _, stage := range []string{"root", "ancestor", "leaf", "logical-root", "logical-metadata", "logical-ancestor", "other"} {
			for _, errnoName := range []string{"eacces", "eperm", "enoent", "eloop", "enotdir", "other"} {
				candidate := subject + "-open-" + stage + "-" + errnoName
				if category == candidate {
					return candidate
				}
			}
		}
	}
	return "launch-failed"
}

func decodeMCPRecipes(encoded []byte) ([]MCPRecipe, error) {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var recipes []MCPRecipe
	if err := decoder.Decode(&recipes); err != nil || recipes == nil || len(recipes) == 0 || len(recipes) > 128 {
		return nil, errors.New("MCP recipes are invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errors.New("MCP recipes contain trailing data")
	}
	canonical, err := json.Marshal(recipes)
	if err != nil || !bytes.Equal(append(canonical, '\n'), encoded) {
		return nil, errors.New("MCP recipes are not canonical")
	}
	seen := make(map[string]bool, len(recipes))
	for _, recipe := range recipes {
		if recipe.ID == "" || seen[recipe.ID] || len(recipe.Arguments) > 128 || len(recipe.EnvNames) > 128 || len(recipe.Disabled) > 256 {
			return nil, errors.New("MCP recipes contain invalid entries")
		}
		seen[recipe.ID] = true
	}
	return recipes, nil
}

func (identity MCPRecipeIdentity) pathIdentity() pathIdentity {
	return pathIdentity{device: identity.Device, inode: identity.Inode, mode: os.FileMode(identity.Mode), links: identity.Links, size: identity.Size, modifiedNanos: identity.Mtime}
}

func recipePathWitness(identities []MCPRecipeIdentity) []pathIdentity {
	result := make([]pathIdentity, len(identities))
	for index, identity := range identities {
		result[index] = identity.pathIdentity()
	}
	return result
}

func recipeWorkspaceIdentityMatches(logicalPath, canonicalPath string, expected MCPRecipeIdentity, expectedWitness []MCPRecipeIdentity) bool {
	canonical, witness, identity, err := inspectGrantPath(logicalPath, PathTypeDirectory, PathAccessReadOnly)
	return err == nil && canonical == canonicalPath && identity == expected.pathIdentity() && equalPathWitness(witness, recipePathWitness(expectedWitness))
}
