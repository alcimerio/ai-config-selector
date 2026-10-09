package launch

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/alcimerio/ai-config-selector/internal/exclusionintent"
)

// PathExclusionIntent describes a pathname denial, independently of grants.
type PathExclusionIntent struct {
	ID            string
	Type          PathType
	ReferenceKind PathReferenceKind
	Path          string
}

// FilesystemExclusion keeps captured paths and identities private to launch.
// The parent of an absent leaf is captured so missing ancestors cannot redirect
// a later creation. Both logical and canonical names remain denied.
type FilesystemExclusion struct {
	ID                string
	path, logicalPath string
	witness           FilesystemGrant
	exists            bool
}

func ResolveFilesystemExclusions(intents []PathExclusionIntent, workspace, sessions string) (resolved []FilesystemExclusion, failure error) {
	defer func() {
		if failure != nil {
			failure = sandboxError(SandboxUnsafePath, failure)
		}
	}()
	selection := exclusionintent.Empty()
	for _, intent := range intents {
		selection.Entries = append(selection.Entries, exclusionintent.Entry{ID: intent.ID, Type: exclusionintent.Type(intent.Type), Reference: exclusionintent.Reference{Kind: string(intent.ReferenceKind), Path: intent.Path}})
	}
	canonicalIntent, err := exclusionintent.Canonical(selection)
	if err != nil {
		return nil, err
	}
	if len(canonicalIntent.Entries) == 0 {
		return nil, nil
	}
	workspacePath, workspaceWitness, workspaceIdentity, err := inspectGrantPath(filepath.Clean(workspace), PathTypeDirectory, PathAccessReadOnly)
	if err != nil {
		return nil, errors.New("exclusion workspace is unsafe")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, errors.New("user home is unavailable")
	}
	home, err = filepath.EvalSymlinks(home)
	if err != nil {
		return nil, errors.New("user home is unavailable")
	}
	private, err := resolveFuturePath(sessions)
	if err != nil {
		return nil, err
	}
	result := make([]FilesystemExclusion, 0, len(intents))
	for _, entry := range canonicalIntent.Entries {
		logical := entry.Reference.Path
		if entry.Reference.Kind == string(PathReferenceWorkspaceRelative) {
			logical = filepath.Join(workspacePath, filepath.FromSlash(logical))
		}
		kind := PathType(entry.Type)
		captured := logical
		exists := true
		if _, err := os.Lstat(logical); errors.Is(err, os.ErrNotExist) {
			exists = false
			captured = filepath.Dir(logical)
			kind = PathTypeDirectory
		} else if err != nil {
			return nil, exclusionFailure(entry.ID, "path is unavailable")
		}
		canonical, witness, identity, err := inspectGrantPath(captured, kind, PathAccessReadOnly)
		if err != nil {
			return nil, exclusionFailure(entry.ID, "path has missing ancestors, an unsafe link, or the wrong type")
		}
		path := canonical
		if !exists {
			path = filepath.Join(canonical, filepath.Base(logical))
		}
		if entry.Reference.Kind == string(PathReferenceWorkspaceRelative) && !withinOrEqual(workspacePath, path) {
			return nil, exclusionFailure(entry.ID, "path escapes its workspace")
		}
		if entry.Reference.Kind == string(PathReferenceLocalAbsolute) && !supportedLocalGrantRoot(home, path) {
			return nil, exclusionFailure(entry.ID, "local path is outside supported roots")
		}
		if pathsOverlap(path, private) || pathsOverlap(path, SessionOperationsDirectory(private)) {
			return nil, exclusionFailure(entry.ID, "path conflicts with required Session state")
		}
		grant := FilesystemGrant{Type: kind, Access: PathAccessReadOnly, logicalPath: captured, logicalWitness: witness, path: canonical, identity: identity}
		if entry.Reference.Kind == string(PathReferenceWorkspaceRelative) {
			grant.workspaceRelative = true
			grant.workspaceLogicalPath = filepath.Clean(workspace)
			grant.workspaceLogicalWitness = append([]pathIdentity(nil), workspaceWitness...)
			grant.workspacePath = workspacePath
			grant.workspaceIdentity = workspaceIdentity
		}
		result = append(result, FilesystemExclusion{ID: entry.ID, path: path, logicalPath: logical, witness: grant, exists: exists})
	}
	return result, nil
}

type exclusionError struct{ id, reason string }

func (e *exclusionError) Error() string        { return fmt.Sprintf("excluded path %q: %s", e.id, e.reason) }
func exclusionFailure(id, reason string) error { return &exclusionError{id: id, reason: reason} }

func revalidateFilesystemExclusions(exclusions []FilesystemExclusion, workspace, sessions string) ([]FilesystemExclusion, error) {
	result := append([]FilesystemExclusion(nil), exclusions...)
	for _, entry := range result {
		if entry.path == "" || entry.logicalPath == "" {
			return nil, errors.New("invalid exclusion witness")
		}
		if _, err := revalidateFilesystemGrants([]FilesystemGrant{entry.witness}, workspace, sessions); err != nil {
			return nil, exclusionFailure(entry.ID, "captured path identity changed")
		}
		if !entry.exists {
			// A host creation between capture and Start invalidates the capture. Once
			// started, the fixed literal/subtree policy denies target-side creation.
			if _, err := os.Lstat(entry.logicalPath); !errors.Is(err, os.ErrNotExist) {
				return nil, exclusionFailure(entry.ID, "absent path changed before startup")
			}
		}
	}
	return result, nil
}

// ValidateExclusionSources rejects copied material on either side of a denial.
// A whole bundle cannot be copied when it contains an excluded descendant.
func ValidateExclusionSources(exclusions []FilesystemExclusion, sources []string) error {
	if len(exclusions) == 0 {
		return nil
	}
	for _, source := range sources {
		if source == "" {
			continue
		}
		canonical, err := filepath.EvalSymlinks(source)
		if err != nil {
			return sandboxError(SandboxUnsafePath, nil)
		}
		for _, entry := range exclusions {
			if pathsOverlap(entry.path, canonical) || pathsOverlap(entry.logicalPath, filepath.Clean(source)) {
				return sandboxError(SandboxUnsafePath, exclusionFailure(entry.ID, "conflicts with selected material; remove the selection or exclusion"))
			}
		}
	}
	return nil
}

func validateExclusionRequirements(exclusions []FilesystemExclusion, grants []FilesystemGrant, executables []ExecutableGrant, required []string) error {
	for _, entry := range exclusions {
		for _, grant := range grants {
			if withinOrEqual(entry.path, grant.path) {
				return exclusionFailure(entry.ID, "conflicts with selected path grant "+grant.ID)
			}
		}
		for _, grant := range executables {
			if pathsOverlap(entry.path, grant.path) {
				return exclusionFailure(entry.ID, "conflicts with selected executable "+grant.ID)
			}
		}
		for _, path := range required {
			if pathsOverlap(entry.path, path) {
				return exclusionFailure(entry.ID, "conflicts with a required runtime input")
			}
		}
	}
	return nil
}

// PathExcluded is an owner-side planning observation. It exposes no captured
// pathname and does not replace native enforcement or revalidation.
func PathExcluded(exclusions []FilesystemExclusion, candidate string) bool {
	canonical, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return false
	}
	for _, entry := range exclusions {
		if withinOrEqual(entry.path, canonical) || withinOrEqual(entry.logicalPath, filepath.Clean(candidate)) {
			return true
		}
	}
	return false
}
