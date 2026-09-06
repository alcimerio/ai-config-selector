// Package runcommand resolves and preserves one explicit generic command
// intent. Resolution never consults the invoking process PATH.
package runcommand

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const FixedSearchPath = "/usr/local/bin:/usr/bin:/bin"

type Form string

const (
	BareName          Form = "bare name through the fixed ACS search path"
	AbsolutePath      Form = "absolute path (hidden)"
	WorkspaceRelative Form = "workspace-relative ./ path (hidden)"
)

// Command is an immutable resolved executable identity and literal argv.
// Its fields are private so callers cannot forge a successful revalidation.
type Command struct {
	intent, executable, workspace string
	arguments                     []string
	form                          Form
	identity                      os.FileInfo
	workspaceIdentity             os.FileInfo
	digest                        [sha256.Size]byte
}

// ValidateSyntax rejects command forms before filesystem discovery.
func ValidateSyntax(argv []string) error {
	if len(argv) == 0 || argv[0] == "" || argv[0] == "--" {
		return errors.New("missing command after --")
	}
	for _, value := range argv {
		if strings.IndexByte(value, 0) >= 0 {
			return errors.New("command contains NUL")
		}
	}
	executable := argv[0]
	if strings.ContainsRune(executable, filepath.Separator) &&
		!filepath.IsAbs(executable) && !strings.HasPrefix(executable, "."+string(filepath.Separator)) {
		return errors.New("relative executable paths must begin with ./")
	}
	return nil
}

// Resolve validates one command against the current canonical workspace and
// captures enough file identity to detect ordinary path/symlink replacement.
func Resolve(workingDirectory string, argv []string) (Command, error) {
	if err := ValidateSyntax(argv); err != nil {
		return Command{}, err
	}
	workspace, workspaceIdentity, err := canonicalDirectory(workingDirectory)
	if err != nil {
		return Command{}, errors.New("working directory is unavailable")
	}
	executable, form, err := resolveExecutable(workspace, argv[0])
	if err != nil {
		return Command{}, err
	}
	info, digest, err := executableSnapshot(executable)
	if err != nil {
		return Command{}, errors.New("executable is unavailable")
	}
	return Command{intent: argv[0], executable: executable, workspace: workspace,
		arguments: append([]string(nil), argv[1:]...), form: form, identity: info,
		workspaceIdentity: workspaceIdentity, digest: digest}, nil
}

// Revalidate repeats resolution immediately before native preparation.
func (command Command) Revalidate(workingDirectory string) (string, []string, error) {
	workspace, workspaceIdentity, err := canonicalDirectory(workingDirectory)
	if err != nil || workspace != command.workspace || !sameWorkspaceIdentity(command.workspaceIdentity, workspaceIdentity) {
		return "", nil, errors.New("working directory changed after command resolution")
	}
	executable, form, err := resolveExecutable(workspace, command.intent)
	if err != nil || executable != command.executable || form != command.form {
		return "", nil, errors.New("executable path changed after command resolution")
	}
	info, digest, err := executableSnapshot(executable)
	if err != nil || !sameIdentity(command.identity, info) || digest != command.digest {
		return "", nil, errors.New("executable identity changed after command resolution")
	}
	return executable, append([]string(nil), command.arguments...), nil
}

func (command Command) Form() Form         { return command.form }
func (command Command) ArgumentCount() int { return len(command.arguments) }

func canonicalDirectory(path string) (string, os.FileInfo, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", nil, errors.New("path must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", nil, err
	}
	file, err := openPath(resolved, unix.O_DIRECTORY)
	if err != nil {
		return "", nil, errors.New("path is not a directory")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		return "", nil, errors.New("path is not a directory")
	}
	return resolved, info, nil
}

func resolveExecutable(workspace, intent string) (string, Form, error) {
	var candidate string
	form := BareName
	switch {
	case filepath.IsAbs(intent):
		candidate, form = filepath.Clean(intent), AbsolutePath
	case strings.HasPrefix(intent, "."+string(filepath.Separator)):
		candidate, form = filepath.Join(workspace, intent), WorkspaceRelative
	default:
		for _, directory := range strings.Split(FixedSearchPath, string(os.PathListSeparator)) {
			path := filepath.Join(directory, intent)
			if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
				candidate = path
				break
			}
		}
		if candidate == "" {
			return "", "", errors.New("executable was not found in the fixed ACS search path")
		}
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", "", errors.New("executable is unavailable")
	}
	if form == WorkspaceRelative && !withinOrEqual(workspace, resolved) {
		return "", "", errors.New("workspace-relative executable resolves outside the workspace")
	}
	return resolved, form, nil
}

func withinOrEqual(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func sameIdentity(before, after os.FileInfo) bool {
	return before != nil && after != nil && os.SameFile(before, after) && before.Mode() == after.Mode() &&
		before.Size() == after.Size() && before.ModTime().Equal(after.ModTime())
}

func sameWorkspaceIdentity(before, after os.FileInfo) bool {
	return before != nil && after != nil && before.IsDir() && after.IsDir() && os.SameFile(before, after)
}

func executableSnapshot(path string) (os.FileInfo, [sha256.Size]byte, error) {
	file, err := openPath(path, 0)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, [sha256.Size]byte{}, errors.New("path is not an executable regular file")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return info, digest, nil
}

func openPath(path string, flags int) (*os.File, error) {
	descriptor, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW|flags, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(descriptor), path), nil
}
