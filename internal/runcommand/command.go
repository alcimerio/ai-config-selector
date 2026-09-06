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
	workspace, err := canonicalDirectory(workingDirectory)
	if err != nil {
		return Command{}, errors.New("working directory is unavailable")
	}
	executable, form, err := resolveExecutable(workspace, argv[0])
	if err != nil {
		return Command{}, err
	}
	info, digest, err := executableSnapshot(executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return Command{}, errors.New("executable is unavailable")
	}
	return Command{intent: argv[0], executable: executable, workspace: workspace,
		arguments: append([]string(nil), argv[1:]...), form: form, identity: info, digest: digest}, nil
}

// Revalidate repeats resolution immediately before native preparation.
func (command Command) Revalidate(workingDirectory string) (string, []string, error) {
	workspace, err := canonicalDirectory(workingDirectory)
	if err != nil || workspace != command.workspace {
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

func canonicalDirectory(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("path must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("path is not a directory")
	}
	return resolved, nil
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

func executableSnapshot(path string) (os.FileInfo, [sha256.Size]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], hash.Sum(nil))
	return info, digest, nil
}
