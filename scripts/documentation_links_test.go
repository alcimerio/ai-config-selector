package scripts

import (
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Keep the newcomer navigation and ordinary relative Markdown links usable.
// This is intentionally an offline path check, not a remote-link, rendered
// Markdown, or heading-fragment validator.
func TestDocumentationRelativeLinks(t *testing.T) {
	repository := ".."
	link := regexp.MustCompile(`\[[^\]\n]+\]\(([^)\s]+)\)`)
	err := filepath.WalkDir(repository, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".md" {
			return nil
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, match := range link.FindAllStringSubmatch(string(contents), -1) {
			target, err := url.Parse(match[1])
			if err != nil {
				t.Errorf("%s: malformed link %q: %v", path, match[1], err)
				continue
			}
			if target.IsAbs() || target.Host != "" || target.Path == "" {
				continue
			}
			resolved := filepath.Join(filepath.Dir(path), filepath.FromSlash(target.Path))
			if _, err := os.Stat(resolved); err != nil {
				t.Errorf("%s: broken relative link %q: %v", path, match[1], err)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestDocumentationIndexCoversMaintainedGuides(t *testing.T) {
	index := readRepositoryFile(t, "..", "docs/README.md")
	err := filepath.WalkDir("../docs", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".md" || path == "../docs/README.md" {
			return nil
		}
		relative, err := filepath.Rel("../docs", path)
		if err != nil {
			return err
		}
		if !strings.Contains(index, "("+filepath.ToSlash(relative)+")") {
			t.Errorf("docs/README.md does not link %s", relative)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, guide := range []string{"docs/getting-started.md", "docs/README.md", "docs/security-model.md", "CONTRIBUTING.md"} {
		if !strings.Contains(readRepositoryFile(t, "..", "README.md"), "("+guide+")") {
			t.Errorf("README.md does not link newcomer entry point %s", guide)
		}
	}
}

// Keep the README focused on first use; upgrade safety stays in the executable
// examples exercised by TestManualUpgradeExamples.
func TestReadmeRoutesExistingInstallsToRecoveryGuide(t *testing.T) {
	readme := readRepositoryFile(t, "..", "README.md")
	if !strings.Contains(readme, "[upgrade and recovery guide](docs/manual-upgrade-recovery.md)") {
		t.Fatal("README must route existing installs to the tested recovery procedure")
	}
	if strings.Contains(readme, "published-v050-bootstrap-example") {
		t.Fatal("README duplicates the recovery guide's bootstrap procedure")
	}
}
