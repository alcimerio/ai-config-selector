package scripts

import (
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"unicode"
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
		if strings.HasPrefix(filepath.ToSlash(relative), "releases/") {
			return nil
		}
		if !strings.Contains(index, "("+filepath.ToSlash(relative)+")") {
			t.Errorf("docs/README.md does not link %s", relative)
		}
		// Every maintained guide/reference/development page provides a route
		// back to the hub. Release bodies are published verbatim on GitHub,
		// so their links deliberately remain absolute and version-pinned.
		if !strings.HasPrefix(filepath.ToSlash(relative), "releases/") {
			contents := readRepositoryFile(t, "..", filepath.Join("docs", relative))
			if !strings.Contains(contents, "[Documentation index](../README.md)") {
				t.Errorf("%s does not link back to the documentation index", relative)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(index, "(releases/)") {
		t.Fatal("documentation index must link the release-note history")
	}
}

// Other pages deep-link into README sections (for example docs/README.md and
// the getting-started guide link #install and #build-from-source). Renaming a
// README heading must not silently break those links, so every fragment that
// targets README.md, from any Markdown file, must match a README heading slug
// or an explicit HTML anchor. Fragments into other files are not checked.
func TestReadmeLinkFragmentsResolve(t *testing.T) {
	repository := ".."
	readmePath := filepath.Join(repository, "README.md")
	anchors := markdownAnchors(readRepositoryFile(t, repository, "README.md"))
	link := regexp.MustCompile(`\[[^\]\n]*\]\(([^)\s]+)\)`)
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
			if err != nil || target.IsAbs() || target.Host != "" || target.Fragment == "" {
				continue
			}
			resolved := path
			if target.Path != "" {
				resolved = filepath.Join(filepath.Dir(path), filepath.FromSlash(target.Path))
			}
			if filepath.Clean(resolved) != filepath.Clean(readmePath) {
				continue
			}
			if !anchors[strings.ToLower(target.Fragment)] {
				t.Errorf("%s: link %q targets a README section that does not exist", path, match[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// markdownAnchors approximates GitHub's heading slugs: lowercase, drop
// punctuation other than '-' and '_', turn spaces into '-', and suffix
// duplicates with -1, -2, ... Explicit id/name attributes also count.
func markdownAnchors(document string) map[string]bool {
	anchors := make(map[string]bool)
	counts := make(map[string]int)
	inFence := false
	for _, line := range strings.Split(document, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		heading := markdownHeading.FindStringSubmatch(line)
		if heading == nil {
			continue
		}
		var slug strings.Builder
		for _, r := range strings.ToLower(strings.TrimSpace(heading[1])) {
			switch {
			case r == ' ':
				slug.WriteRune('-')
			case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r):
				slug.WriteRune(r)
			}
		}
		base := slug.String()
		if n := counts[base]; n > 0 {
			anchors[fmt.Sprintf("%s-%d", base, n)] = true
		} else {
			anchors[base] = true
		}
		counts[base]++
	}
	for _, match := range htmlAnchor.FindAllStringSubmatch(document, -1) {
		anchors[strings.ToLower(match[1])] = true
	}
	return anchors
}

var (
	markdownHeading = regexp.MustCompile(`^#{1,6}\s+(.+?)\s*#*\s*$`)
	htmlAnchor      = regexp.MustCompile(`<a\s+(?:id|name)="([^"]+)"`)
)
