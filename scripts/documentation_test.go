package scripts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV020DocumentationUsesOneSupportAndInstallationContract(t *testing.T) {
	repository := filepath.Clean("..")
	documents := []string{
		"README.md",
		"CONTRIBUTING.md",
		"docs/architecture.md",
		"docs/releases/v0.2.0.md",
		"docs/releases/v0.2.0-checklist.md",
	}
	required := []string{
		"macOS 26",
		"Ubuntu 24.04 LTS",
		"darwin/arm64",
		"darwin/amd64",
		"linux/amd64",
		"linux/arm64",
	}

	for _, document := range documents {
		contents, err := os.ReadFile(filepath.Join(repository, document))
		if err != nil {
			t.Fatalf("read %s: %v", document, err)
		}
		text := string(contents)
		for _, term := range required {
			if !strings.Contains(text, term) {
				t.Errorf("%s does not name %s", document, term)
			}
		}
		for _, unsafe := range []string{"curl | sh", "curl|sh", "releases/latest"} {
			if strings.Contains(text, unsafe) {
				t.Errorf("%s presents unsafe or mutable installation text %q", document, unsafe)
			}
		}
	}
}

func TestV020ReleaseNotesMatchTagWorkflowPath(t *testing.T) {
	notes := filepath.Join("..", "docs", "releases", "v0.2.0.md")
	info, err := os.Stat(notes)
	if err != nil {
		t.Fatalf("stat release notes: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("v0.2.0 release notes are empty")
	}

	workflow, err := os.ReadFile(filepath.Join("..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	if !strings.Contains(string(workflow), `"docs/releases/$GITHUB_REF_NAME.md"`) {
		t.Fatal("release workflow no longer consumes version-controlled tag notes")
	}
}
