package devin

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func TestEditProfileDraftUsesRealCatalogAndTypedSkillsBinding(t *testing.T) {
	existingHome := t.TempDir()
	writeEditorSkill(t, existingHome, filepath.Join(".config", "devin", "skills", "review"))
	writeEditorSkill(t, existingHome, filepath.Join(".agents", "skills", "review"))
	adapter, err := New(Config{BinaryPath: "devin", ExistingHomeDir: existingHome})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	edited, err := adapter.EditProfileDraft(context.Background(), adapter.Categories().NewDraft(), strings.NewReader("2,1\n"), &output)
	if err != nil {
		t.Fatal(err)
	}
	references, err := category.Selection(edited, adapter.skillsCategory)
	if err != nil {
		t.Fatal(err)
	}
	want := []skills.SkillReference{
		{Source: GlobalSourceSharedAgents, RelativePath: "review"},
		{Source: GlobalSourceDevinConfig, RelativePath: "review"},
	}
	if !reflect.DeepEqual(references, want) {
		t.Fatalf("edited references = %#v, want %#v", references, want)
	}
	for _, detail := range []string{"review [devin-config]", "review [shared-agents]", "Enter comma-separated numbers"} {
		if !strings.Contains(output.String(), detail) {
			t.Errorf("editor output does not contain %q: %s", detail, output.String())
		}
	}
}

func TestEditProfileDraftEscapesCatalogTextAndRequiresEmptyConfirmation(t *testing.T) {
	existingHome := t.TempDir()
	writeEditorSkill(t, existingHome, filepath.Join(".config", "devin", "skills", "review\nforged\x1b[31m"))
	adapter, err := New(Config{BinaryPath: "devin", ExistingHomeDir: existingHome})
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err := adapter.EditProfileDraft(context.Background(), adapter.Categories().NewDraft(), strings.NewReader("\nn\n"), &output); err == nil || !strings.Contains(err.Error(), "not confirmed") {
		t.Fatalf("declined empty selection error = %v", err)
	}
	if strings.ContainsAny(output.String(), "\x1b") || strings.Contains(output.String(), "review\nforged") {
		t.Fatalf("editor emitted raw terminal control characters: %q", output.String())
	}
	for _, escaped := range []string{`review\nforged`, `\x1b[31m`, "Create an empty Profile?"} {
		if !strings.Contains(output.String(), escaped) {
			t.Errorf("editor output does not contain %q: %q", escaped, output.String())
		}
	}
}

func TestEditProfileDraftRejectsANumberOutsideTheDisplayedCatalog(t *testing.T) {
	adapter, err := New(Config{BinaryPath: "devin", ExistingHomeDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.EditProfileDraft(context.Background(), adapter.Categories().NewDraft(), strings.NewReader("1\n"), &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "not a displayed Skill Bundle number") {
		t.Fatalf("invalid selection error = %v", err)
	}
}

func writeEditorSkill(t *testing.T, existingHome, relativePath string) {
	t.Helper()
	bundlePath := filepath.Join(existingHome, relativePath)
	if err := os.MkdirAll(bundlePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundlePath, "SKILL.md"), []byte("# fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
