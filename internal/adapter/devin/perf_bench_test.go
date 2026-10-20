package devin_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/adapter/devin"
	"github.com/alcimerio/ai-config-selector/internal/profile"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func BenchmarkProfileLoadResolveExplain(b *testing.B) {
	home := b.TempDir()
	bundle := filepath.Join(home, ".config", "devin", "skills", "review")
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "SKILL.md"), []byte("# review\n"), 0o600); err != nil {
		b.Fatal(err)
	}
	adapter, err := devin.New(devin.Config{BinaryPath: "devin", ExistingHomeDir: home})
	if err != nil {
		b.Fatal(err)
	}
	acsHome := filepath.Join(home, ".acs")
	if err := os.MkdirAll(filepath.Join(acsHome, "profiles"), 0o700); err != nil {
		b.Fatal(err)
	}
	store := profile.NewStore(acsHome, adapter.Categories())
	if _, err := store.Create(devin.NewSkillsProfile("reviews", []skills.SkillReference{{
		Source: devin.GlobalSourceDevinConfig, RelativePath: "review",
	}})); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		loaded, err := store.Load("reviews")
		if err != nil {
			b.Fatal(err)
		}
		resolved, err := adapter.Categories().ResolveFor(context.Background(), loaded, "devin")
		if err != nil {
			b.Fatal(err)
		}
		if resolved.Explanation().AuthorityDigest == "" {
			b.Fatal("missing explanation digest")
		}
	}
}
