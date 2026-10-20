package skillcatalog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
)

func BenchmarkDiscoverReport(b *testing.B) {
	home := b.TempDir()
	for _, rule := range devinruntime.GlobalSourceRules() {
		root := filepath.Join(home, rule.RelativeDirectory)
		for index := 0; index < 100; index++ {
			bundle := filepath.Join(root, fmt.Sprintf("skill-%s-%d", rule.Source, index))
			if err := os.MkdirAll(bundle, 0o700); err != nil {
				b.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(bundle, "SKILL.md"), []byte("# skill\n"), 0o600); err != nil {
				b.Fatal(err)
			}
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for index := 0; index < b.N; index++ {
		found, err := DiscoverReport(context.Background(), home, nil, nil)
		if err != nil || len(found) != 200 {
			b.Fatalf("discover: %v count=%d", err, len(found))
		}
	}
}
