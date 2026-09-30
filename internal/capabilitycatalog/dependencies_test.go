package capabilitycatalog_test

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCatalogHasNoProductionDependencies(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			t.Errorf("structural catalog must remain dependency-free: %s imports %s", path, imp.Path.Value)
		}
	}
}

func TestConsumersDependDirectlyOnNeutralCatalog(t *testing.T) {
	const prefix = "github.com/alcimerio/ai-config-selector/internal/"
	for _, consumer := range []string{"category", "profileinspect", "profileexchange"} {
		t.Run(consumer, func(t *testing.T) {
			files, err := filepath.Glob(filepath.Join("..", consumer, "*.go"))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, path := range files {
				if strings.HasSuffix(path, "_test.go") {
					continue
				}
				file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
				if err != nil {
					t.Fatal(err)
				}
				for _, imp := range file.Imports {
					name, err := strconv.Unquote(imp.Path.Value)
					if err != nil {
						t.Fatal(err)
					}
					found = found || name == prefix+"capabilitycatalog"
					// Registry's named decode still intentionally uses strict
					// inspection; exchange only needs the structural catalog.
					if consumer == "profileexchange" && name == prefix+"profileinspect" {
						t.Errorf("exchange must not obtain structural metadata from inspection: %s", path)
					}
				}
			}
			if !found {
				t.Fatal("consumer does not depend on the neutral capability catalog")
			}
		})
	}
}
