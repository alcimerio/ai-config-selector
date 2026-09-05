package diagnostics

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Guard the narrow production entry points against accidentally replacing native
// metadata with the similarly named active launch platform/readiness helpers.
func TestPassiveEntryPointsHaveNoActiveOperations(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	files = append(files, "../adapter/devin/catalog.go", "../cli/diagnostics.go")
	forbidden := map[string]bool{"CurrentPlatform": true, "Readiness": true, "Check": true, "PlanLaunch": true, "Plan": true, "Launch": true, "Login": true, "Recover": true, "Chmod": true, "Mkdir": true, "MkdirAll": true, "WriteFile": true, "Create": true, "Start": true, "Command": true, "CommandContext": true, "IsTerminal": true}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range file.Imports {
			name, _ := strconv.Unquote(imp.Path.Value)
			if name == "os/exec" || strings.Contains(name, "/codexauth") || strings.Contains(name, "/session") {
				t.Errorf("active dependency in %s: %s", path, name)
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			if selector, ok := n.(*ast.SelectorExpr); ok && forbidden[selector.Sel.Name] {
				t.Errorf("active operation %s in %s", selector.Sel.Name, path)
			}
			return true
		})
	}
}
