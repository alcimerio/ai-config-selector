package cli_test

import (
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestProfileExchangeCompositionDoesNotImportProviders(t *testing.T) {
	for _, name := range []string{"profile_exchange.go", "../commonprofile/registry.go", "../category/codec.go"} {
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"/adapter/", "/builder", "/executor", "/devinruntime", "/codexauth", "os/exec"} {
				if strings.Contains(path, forbidden) {
					t.Errorf("passive exchange composition imports provider/runtime dependency %q", path)
				}
			}
		}
	}
}
