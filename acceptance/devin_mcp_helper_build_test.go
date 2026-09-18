//go:build darwin || linux

package acceptance_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func buildDevinResearchHelper(t *testing.T, relative, destination string, values map[string]string) {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	packagePath := filepath.Join(filepath.Dir(source), "testdata", relative)
	args := []string{"build", "-trimpath", "-o", destination}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	flags, err := goLinkerFlags(values, keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(flags) > 0 {
		args = append(args, "-ldflags", strings.Join(flags, " "))
	}
	args = append(args, packagePath)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...)
	output, err := cmd.CombinedOutput()
	if err != nil || ctx.Err() != nil {
		t.Fatalf("build isolated Devin helper: %v: %.4096s", err, output)
	}
}

func goLinkerFlags(values map[string]string, keys []string) ([]string, error) {
	flags := make([]string, 0, len(keys))
	for _, key := range keys {
		value := values[key]
		operand := "main." + key + "=" + value
		if strings.ContainsAny(value, " \t\r\n") {
			switch {
			case !strings.Contains(operand, "'"):
				operand = "'" + operand + "'"
			case !strings.Contains(operand, `"`):
				operand = `"` + operand + `"`
			default:
				return nil, fmt.Errorf("unsupported Go linker value for %s: both quote delimiters and whitespace", key)
			}
		}
		// Go's quoted.Split grammar requires the -X flag and its quoted
		// operand to be separate tokens. Quoting the complete -X token makes
		// cmd/go treat the leading quote as a package pattern.
		flags = append(flags, "-X "+operand)
	}
	return flags, nil
}

func TestBuildDevinResearchHelpersAcceptGoLinkerQuotedValues(t *testing.T) {
	for _, relative := range []string{"devin-native-mcp-server", "devin-trampoline"} {
		t.Run(relative, func(t *testing.T) {
			values := map[string]string{}
			if relative == "devin-native-mcp-server" {
				values = map[string]string{
					"forbiddenPath": filepath.Join(t.TempDir(), `ordinary path with spaces`),
					"evidenceBase":  filepath.Join(t.TempDir(), `evidence path with spaces`),
				}
			} else {
				values = map[string]string{
					"endpoint":     `http://127.0.0.1:1234/path?q=space value`,
					"coordination": filepath.Join(t.TempDir(), `coordination path with spaces`),
					"target":       filepath.Join(t.TempDir(), `target path with spaces`),
					"memberDigest": "deadbeef",
				}
			}
			output := filepath.Join(t.TempDir(), "helper")
			buildDevinResearchHelper(t, relative, output, values)
			if _, err := os.Stat(output); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGoLinkerFlagsRejectUnsupportedQuoteValues(t *testing.T) {
	keys := []string{"value"}
	for _, value := range []string{`contains'" quote`, `contains'"\path with spaces`} {
		if _, err := goLinkerFlags(map[string]string{"value": value}, keys); err == nil {
			t.Fatalf("accepted unsupported linker value %q", value)
		}
	}
}

func TestGoLinkerFlagsRuntimeProbePreservesRepresentableValues(t *testing.T) {
	values := map[string]string{"first": `single' quote \path with spaces`, "second": "double\" quote \\path with spaces"}
	output := filepath.Join(t.TempDir(), "probe")
	buildDevinResearchHelper(t, "devin-linker-probe", output, values)
	encoded, err := exec.Command(output, "--print").Output()
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]string
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	for key, want := range values {
		if got[key] != want {
			t.Fatalf("runtime linker value %s=%q want %q", key, got[key], want)
		}
	}
}
