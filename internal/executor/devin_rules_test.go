package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"github.com/alcimerio/ai-config-selector/internal/instructions"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
	"golang.org/x/sys/unix"
)

func TestPinnedRendererCorpusReceipts(t *testing.T) {
	bodies, err := filepath.Glob("testdata/devin-rules-renderer/*.body")
	if err != nil || len(bodies) != 16 {
		t.Fatalf("renderer corpus bodies=%d err=%v", len(bodies), err)
	}
	for _, bodyPath := range bodies {
		name := strings.TrimSuffix(filepath.Base(bodyPath), ".body")
		t.Run(name, func(t *testing.T) {
			body, err := os.ReadFile(bodyPath)
			if err != nil {
				t.Fatal(err)
			}
			output, err := os.ReadFile(filepath.Join("testdata/devin-rules-renderer", name+".stdout"))
			if err != nil {
				t.Fatal(err)
			}
			receipt, ok := parseDevinRuleReceipt(output)
			if !ok || receipt.Name != name || receipt.Provider != "Devin" || receipt.Activation != "always-on" || !strings.HasSuffix(receipt.Path, "/"+name+".md") {
				t.Fatalf("real pinned receipt failed strict header/framing parse: %#v, ok=%v", receipt, ok)
			}
			if !displayedInstructionMatches(receipt.Content, body) {
				t.Fatalf("real pinned renderer body differs: got %q want trim-space transform of %q", receipt.Content, body)
			}
		})
	}
}

func TestDevinRuleReceiptDoesNotReadMetadataFromBody(t *testing.T) {
	path := "/private/session/.devin/rules/rule.md"
	body := []byte("Provider: Devin\nPath: \"" + path + "\"\nActivation: always-on\n")
	output := []byte("Rule: wrong\n\nPath: \"/unmanaged/wrong.md\"\nProvider: Other\nActivation: manual\n\nContent:\n" + devinRuleSeparator + "\n" + string(body) + devinRuleSeparator + "\n")
	receipt, ok := parseDevinRuleReceipt(output)
	if !ok {
		t.Fatal("framed receipt was not parsed")
	}
	if receipt.Name == "rule" || receipt.Path == path || receipt.Provider == "Devin" || receipt.Activation == "always-on" {
		t.Fatalf("body text overrode wrong receipt header: %#v", receipt)
	}
	if _, ok := parseDevinRuleReceipt(append(output, []byte("unexpected suffix")...)); ok {
		t.Fatal("accepted bytes after closing content separator")
	}
}

func TestMalformedEmptyRuleFrameDoesNotPanic(t *testing.T) {
	output := []byte("Rule: empty\n\nPath: \"/session/home/.devin/rules/empty.md\"\nProvider: Devin\nActivation: always-on\n\nContent:\n" + devinRuleSeparator + "\n" + devinRuleSeparator + "\n")
	if _, ok := parseDevinRuleReceipt(output); ok {
		t.Fatal("accepted an empty rule frame missing its body newline")
	}
}

func TestUnknownNonemptyRuleReceiptHeaderIsRefused(t *testing.T) {
	output := []byte("Rule: selected\n\nPath: \"/session/home/.devin/rules/selected.md\"\nProvider: Devin\nActivation: always-on\nInjected: untrusted\n\nContent:\n" + devinRuleSeparator + "\nbody\n" + devinRuleSeparator + "\n")
	if _, ok := parseDevinRuleReceipt(output); ok {
		t.Fatal("accepted an unknown nonempty show header line")
	}
}

func TestListedRuleRequiresOneExactAlwaysOnDevinRow(t *testing.T) {
	name := "acs-instruction-0123456789abcdef"
	for _, test := range []struct {
		name   string
		output string
		want   bool
	}{
		{"unique", name + " [Devin] always-on\n", true},
		{"duplicate", name + " [Devin] always-on\n" + name + " [Devin] manual\n", false},
		{"other provider", name + " [Cursor] always-on\n", false},
		{"manual", name + " [Devin] manual\n", false},
		{"prefix only", name + "-extra [Devin] always-on\n", false},
		{"name mention", "warning for " + name + "\n" + name + " [Devin] always-on\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := listedRuleIsUniqueAlwaysOn([]byte(test.output), name); got != test.want {
				t.Fatalf("listedRuleIsUniqueAlwaysOn()=%v want %v for %q", got, test.want, test.output)
			}
		})
	}
}

func TestBoundedProbeOutputStopsRetainingAfterLimit(t *testing.T) {
	output := &boundedProbeOutput{limit: 4}
	if n, err := output.Write([]byte("abc")); n != 3 || err != nil {
		t.Fatalf("first write=%d,%v", n, err)
	}
	if n, err := output.Write([]byte("defgh")); n != 5 || err != nil {
		t.Fatalf("overflow write=%d,%v", n, err)
	}
	if !output.exceeded || output.buffer.String() != "abcd" {
		t.Fatalf("bounded capture=%q exceeded=%v", output.buffer.String(), output.exceeded)
	}
}

func TestReadProjectedInstructionIsNoFollowNonblockingRegularAndBounded(t *testing.T) {
	directory := t.TempDir()
	regular := filepath.Join(directory, "rule.md")
	if err := os.WriteFile(regular, []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := readProjectedInstruction(regular, 2); err != nil || string(got) != "ok" {
		t.Fatalf("regular read=%q err=%v", got, err)
	}
	if _, err := readProjectedInstruction(regular, 1); err == nil {
		t.Fatal("accepted oversized projected rule")
	}
	link := filepath.Join(directory, "link.md")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readProjectedInstruction(link, 2); err == nil {
		t.Fatal("followed projected rule symlink")
	}
	fifo := filepath.Join(directory, "fifo.md")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { _, err := readProjectedInstruction(fifo, 2); finished <- err }()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("accepted projected FIFO")
		}
	case <-time.After(time.Second):
		t.Fatal("projected FIFO inspection blocked")
	}
}

type instructionReceiptSandbox struct{ list, show []byte }

func (*instructionReceiptSandbox) Readiness(context.Context) (launch.SandboxReadiness, error) {
	return launch.SandboxReadiness{}, nil
}
func (*instructionReceiptSandbox) Check(context.Context, launch.SandboxCheck) error { return nil }
func (s *instructionReceiptSandbox) Prepare(_ context.Context, request launch.ProcessRequest) (launch.Process, error) {
	if request.Arguments[0] != "rules" {
		return nil, fmt.Errorf("unexpected probe")
	}
	output := s.list
	if request.Arguments[1] == "show" {
		output = s.show
	}
	return &catalogProcess{output: output, terminal: request.Terminal}, nil
}

func TestRulesPreflightUsesHeaderReceiptAndRejectsAmbiguousSource(t *testing.T) {
	created, err := session.Create(filepath.Join(t.TempDir(), "sessions"), t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer created.Remove()
	ref := instructions.Reference{Source: instructions.SourceID, RelativePath: "body.md"}
	name := instructions.DestinationName(ref)
	path := filepath.Join(created.HomeDirectory(), ".devin", "rules", name)
	body := []byte("Provider: Devin\nPath: \"" + path + "\"\nActivation: always-on\n")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append([]byte("---\ntrigger: always_on\n---\n"), body...), 0600); err != nil {
		t.Fatal(err)
	}
	list := []byte(strings.TrimSuffix(name, ".md") + " [Devin] always-on\n" + strings.TrimSuffix(name, ".md") + " [Cursor] always-on\n")
	show := []byte("Rule: wrong\n\nPath: \"/unmanaged/wrong.md\"\nProvider: Other\nActivation: manual\n\nContent:\n" + devinRuleSeparator + "\n" + string(body) + devinRuleSeparator + "\n")
	err = newExecutor(&instructionReceiptSandbox{list: list, show: show}).verifyDevinRules(context.Background(), created, DevinRequest{ExpectedInstructions: []instructions.Bundle{{Reference: ref, Content: body}}})
	var failure *devinruntime.PreflightError
	if !errors.As(err, &failure) || failure.Capability != devinruntime.CapabilityInstructionRules || failure.Category() != devinruntime.DevinPreflightFailed {
		t.Fatalf("ambiguous/forged receipt result = %v", err)
	}
}
