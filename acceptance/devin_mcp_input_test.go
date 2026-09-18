package acceptance_test

import (
	"bytes"
	"errors"
	"strings"
	"unicode/utf8"
)

// Stages advance before attempting a write, so an incomplete write cannot retry.
// A completed Enter still awaits an independently accepted model request.
type devinInputProgress struct{ stage, prompt string }

func (p *devinInputProgress) prepare(f devinInputFrame, b []byte) error {
	switch p.stage {
	case "paste":
		if !devinInitialPrompt(f) || len(b) > 512 || !bytes.HasPrefix(b, []byte("\x1b[200~")) || !bytes.HasSuffix(b, []byte("\x1b[201~")) {
			return errors.New("unobserved paste payload/frame")
		}
		text := string(b[6 : len(b)-6])
		if len(text) == 0 {
			return errors.New("empty prompt")
		}
		for _, r := range text {
			if r < 32 || r > 126 {
				return errors.New("prompt must be fixed printable ASCII")
			}
		}
		p.prompt = text
		p.stage = "submit"
	case "submit":
		if !bytes.Equal(b, []byte{'\r'}) || !devinRenderedPrompt(f, p.prompt) {
			return errors.New("Enter without current exact rendered prompt")
		}
		p.stage = "await-request"
	case "approval":
		if !f.Raw || !f.BracketedPaste || !f.ApprovalOnce || !bytes.Equal(b, []byte{13}) {
			return errors.New("approval requires exact selected once menu and one Enter")
		}
		p.stage = "await-result"
	case "exit":
		if !bytes.Equal(b, []byte{4}) || !devinExitReady(f) {
			return errors.New("exit requires observed empty idle and one Ctrl+D")
		}
		p.stage = "finished"
	default:
		return errors.New("application input in inactive stage")
	}
	return nil
}
func (p *devinInputProgress) observedModel(models, writes int) error {
	if models < 0 || writes < 0 || writes > models {
		return errors.New("invalid model progress")
	}
	if models > 0 && (p.stage == "paste" || p.stage == "submit") {
		return errors.New("model preceded separate Enter")
	}
	if p.stage == "await-request" && models >= 1 && writes >= 1 {
		p.stage = "approval"
	}
	return nil
}
func devinRenderedPrompt(f devinInputFrame, prompt string) bool {
	if !f.Raw || !f.TypedStyles || !f.BracketedPaste || f.Row < 2 || f.Row >= 39 || len(f.Lines) != 40 {
		return false
	}
	first, last := f.Lines[f.Row-1], f.Lines[f.Row]
	return strings.HasPrefix(first, "❭ ") && strings.HasPrefix(last, "  ") && f.Column == utf8.RuneCountInString(last) && f.Lines[f.Row-2] == strings.Repeat("─", 120) && f.Lines[f.Row+1] == strings.Repeat("─", 120) && strings.TrimPrefix(first, "❭ ")+" "+strings.TrimPrefix(last, "  ") == prompt
}

const devinNativePrompt = "List MCP servers and tools. Use mcp_call_tool once with server_name fixture, tool_name acs_allowed_echo, arguments {}, then respond READY. Do not use any other tool."

func devinExitReady(f devinInputFrame) bool {
	return devinInitialPrompt(f) && f.Row >= 3 && f.Lines[f.Row-3] == " READY"
}
func devinNativeInput(f devinInputFrame, stage string) ([]byte, error) {
	switch stage {
	case "paste":
		if devinInitialPrompt(f) {
			return []byte("\x1b[200~" + devinNativePrompt + "\x1b[201~"), nil
		}
	case "submit":
		if devinRenderedPrompt(f, devinNativePrompt) {
			return []byte{13}, nil
		}
	case "approval":
		if f.Raw && f.BracketedPaste && f.ApprovalOnce {
			return []byte{13}, nil
		}
	case "exit":
		if devinExitReady(f) {
			return []byte{4}, nil
		}
	default:
		return nil, errors.New("unexpected native input stage")
	}
	return nil, nil
}
