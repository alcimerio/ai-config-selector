package builder

import (
	tea "charm.land/bubbletea/v2"

	"github.com/alcimerio/ai-config-selector/internal/category"
	"github.com/alcimerio/ai-config-selector/internal/commonprofile"
	"reflect"
	"testing"
)

func TestNetworkEditorAddsRejectsCancelsAndRemoves(t *testing.T) {
	binding, err := commonprofile.NewNetworkBinding()
	if err != nil {
		t.Fatal(err)
	}
	registry, err := category.NewRegistry("devin", binding.Registration())
	if err != nil {
		t.Fatal(err)
	}
	editor := networkEditor{draft: registry.NewDraft(), binding: binding}
	press := func(value string) {
		key := tea.Key{Code: []rune(value)[0], Text: value}
		switch value {
		case "enter":
			key.Code = tea.KeyEnter
		case "esc":
			key.Code = tea.KeyEsc
		case "backspace":
			key.Code = tea.KeyBackspace
		}
		model, _ := editor.Update(tea.KeyPressMsg(key))
		editor = model.(networkEditor)
	}
	add := func(value string) {
		press("a")
		for _, char := range value {
			press(string(char))
		}
		press("enter")
	}
	add("1455")
	selection, _ := category.Selection(editor.draft, binding)
	if !reflect.DeepEqual(selection.LoopbackPorts, []int{1455}) {
		t.Fatalf("ports=%v", selection.LoopbackPorts)
	}
	for _, bad := range []string{"0", "65536", "1455", ""} {
		add(bad)
		if editor.form == nil || editor.err == "" {
			t.Fatalf("accepted invalid port %q", bad)
		}
		press("esc")
		selection, _ := category.Selection(editor.draft, binding)
		if !reflect.DeepEqual(selection.LoopbackPorts, []int{1455}) {
			t.Fatal("invalid input/cancel changed draft")
		}
	}
	press("a")
	press("9")
	press("esc")
	press("d")
	selection, _ = category.Selection(editor.draft, binding)
	if len(selection.LoopbackPorts) != 0 {
		t.Fatal("remove failed")
	}
}
