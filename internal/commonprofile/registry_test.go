package commonprofile

import (
	"context"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/instructions"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func TestSharedBindingsRequireExplicitRuntimeDependencies(t *testing.T) {
	valid := Runtime{
		DiscoverSkills: func(context.Context, []skills.SkillReference) ([]skills.SkillBundle, error) {
			t.Fatal("binding construction discovered resources")
			return nil, nil
		},
		SkillProjection: &testProjection{},
		ResolveInstructions: func(context.Context, []instructions.Reference) ([]instructions.Bundle, error) {
			t.Fatal("binding construction resolved resources")
			return nil, nil
		},
		InstructionProjection: reviewInstructionProjection{"devin"},
	}
	if _, err := NewBindings(valid); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*Runtime)
		want   string
	}{
		{"no skills discovery", func(runtime *Runtime) { runtime.DiscoverSkills = nil }, "common Skills registration is incomplete"},
		{"no skills projection", func(runtime *Runtime) { runtime.SkillProjection = nil }, "common Skills registration is incomplete"},
		{"invalid skills projection", func(runtime *Runtime) { runtime.SkillProjection = &testProjection{version: -1} }, "common Skills registration is incomplete"},
		{"no instruction resolution", func(runtime *Runtime) { runtime.ResolveInstructions = nil }, "common instructions registration is incomplete"},
		{"no instruction projection", func(runtime *Runtime) { runtime.InstructionProjection = nil }, "common instructions registration is incomplete"},
		{"invalid instruction projection", func(runtime *Runtime) { runtime.InstructionProjection = reviewInstructionProjection{} }, "common instructions registration is incomplete"},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := valid
			test.change(&runtime)
			if _, err := NewBindings(runtime); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("incomplete runtime admitted: %v", err)
			}
		})
	}
}
