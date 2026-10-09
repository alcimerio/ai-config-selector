package category

import (
	"errors"

	"github.com/alcimerio/ai-config-selector/internal/profile"
)

// Codec exposes the shared Profile admission and normalization rules without
// draft editing, source resolution, target requirements, or launch authority.
// Its registry is private and contains no runtime callbacks.
type Codec struct {
	registry *Registry
}

// NewCodec assembles a passive view of the same capability registrations used
// by execution registries. Common intent and inactive overlays are
// provider-neutral, so the codec selects no target.
func NewCodec(registrations []Registration) (*Codec, error) {
	if len(registrations) == 0 {
		return nil, errors.New("Profile codec requires capability registrations")
	}
	passive := append([]Registration(nil), registrations...)
	for i := range passive {
		passive[i].resolve, passive[i].resolveSyntax, passive[i].contribute = nil, nil, nil
	}
	registry, err := newRegistry("common", passive)
	if err != nil {
		return nil, err
	}
	return &Codec{registry: registry}, nil
}

func (codec *Codec) Normalize(candidate profile.Profile) (profile.Profile, error) {
	return codec.registry.Normalize(candidate)
}

func (codec *Codec) Decode(contents []byte) (profile.Profile, error) {
	return codec.registry.Decode(contents)
}

func (codec *Codec) DecodeNamed(name string, contents []byte) (profile.Profile, error) {
	return codec.registry.DecodeNamed(name, contents)
}
