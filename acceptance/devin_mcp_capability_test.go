package acceptance_test

import "errors"

type devinCapability struct {
	ID, RootName, Challenge string
	Generation              uint64
	Removed                 bool
}

// Freshness is per Session: skills and attached share a sequential Session,
// while auth owns an independent concurrent recovery capability.
type devinPhaseCapabilities struct {
	previous map[string]devinCapability
	phases   map[string]devinCapability
}

func newDevinPhaseCapabilities() *devinPhaseCapabilities {
	return &devinPhaseCapabilities{previous: make(map[string]devinCapability), phases: make(map[string]devinCapability)}
}

func (observed *devinPhaseCapabilities) record(phase string, cap devinCapability) error {
	if cap.ID == "" || cap.RootName == "" || cap.Generation == 0 || cap.Challenge == "" || cap.Removed {
		return errors.New("capability identity")
	}
	if _, exists := observed.phases[phase]; exists {
		return errors.New("duplicate phase capability")
	}
	skills := observed.phases["skills"]
	switch phase {
	case "skills":
	case "auth":
		if skills.ID == "" || cap.ID == skills.ID || cap.RootName == skills.RootName {
			return errors.New("auth Session is not independent")
		}
	case "attached":
		if skills.ID == "" || cap.ID != skills.ID || cap.RootName != skills.RootName {
			return errors.New("main Session changed")
		}
	default:
		return errors.New("unknown phase capability")
	}
	if previous, exists := observed.previous[cap.ID]; exists {
		if cap.RootName != previous.RootName || cap.Generation <= previous.Generation || cap.Challenge == previous.Challenge {
			return errors.New("phase capability not fresh")
		}
	}
	for id, previous := range observed.previous {
		if id != cap.ID && (cap.RootName == previous.RootName || cap.Challenge == previous.Challenge) {
			return errors.New("Session capability binding reused")
		}
	}
	observed.previous[cap.ID], observed.phases[phase] = cap, cap
	return nil
}
