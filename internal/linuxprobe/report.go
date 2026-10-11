// Package linuxprobe observes prerequisites for the future Linux sandbox.
// Passing these probes never enables a backend or establishes containment.
package linuxprobe

import "context"

type Check struct {
	ID, Status, Code, NextStep string
}

type Report struct {
	Checks []Check
}

// PrerequisitesPassed concerns only these bounded observations. Launch admission
// remains owned by launch.ValidatePlatform, which continues to reject Linux.
func (r Report) PrerequisitesPassed() bool {
	if len(r.Checks) == 0 {
		return false
	}
	for _, c := range r.Checks {
		if c.Status != "pass" {
			return false
		}
	}
	return true
}

// Probe runs bounded, credential-free observations. Active checks use disposable
// helpers and a child of the calling process's delegated cgroup, never a Session.
func Probe(ctx context.Context) Report { return probe(ctx) }
