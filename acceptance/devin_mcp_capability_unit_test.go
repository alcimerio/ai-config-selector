package acceptance_test

import "testing"

func TestDevinPhaseCapabilitiesRequirePerSessionFreshness(t *testing.T) {
	skills := devinCapability{ID: "main", RootName: "session-main", Generation: 1, Challenge: "skills"}
	auth := devinCapability{ID: "auth", RootName: "session-auth", Generation: 1, Challenge: "auth"}
	attached := devinCapability{ID: "main", RootName: "session-main", Generation: 2, Challenge: "attached"}
	for _, test := range []struct {
		name  string
		phase string
		cap   devinCapability
		valid bool
	}{
		{"independent auth generation one", "auth", auth, true},
		{"auth shares main", "auth", attached, false},
		{"auth shares root", "auth", devinCapability{ID: "auth", RootName: skills.RootName, Generation: 1, Challenge: "auth"}, false},
		{"auth shares challenge", "auth", devinCapability{ID: "auth", RootName: auth.RootName, Generation: 1, Challenge: skills.Challenge}, false},
		{"fresh attached", "attached", attached, true},
		{"stale attached generation", "attached", devinCapability{ID: skills.ID, RootName: skills.RootName, Generation: 1, Challenge: "attached"}, false},
		{"stale attached challenge", "attached", devinCapability{ID: skills.ID, RootName: skills.RootName, Generation: 2, Challenge: skills.Challenge}, false},
		{"attached changes Session", "attached", auth, false},
		{"attached changes root", "attached", devinCapability{ID: skills.ID, RootName: auth.RootName, Generation: 2, Challenge: "attached"}, false},
		{"removed capability", "auth", devinCapability{ID: auth.ID, RootName: auth.RootName, Generation: 1, Challenge: "auth", Removed: true}, false},
		{"duplicate phase", "skills", attached, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			observed := newDevinPhaseCapabilities()
			if err := observed.record("skills", skills); err != nil {
				t.Fatal(err)
			}
			if err := observed.record(test.phase, test.cap); (err == nil) != test.valid {
				t.Fatalf("capability admission = %v, valid = %t", err, test.valid)
			}
		})
	}
}

func TestDevinDriverRequiresObservedHomeForEachPhase(t *testing.T) {
	d := nativeDevinTestDriver(t)
	d.phaseHomes = map[string]string{"skills": d.home, "auth": "/private/auth/home", "attached": d.home}
	nativeDevinPhase(t, d, "skills", "list", "--json")
	if err := d.end(true); err != nil {
		t.Fatal(err)
	}
	if err := d.begin(devinPhaseReceipt{PID: 43, Argv: []string{"auth", "status"}, MemberSHA256: d.member, SessionHome: d.home}); err == nil {
		t.Fatal("auth admitted with the main Session home")
	}
	if err := d.begin(devinPhaseReceipt{PID: 43, Argv: []string{"auth", "status"}, MemberSHA256: d.member, SessionHome: d.phaseHomes["auth"]}); err != nil {
		t.Fatal(err)
	}
	if err := d.end(true); err != nil {
		t.Fatal(err)
	}
	nativeDevinPhase(t, d, "--respect-workspace-trust", "false")
}
