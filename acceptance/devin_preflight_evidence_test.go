package acceptance_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

type fakeDevinResult struct {
	PreflightSkills            bool `json:"preflightSkills"`
	PreflightAuthentication    bool `json:"preflightAuthentication"`
	WorkspaceWritable          bool `json:"workspaceWritable"`
	SessionWritable            bool `json:"sessionWritable"`
	TemporaryWritable          bool `json:"temporaryWritable"`
	HostFileReadable           bool `json:"hostFileReadable"`
	SymlinkEscapeReadable      bool `json:"symlinkEscapeReadable"`
	AllowedEnvironment         bool `json:"allowedEnvironment"`
	BlockedEnvironmentVisible  bool `json:"blockedEnvironmentVisible"`
	DescriptorLeaked           bool `json:"descriptorLeaked"`
	HostSocketReachable        bool `json:"hostSocketReachable"`
	OutboundIP                 bool `json:"outboundIP"`
	LocalIPBind                bool `json:"localIPBind"`
	LocalUnixBind              bool `json:"localUnixBind"`
	ExternalWriteSucceeded     bool `json:"externalWriteSucceeded"`
	DescendantStarted          bool `json:"descendantStarted"`
	RegisteredSysctls          bool `json:"registeredSysctls"`
	UnregisteredSysctlDenied   bool `json:"unregisteredSysctlDenied"`
	SystemTrustSettings        bool `json:"systemTrustSettings"`
	LocalSystemTrust           bool `json:"localSystemTrust"`
	SelectedCommonSkills       bool `json:"selectedCommonSkills"`
	SelectedProjectedSkills    bool `json:"selectedProjectedSkills"`
	UnselectedGlobalAbsent     bool `json:"unselectedGlobalAbsent"`
	ProjectAgentReadable       bool `json:"projectAgentReadable"`
	ProjectDevinReadable       bool `json:"projectDevinReadable"`
	EnvironmentSkillsAbsent    bool `json:"environmentSkillsAbsent"`
	EnvironmentAuthAbsent      bool `json:"environmentAuthAbsent"`
	EnvironmentSelected        bool `json:"environmentSelected"`
	EnvironmentOptional        bool `json:"environmentOptional"`
	EnvironmentSecretSelected  bool `json:"environmentSecretSelected"`
	EnvironmentUnselectedGone  bool `json:"environmentUnselectedGone"`
	EnvironmentChildSelected   bool `json:"environmentChildSelected"`
	EnvironmentChildOptional   bool `json:"environmentChildOptional"`
	EnvironmentChildSecret     bool `json:"environmentChildSecret"`
	EnvironmentChildUnselected bool `json:"environmentChildUnselected"`
}

// Each contained probe writes only to its own HOME. The host collects the
// receipt before releasing the probe, so Session cleanup cannot erase it.
// The workspace stays read-only when selected; release files are host writes.
type fakeDevinPreflightEvidence struct {
	Home   string          `json:"home"`
	Phase  string          `json:"phase"`
	Result fakeDevinResult `json:"result"`
}

func fakeDevinPreflightReceiptName(phase string) string {
	return ".acs-native-" + phase + "-receipt.json"
}

func readFakeDevinPreflightEvidence(sessions, phase string) (fakeDevinPreflightEvidence, bool, error) {
	paths, err := filepath.Glob(filepath.Join(sessions, "session-*", "home", fakeDevinPreflightReceiptName(phase)))
	if err != nil || len(paths) == 0 {
		return fakeDevinPreflightEvidence{}, false, err
	}
	if len(paths) != 1 {
		return fakeDevinPreflightEvidence{}, false, fmt.Errorf("%s has %d preflight receipts", phase, len(paths))
	}
	contents, err := os.ReadFile(paths[0])
	if err != nil {
		return fakeDevinPreflightEvidence{}, false, err
	}
	var evidence fakeDevinPreflightEvidence
	if err := json.Unmarshal(contents, &evidence); err != nil {
		return evidence, false, err
	}
	// Resolve aliases such as macOS /var -> /private/var, while rejecting a
	// receipt that attributes another Session's evidence to this probe.
	recorded, err := os.Stat(evidence.Home)
	if err != nil {
		return evidence, false, err
	}
	actual, err := os.Stat(filepath.Dir(paths[0]))
	if err != nil {
		return evidence, false, err
	}
	if evidence.Phase != phase || !os.SameFile(recorded, actual) {
		return evidence, false, fmt.Errorf("%s receipt is not bound to its Session HOME", phase)
	}
	if (phase == "skills" && (!evidence.Result.PreflightSkills || evidence.Result.PreflightAuthentication)) ||
		(phase == "authentication" && (!evidence.Result.PreflightAuthentication || evidence.Result.PreflightSkills)) {
		return evidence, false, fmt.Errorf("%s receipt lacks its own exclusive preflight marker", phase)
	}
	return evidence, true, nil
}

func TestSharedTargetPreflightEvidenceIsCollectedPerSession(t *testing.T) {
	for _, test := range []struct {
		name         string
		skills, auth bool
	}{
		{name: "neither"},
		{name: "skills only", skills: true},
		{name: "authentication only", auth: true},
		{name: "both independent Sessions", skills: true, auth: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			sessions := t.TempDir()
			for phase, present := range map[string]bool{"skills": test.skills, "authentication": test.auth} {
				if !present {
					continue
				}
				home := filepath.Join(sessions, "session-"+phase, "home")
				evidence := fakeDevinPreflightEvidence{Home: home, Phase: phase, Result: fakeDevinResult{
					PreflightSkills: phase == "skills", PreflightAuthentication: phase == "authentication",
				}}
				writeFakeDevinPreflightEvidenceForTest(t, home, phase, evidence)
			}
			for phase, want := range map[string]bool{"skills": test.skills, "authentication": test.auth} {
				evidence, found, err := readFakeDevinPreflightEvidence(sessions, phase)
				if err != nil || found != want {
					t.Fatalf("%s evidence = %+v, %v, %v; want found=%v", phase, evidence, found, err, want)
				}
			}
			// Model auth cleanup after host collection. The main Session alone
			// must never be reported as evidence that authentication ran.
			if err := os.RemoveAll(filepath.Join(sessions, "session-authentication")); err != nil {
				t.Fatal(err)
			}
			if _, found, err := readFakeDevinPreflightEvidence(sessions, "authentication"); err != nil || found {
				t.Fatalf("invented auth evidence after its Session was removed: found=%v err=%v", found, err)
			}
		})
	}
}

func TestSharedTargetPreflightEvidenceRejectsMisattribution(t *testing.T) {
	for _, name := range []string{"different HOME", "different phase", "missing marker", "both markers", "duplicate receipt", "malformed receipt"} {
		t.Run(name, func(t *testing.T) {
			sessions := t.TempDir()
			home := filepath.Join(sessions, "session-authentication", "home")
			evidence := fakeDevinPreflightEvidence{Home: home, Phase: "authentication", Result: fakeDevinResult{PreflightAuthentication: true}}
			switch name {
			case "different HOME":
				evidence.Home = t.TempDir()
			case "different phase":
				evidence.Phase = "skills"
			case "missing marker":
				evidence.Result.PreflightAuthentication = false
			case "both markers":
				evidence.Result.PreflightSkills = true
			case "duplicate receipt":
				other := filepath.Join(sessions, "session-other", "home")
				writeFakeDevinPreflightEvidenceForTest(t, other, "authentication", fakeDevinPreflightEvidence{Home: other, Phase: "authentication", Result: evidence.Result})
			}
			writeFakeDevinPreflightEvidenceForTest(t, home, "authentication", evidence)
			if name == "malformed receipt" {
				if err := os.WriteFile(filepath.Join(home, fakeDevinPreflightReceiptName("authentication")), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, found, err := readFakeDevinPreflightEvidence(sessions, "authentication"); err == nil || found {
				t.Fatalf("accepted misattributed evidence: found=%v err=%v", found, err)
			}
		})
	}
}

func writeFakeDevinPreflightEvidenceForTest(t *testing.T, home, phase string, evidence fakeDevinPreflightEvidence) {
	t.Helper()
	if err := os.MkdirAll(home, 0700); err != nil {
		t.Fatal(err)
	}
	contents, err := json.Marshal(evidence)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, fakeDevinPreflightReceiptName(phase)), contents, 0600); err != nil {
		t.Fatal(err)
	}
}
