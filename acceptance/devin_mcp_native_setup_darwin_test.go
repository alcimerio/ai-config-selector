//go:build darwin

package acceptance_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// assembleNativeDevinProof is the complete public-ACS composition. Its two
// protocol contracts are supplied only after pinned-target observation; absence
// is failure, never a skipped/green proof. No test invokes this until review.
func assembleNativeDevinProof(t *testing.T, input func(devinInputFrame, string) ([]byte, error), listing func(int, string) error) {
	t.Helper()
	if runtime.GOARCH != "arm64" {
		t.Fatal("locked target is Darwin arm64")
	}
	if input == nil || listing == nil {
		t.Fatal("observed terminal/listing contracts required")
	}
	candidate := promotedBinary(t)
	if promotedSandboxCapability(t) != "available" {
		t.Fatal("production native sandbox unavailable")
	}
	target, archive := os.Getenv("ACS_TEST_DEVIN_BINARY"), os.Getenv("ACS_TEST_DEVIN_ARCHIVE")
	digest, e := verifyDevinDarwinMember(archive, target)
	if e != nil {
		t.Fatal(e)
	}
	home := realTemporaryDirectory(t)
	workspace := realTemporaryDirectory(t)
	tools := filepath.Join(workspace, "tools")
	coord := filepath.Join(workspace, "coordination")
	for _, p := range []string{tools, coord} {
		if e = os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	endpoint, e := copyDevinSyntheticCredentials(home)
	if e != nil {
		t.Fatal(e)
	}
	inputRoot := realTemporaryDirectory(t)
	inputPath := filepath.Join(inputRoot, "native-mcp-input.txt")
	evidenceBase := filepath.Join(workspace, "mcp-evidence")
	if e = writeDevinNativeProfile(home, inputPath); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(inputPath, []byte("acs selected input\n"), 0600); e != nil {
		t.Fatal(e)
	}
	// Ambient configs point only at an exclusive tripwire script. Starting any
	// unselected imported server is observable and fails the final proof.
	tripwire := filepath.Join(workspace, "ambient-poison")
	poison := filepath.Join(workspace, "ambient-server.sh")
	script := "#!/bin/sh\nset -eu\n(set -C; : > " + devinShellLiteral(tripwire) + ")\nexit 91\n"
	if e = os.WriteFile(poison, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	if e = devinSeedProjectImports(workspace, poison); e != nil {
		t.Fatal(e)
	}
	if _, e = devinInspectState(filepath.Join(home, ".acs", "profiles")); e != nil {
		t.Fatal(e)
	}

	outside := realTemporaryDirectory(t)
	forbidden := filepath.Join(outside, "forbidden.txt")
	if e = os.WriteFile(forbidden, []byte("outside selected authority\n"), 0600); e != nil {
		t.Fatal(e)
	}
	buildDevinResearchHelper(t, "devin-native-mcp-server", filepath.Join(workspace, "native-mcp-server"), map[string]string{"forbiddenPath": forbidden, "evidenceBase": evidenceBase})
	// Keep the byte-identical locked target within the already selected workspace
	// so the trampoline needs no additional production filesystem authority.
	realTarget := filepath.Join(tools, "devin-real")
	source, e := os.Open(target)
	if e != nil {
		t.Fatal(e)
	}
	dest, e := os.OpenFile(realTarget, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0500)
	if e != nil {
		_ = source.Close()
		t.Fatal(e)
	}
	_, copyErr := io.Copy(dest, io.LimitReader(source, 512<<20+1))
	sourceErr := source.Close()
	destErr := dest.Close()
	if copyErr != nil || sourceErr != nil || destErr != nil {
		t.Fatal("copy locked member", copyErr, sourceErr, destErr)
	}
	if copied, e := verifyDevinDarwinMember(archive, realTarget); e != nil || copied != digest {
		t.Fatal("copied member provenance", e)
	}
	trampoline := filepath.Join(tools, "devin")
	buildDevinResearchHelper(t, "devin-trampoline", trampoline, map[string]string{"target": realTarget, "memberDigest": digest, "endpoint": "http://" + endpoint, "coordination": coord})
	d := &devinDriver{member: digest, listingProof: listing}
	var observedLive *devinLiveDescendant
	d.serverProof = func(stage int) error {
		deadline := time.Now().Add(500 * time.Millisecond)
		for {
			e := verifyDevinServerJournal(evidenceBase, stage, false)
			if e == nil && stage == 3 {
				observedLive, e = observeDevinLiveDescendant(evidenceBase)
			}
			if e == nil {
				return nil
			}
			if time.Now().After(deadline) {
				return e
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	closeListener, e := startDevinListener(d, endpoint)
	if e != nil {
		t.Fatal(e)
	}
	closed := false
	defer func() {
		if !closed {
			if e := closeListener(); e != nil {
				t.Error(e)
			}
		}
	}()
	before := promotedSessionSnapshot(t, candidate, home, tools+":/usr/bin:/bin")
	run := devinNativeRun{Candidate: candidate, Home: home, Tools: tools, Workspace: workspace, Profile: "devin-native-mcp", Coordination: coord, Driver: d, Input: input, Observe: devinPhaseObserver(candidate, home, tools, workspace, trampoline, d)}
	run.VerifyEffects = func() error {
		if _, e := os.Stat(forbidden + ".descendant-effect"); !os.IsNotExist(e) {
			return errors.New("forbidden descendant marker exists")
		}
		if _, e := os.Stat(forbidden + ".effect"); !os.IsNotExist(e) {
			return errors.New("forbidden outside marker exists")
		}
		if _, e := os.Stat(tripwire); !os.IsNotExist(e) {
			return errors.New("ambient server started")
		}
		if observedLive == nil {
			return errors.New("no independently observed live descendant")
		}
		var finalIdentity devinDescendantIdentity
		if e := devinReadJSON(evidenceBase+".effect.descendant", &finalIdentity); e != nil {
			return e
		}
		if finalIdentity != observedLive.Identity {
			return errors.New("descendant identity changed after live observation")
		}
		return verifyDevinServerJournal(evidenceBase, 3, true)
	}
	if e = runPublicDevinPTY(run); e != nil {
		t.Fatal(e)
	}
	e = closeListener()
	closed = true
	if e != nil {
		t.Fatal(e)
	}
	if e = d.finalSuccess(); e != nil {
		t.Fatal(e)
	}
	assertNewRemovedPromotedSessions(t, candidate, home, tools+":/usr/bin:/bin", before, "devin")
	if _, e = devinInspectState(filepath.Join(home, ".acs", "profiles")); e != nil {
		t.Fatal(e)
	}
	if copied, e := verifyDevinDarwinMember(archive, realTarget); e != nil || copied != digest {
		t.Fatal("copied target changed", e)
	}
	if after, e := verifyDevinDarwinMember(archive, target); e != nil || after != digest {
		t.Fatal("locked member changed", e)
	}
}
func verifyDevinServerJournal(base string, stage int, final bool) error {
	if stage == 1 {
		return nil
	} // list_servers can precede lazy external startup
	b, e := os.ReadFile(base + ".journal")
	if e != nil {
		return e
	}
	if len(b) > 65536 {
		return errors.New("journal cap")
	}
	decoder := json.NewDecoder(bytes.NewReader(b))
	listed, called, eof := false, false, false
	serverPID := 0
	journalDescendantPID := 0
	pending := map[string]string{}
	completed := map[string]bool{}
	initialized := false
	sawEOF := false
	for count := 0; count < 64; count++ {
		var event struct {
			Event, Method string
			ID            json.RawMessage
			Result        json.RawMessage
			Params        json.RawMessage
			PID           int
			Called        bool
		}
		e = decoder.Decode(&event)
		if e == io.EOF {
			sawEOF = true
			break
		}
		if e != nil {
			return e
		}
		switch event.Event {
		case "request":
			if event.Method == "notifications/initialized" {
				if !completed["initialize"] || initialized || len(event.ID) != 0 {
					return errors.New("initialized notification ordering")
				}
				initialized = true
				continue
			}
			id := string(event.ID)
			if id == "" || id == "null" || pending[id] != "" {
				return errors.New("journal request identity")
			}
			if event.Method != "initialize" && event.Method != "tools/list" && event.Method != "tools/call" {
				return errors.New("journal unexpected method")
			}
			if event.Method != "initialize" && !initialized {
				return errors.New("journal request before initialized")
			}
			if completed[event.Method] {
				return errors.New("journal duplicate method")
			}
			pending[id] = event.Method
			if event.Method == "tools/call" {
				var p struct {
					Name      string
					Arguments map[string]any
				}
				if json.Unmarshal(event.Params, &p) != nil || p.Name != "acs_allowed_echo" || p.Arguments == nil || len(p.Arguments) != 0 || !listed {
					return errors.New("journal exact call mismatch")
				}
			}
		case "response-complete":
			id := string(event.ID)
			if pending[id] != event.Method {
				return errors.New("journal response ID/method mismatch")
			}
			delete(pending, id)
			completed[event.Method] = true
			switch event.Method {
			case "initialize":
				var result struct{ ProtocolVersion string }
				if json.Unmarshal(event.Result, &result) != nil || result.ProtocolVersion != "2025-11-25" {
					return errors.New("journal initialize version")
				}
			case "tools/list":
				var result struct{ Tools []struct{ Name string } }
				if json.Unmarshal(event.Result, &result) != nil || len(result.Tools) != 2 || result.Tools[0].Name != "acs_allowed_echo" || result.Tools[1].Name != "acs_blocked_echo" {
					return errors.New("journal full server listing")
				}
				listed = true
			case "tools/call":
				var result struct {
					Content []struct{ Type, Text string }
					IsError bool
				}
				if json.Unmarshal(event.Result, &result) != nil || result.IsError || len(result.Content) != 1 || result.Content[0].Type != "text" || result.Content[0].Text != "ACS_MCP_TOOL_OK" {
					return errors.New("journal call result")
				}
				called = true
			}
		case "descendant-started":
			if event.PID <= 1 || journalDescendantPID != 0 {
				return errors.New("journal descendant PID")
			}
			journalDescendantPID = event.PID
		case "stdin-eof":
			if !event.Called || !called || len(pending) != 0 {
				return errors.New("journal premature EOF")
			}
			eof = true
		default:
			return errors.New("journal unknown event")
		}
	}
	if !sawEOF {
		return errors.New("journal event cap or truncation")
	}

	if !listed {
		return errors.New("missing actual tools/list completion")
	}
	if stage < 3 {
		return nil
	}
	if !called {
		return errors.New("missing actual tools/call completion")
	}
	var effect struct {
		Tool        string
		Arguments   map[string]any
		PID, Parent int
		Result      string
	}
	if e = devinReadJSON(base+".effect", &effect); e != nil {
		return e
	}
	if effect.Tool != "acs_allowed_echo" || effect.Arguments == nil || len(effect.Arguments) != 0 || effect.Result != "ACS_MCP_TOOL_OK" || effect.PID <= 1 {
		return errors.New("independent tool effect mismatch")
	}
	serverPID = effect.PID
	var selection struct {
		ArgvMatched, InputMatched, SelectedEnvironmentMatched, AmbientEnvironmentAbsent bool
		InputReadOnly, OutsideReadDenied, OutsideWriteDenied                            bool
		PID, Parent                                                                     int
	}
	if e = devinReadJSON(base+".selection", &selection); e != nil {
		return e
	}
	if !selection.InputReadOnly || !selection.OutsideReadDenied || !selection.OutsideWriteDenied || !selection.ArgvMatched || !selection.InputMatched || !selection.SelectedEnvironmentMatched || !selection.AmbientEnvironmentAbsent || selection.PID != serverPID {
		return errors.New("selected reference witness mismatch")
	}
	var descendant devinDescendantIdentity
	if e = devinReadJSON(base+".effect.descendant", &descendant); e != nil {
		return e
	}
	if !descendant.InheritedEnvironment || !descendant.InputRead || !descendant.InputReadOnly || !descendant.OutsideDenied || descendant.PID <= 1 || descendant.PID != journalDescendantPID || descendant.Parent != serverPID || time.Since(time.Unix(0, descendant.StartedUnixNano)) >= 40*time.Second {
		return errors.New("descendant identity/watchdog window")
	}
	if !final {
		return nil
	}
	if !eof {
		return errors.New("server EOF not observed")
	}
	if !errors.Is(syscall.Kill(descendant.PID, 0), syscall.ESRCH) || !errors.Is(syscall.Kill(serverPID, 0), syscall.ESRCH) {
		return errors.New("MCP descendant/server still exists")
	}
	first, e := os.ReadFile(base + ".effect.descendant.heartbeat")
	if e != nil {
		return e
	}
	time.Sleep(250 * time.Millisecond)
	second, e := os.ReadFile(base + ".effect.descendant.heartbeat")
	if e != nil || !bytes.Equal(first, second) {
		return fmt.Errorf("descendant heartbeat changed: %v", e)
	}
	return nil
}

type devinDescendantIdentity struct {
	PID, Parent                                                   int
	StartedUnixNano                                               int64
	InheritedEnvironment, InputRead, InputReadOnly, OutsideDenied bool
}
type devinLiveDescendant struct {
	Identity   devinDescendantIdentity
	ObservedAt time.Time
	Heartbeat  []byte
}

func observeDevinLiveDescendant(base string) (*devinLiveDescendant, error) {
	var id devinDescendantIdentity
	if e := devinReadJSON(base+".effect.descendant", &id); e != nil {
		return nil, e
	}
	if id.PID <= 1 || id.Parent <= 1 || syscall.Kill(id.PID, 0) != nil || syscall.Kill(id.Parent, 0) != nil {
		return nil, errors.New("descendant/server not live during tool result")
	}
	first, e := os.ReadFile(base + ".effect.descendant.heartbeat")
	if e != nil || len(first) > 32 {
		return nil, errors.New("live heartbeat shape")
	}
	time.Sleep(250 * time.Millisecond)
	second, e := os.ReadFile(base + ".effect.descendant.heartbeat")
	if e != nil || len(second) > 32 || bytes.Equal(first, second) || syscall.Kill(id.PID, 0) != nil || syscall.Kill(id.Parent, 0) != nil {
		return nil, errors.New("descendant did not remain live with advancing heartbeat")
	}
	before, e1 := strconv.ParseInt(string(first), 10, 64)
	after, e2 := strconv.ParseInt(string(second), 10, 64)
	if e1 != nil || e2 != nil || after <= before {
		return nil, errors.New("invalid heartbeat progression")
	}
	return &devinLiveDescendant{Identity: id, ObservedAt: time.Now(), Heartbeat: append([]byte{}, second...)}, nil
}
