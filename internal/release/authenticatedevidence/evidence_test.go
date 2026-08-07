package authenticatedevidence_test

import (
	"strings"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/release/authenticatedevidence"
)

const validDarwinEvidence = `{
  "schema_version": 1,
  "candidate": {
    "version": "v0.2.0",
    "source_commit": "0123456789abcdef0123456789abcdef01234567",
    "archive": "acs_0.2.0_darwin_arm64.tar.gz",
    "archive_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "artifact_set_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "version_output": "acs v0.2.0"
  },
  "target": {
    "platform": "macos-26",
    "os": "darwin",
    "arch": "arm64"
  },
  "started_at": "2026-08-07T12:00:00Z",
  "completed_at": "2026-08-07T12:30:00Z",
  "selected_catalog": [
    {"source": "devin-config", "relative_path": "review"},
    {"source": "shared-agents", "relative_path": "testing/security"}
  ],
  "checks": {
    "candidate_identity": true,
    "visual_profile_builder": true,
    "terminal_restored": true,
    "profile_created": true,
    "dry_run": true,
    "exact_catalog": true,
    "authenticated_launch": true,
    "normal_child_exit": true,
    "session_created": true,
    "session_isolated": true,
    "session_cleaned": true
  },
  "cleanup": {
    "temporary_profile_removed": true,
    "session_credentials_removed": true,
    "candidate_binary_removed": true,
    "logs_removed": true,
    "disposable_host_destroyed": false
  },
  "result": "passed"
}`

func TestValidateAcceptsCompleteCandidateMatchedDarwinEvidence(t *testing.T) {
	err := authenticatedevidence.Validate(strings.NewReader(validDarwinEvidence), authenticatedevidence.Expectations{
		Version:           "v0.2.0",
		SourceCommit:      "0123456789abcdef0123456789abcdef01234567",
		Target:            "darwin/arm64",
		ArchiveSHA256:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ArtifactSetSHA256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	})
	if err != nil {
		t.Fatalf("complete authenticated evidence rejected: %v", err)
	}
}

func TestValidateRejectsEvidenceThatCannotBlockPublication(t *testing.T) {
	tests := []struct {
		name        string
		evidence    string
		expectation authenticatedevidence.Expectations
		want        string
	}{
		{
			name:     "candidate digest mismatch",
			evidence: validDarwinEvidence,
			expectation: authenticatedevidence.Expectations{
				Version: "v0.2.0", SourceCommit: "0123456789abcdef0123456789abcdef01234567", Target: "darwin/arm64",
				ArchiveSHA256: strings.Repeat("c", 64), ArtifactSetSHA256: strings.Repeat("b", 64),
			},
			want: "archive digest does not match",
		},
		{
			name: "unsupported reference target",
			evidence: strings.NewReplacer(
				"acs_0.2.0_darwin_arm64.tar.gz", "acs_0.2.0_linux_arm64.tar.gz",
				`"platform": "macos-26"`, `"platform": "ubuntu-24.04"`,
				`"os": "darwin"`, `"os": "linux"`,
			).Replace(validDarwinEvidence),
			expectation: authenticatedevidence.Expectations{
				Version: "v0.2.0", SourceCommit: "0123456789abcdef0123456789abcdef01234567", Target: "linux/arm64",
				ArchiveSHA256: strings.Repeat("a", 64), ArtifactSetSHA256: strings.Repeat("b", 64),
			},
			want: "supported reference target",
		},
		{
			name:     "failed checklist step",
			evidence: strings.Replace(validDarwinEvidence, `"terminal_restored": true`, `"terminal_restored": false`, 1),
			want:     "terminal_restored did not pass",
		},
		{
			name:     "unsafe catalog value",
			evidence: strings.Replace(validDarwinEvidence, `"relative_path": "review"`, `"relative_path": "/Users/maintainer/token-secret"`, 1),
			want:     "selected catalog entry is invalid",
		},
		{
			name:     "invalid time order",
			evidence: strings.Replace(validDarwinEvidence, `"completed_at": "2026-08-07T12:30:00Z"`, `"completed_at": "2026-08-07T11:30:00Z"`, 1),
			want:     "completion timestamp precedes start",
		},
		{
			name:     "timestamp is not UTC",
			evidence: strings.Replace(validDarwinEvidence, `"completed_at": "2026-08-07T12:30:00Z"`, `"completed_at": "2026-08-07T09:30:00-03:00"`, 1),
			want:     "completion timestamp is invalid",
		},
		{
			name:     "incomplete cleanup",
			evidence: strings.Replace(validDarwinEvidence, `"logs_removed": true`, `"logs_removed": false`, 1),
			want:     "logs_removed did not pass",
		},
		{
			name:     "unknown field",
			evidence: strings.Replace(validDarwinEvidence, `"result": "passed"`, `"credential": "secret",\n  "result": "passed"`, 1),
			want:     "unsupported field",
		},
	}

	defaultExpectation := authenticatedevidence.Expectations{
		Version:           "v0.2.0",
		SourceCommit:      "0123456789abcdef0123456789abcdef01234567",
		Target:            "darwin/arm64",
		ArchiveSHA256:     strings.Repeat("a", 64),
		ArtifactSetSHA256: strings.Repeat("b", 64),
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			expectation := test.expectation
			if expectation.Version == "" {
				expectation = defaultExpectation
			}
			err := authenticatedevidence.Validate(strings.NewReader(test.evidence), expectation)
			if err == nil {
				t.Fatal("invalid authenticated evidence was accepted")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("rejection = %q, want detail %q", err, test.want)
			}
			for _, sensitive := range []string{"/Users/maintainer/token-secret", "credential"} {
				if strings.Contains(err.Error(), sensitive) {
					t.Fatalf("rejection exposed sensitive input: %q", err)
				}
			}
		})
	}
}

func TestValidateRejectsStaleAndOversizedEvidence(t *testing.T) {
	expectation := authenticatedevidence.Expectations{
		Version: "v0.2.0", SourceCommit: "0123456789abcdef0123456789abcdef01234567", Target: "darwin/arm64",
		ArchiveSHA256: strings.Repeat("a", 64), ArtifactSetSHA256: strings.Repeat("b", 64),
		EarliestCompletion: time.Date(2026, 8, 7, 13, 0, 0, 0, time.UTC),
	}
	if err := authenticatedevidence.Validate(strings.NewReader(validDarwinEvidence), expectation); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale evidence rejection = %v", err)
	}

	expectation.EarliestCompletion = time.Time{}
	oversized := validDarwinEvidence + strings.Repeat(" ", 64<<10)
	if err := authenticatedevidence.Validate(strings.NewReader(oversized), expectation); err == nil || !strings.Contains(err.Error(), "oversized") {
		t.Fatalf("oversized evidence rejection = %v", err)
	}
}

func TestValidateRequiresDestroyedDisposableLinuxHost(t *testing.T) {
	linuxEvidence := strings.NewReplacer(
		"acs_0.2.0_darwin_arm64.tar.gz", "acs_0.2.0_linux_amd64.tar.gz",
		`"platform": "macos-26"`, `"platform": "ubuntu-24.04"`,
		`"os": "darwin"`, `"os": "linux"`,
		`"arch": "arm64"`, `"arch": "amd64"`,
		`"disposable_host_destroyed": false`, `"disposable_host_destroyed": true`,
	).Replace(validDarwinEvidence)
	expectation := authenticatedevidence.Expectations{
		Version: "v0.2.0", SourceCommit: "0123456789abcdef0123456789abcdef01234567", Target: "linux/amd64",
		ArchiveSHA256: strings.Repeat("a", 64), ArtifactSetSHA256: strings.Repeat("b", 64),
	}
	if err := authenticatedevidence.Validate(strings.NewReader(linuxEvidence), expectation); err != nil {
		t.Fatalf("complete Linux evidence rejected: %v", err)
	}

	notDestroyed := strings.Replace(linuxEvidence, `"disposable_host_destroyed": true`, `"disposable_host_destroyed": false`, 1)
	if err := authenticatedevidence.Validate(strings.NewReader(notDestroyed), expectation); err == nil || !strings.Contains(err.Error(), "disposable_host_destroyed did not pass") {
		t.Fatalf("incomplete Linux cleanup rejection = %v", err)
	}
}
