package releasegate_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/release/releasegate"
)

func TestValidateBindsBothEvidenceRecordsToExactCandidateBytes(t *testing.T) {
	directory := t.TempDir()
	manifestDigest := writeGateFile(t, directory, "SHA256SUMS", "manifest\n")
	darwinDigest := writeGateFile(t, directory, "acs_0.2.0_darwin_arm64.tar.gz", "darwin\n")
	linuxDigest := writeGateFile(t, directory, "acs_0.2.0_linux_amd64.tar.gz", "linux\n")
	evidence := fmt.Sprintf(`{"schema_version":1,"darwin_arm64":%s,"linux_amd64":%s}`,
		gateEvidence("acs_0.2.0_darwin_arm64.tar.gz", darwinDigest, manifestDigest, "macos-26", "darwin", "arm64", false),
		gateEvidence("acs_0.2.0_linux_amd64.tar.gz", linuxDigest, manifestDigest, "ubuntu-24.04", "linux", "amd64", true),
	)
	expected := releasegate.Expectations{
		Version: "v0.2.0", SourceCommit: "0123456789abcdef0123456789abcdef01234567", CandidateDirectory: directory,
		EarliestCompletion: time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC),
		LatestCompletion:   time.Date(2026, 8, 7, 13, 0, 0, 0, time.UTC),
	}
	if err := releasegate.Validate(strings.NewReader(evidence), expected); err != nil {
		t.Fatalf("candidate-matched evidence rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "acs_0.2.0_linux_amd64.tar.gz"), []byte("replacement\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := releasegate.Validate(strings.NewReader(evidence), expected); err == nil || !strings.Contains(err.Error(), "digest does not match") {
		t.Fatalf("replacement-byte rejection = %v", err)
	}
}

func writeGateFile(t *testing.T, directory, name, contents string) string {
	t.Helper()
	data := []byte(contents)
	if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func gateEvidence(archive, archiveDigest, manifestDigest, platform, targetOS, arch string, destroyed bool) string {
	return fmt.Sprintf(`{
  "schema_version":1,
  "candidate":{"version":"v0.2.0","source_commit":"0123456789abcdef0123456789abcdef01234567","archive":%q,"archive_sha256":%q,"artifact_set_sha256":%q,"version_output":"acs v0.2.0"},
  "target":{"platform":%q,"os":%q,"arch":%q},
  "started_at":"2026-08-07T12:15:00Z","completed_at":"2026-08-07T12:30:00Z",
  "selected_catalog":[{"source":"devin-config","relative_path":"review"}],
  "checks":{"candidate_identity":true,"visual_profile_builder":true,"terminal_restored":true,"profile_created":true,"dry_run":true,"exact_catalog":true,"authenticated_launch":true,"normal_child_exit":true,"session_created":true,"session_isolated":true,"session_cleaned":true},
  "cleanup":{"temporary_profile_removed":true,"session_credentials_removed":true,"candidate_binary_removed":true,"logs_removed":true,"disposable_host_destroyed":%t},
  "result":"passed"
}`, archive, archiveDigest, manifestDigest, platform, targetOS, arch, destroyed)
}
