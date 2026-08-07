// Package authenticatedevidence validates the sanitized, human-owned record of
// an authenticated ACS release-candidate smoke test.
package authenticatedevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	currentSchemaVersion = 1
	maximumEvidenceSize  = 64 << 10
	maximumRunDuration   = 12 * time.Hour
)

var (
	canonicalVersionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	hexCommitPattern        = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hexDigestPattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Expectations binds evidence to the exact candidate and reference target
// being reviewed. Optional time bounds let a publication workflow reject
// evidence outside its approved review window.
type Expectations struct {
	Version            string
	SourceCommit       string
	Target             string
	ArchiveSHA256      string
	ArtifactSetSHA256  string
	EarliestCompletion time.Time
	LatestCompletion   time.Time
}

type evidence struct {
	SchemaVersion   int                `json:"schema_version"`
	Candidate       candidate          `json:"candidate"`
	Target          target             `json:"target"`
	StartedAt       string             `json:"started_at"`
	CompletedAt     string             `json:"completed_at"`
	SelectedCatalog []catalogReference `json:"selected_catalog"`
	Checks          checks             `json:"checks"`
	Cleanup         cleanup            `json:"cleanup"`
	Result          string             `json:"result"`
}

type candidate struct {
	Version           string `json:"version"`
	SourceCommit      string `json:"source_commit"`
	Archive           string `json:"archive"`
	ArchiveSHA256     string `json:"archive_sha256"`
	ArtifactSetSHA256 string `json:"artifact_set_sha256"`
	VersionOutput     string `json:"version_output"`
}

type target struct {
	Platform string `json:"platform"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
}

type catalogReference struct {
	Source       string `json:"source"`
	RelativePath string `json:"relative_path"`
}

type checks struct {
	CandidateIdentity    bool `json:"candidate_identity"`
	VisualProfileBuilder bool `json:"visual_profile_builder"`
	TerminalRestored     bool `json:"terminal_restored"`
	ProfileCreated       bool `json:"profile_created"`
	DryRun               bool `json:"dry_run"`
	ExactCatalog         bool `json:"exact_catalog"`
	AuthenticatedLaunch  bool `json:"authenticated_launch"`
	NormalChildExit      bool `json:"normal_child_exit"`
	SessionCreated       bool `json:"session_created"`
	SessionIsolated      bool `json:"session_isolated"`
	SessionCleaned       bool `json:"session_cleaned"`
}

type cleanup struct {
	TemporaryProfileRemoved   bool `json:"temporary_profile_removed"`
	SessionCredentialsRemoved bool `json:"session_credentials_removed"`
	CandidateBinaryRemoved    bool `json:"candidate_binary_removed"`
	LogsRemoved               bool `json:"logs_removed"`
	DisposableHostDestroyed   bool `json:"disposable_host_destroyed"`
}

// Validate rejects malformed, incomplete, unsafe, or candidate-mismatched
// evidence without echoing untrusted evidence values in its diagnostics.
func Validate(input io.Reader, expected Expectations) error {
	if err := validateExpectations(expected); err != nil {
		return err
	}

	contents, err := io.ReadAll(io.LimitReader(input, maximumEvidenceSize+1))
	if err != nil || len(contents) > maximumEvidenceSize {
		return errors.New("authenticated evidence contains trailing or oversized content")
	}
	if !utf8.Valid(contents) {
		return errors.New("authenticated evidence contains an unsupported field or malformed value")
	}
	if err := rejectDuplicateFields(contents); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var record evidence
	if err := decoder.Decode(&record); err != nil {
		return errors.New("authenticated evidence contains an unsupported field or malformed value")
	}
	if err := ensureJSONEnds(decoder); err != nil {
		return err
	}
	if err := validateIdentity(record, expected); err != nil {
		return err
	}
	if err := validateTimes(record, expected); err != nil {
		return err
	}
	if err := validateCatalog(record.SelectedCatalog); err != nil {
		return err
	}
	if err := validateChecks(record.Checks); err != nil {
		return err
	}
	if err := validateCleanup(record.Target, record.Cleanup); err != nil {
		return err
	}
	if record.Result != "passed" {
		return errors.New("authenticated evidence result is not passed")
	}
	return nil
}

func rejectDuplicateFields(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := inspectJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("authenticated evidence contains trailing or oversized content")
	}
	return nil
}

func inspectJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return errors.New("authenticated evidence contains an unsupported field or malformed value")
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return errors.New("authenticated evidence contains an unsupported field or malformed value")
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("authenticated evidence contains an unsupported field or malformed value")
			}
			if seen[key] {
				return errors.New("authenticated evidence contains a duplicate field")
			}
			seen[key] = true
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := inspectJSONValue(decoder); err != nil {
				return err
			}
		}
	default:
		return errors.New("authenticated evidence contains an unsupported field or malformed value")
	}
	if _, err := decoder.Token(); err != nil {
		return errors.New("authenticated evidence contains an unsupported field or malformed value")
	}
	return nil
}

func validateExpectations(expected Expectations) error {
	if !canonicalVersionPattern.MatchString(expected.Version) ||
		!hexCommitPattern.MatchString(expected.SourceCommit) ||
		!hexDigestPattern.MatchString(expected.ArchiveSHA256) ||
		!hexDigestPattern.MatchString(expected.ArtifactSetSHA256) {
		return errors.New("authenticated evidence expectations are invalid")
	}
	if expected.Target != "darwin/arm64" && expected.Target != "linux/amd64" {
		return errors.New("authenticated evidence expectation is not a supported reference target")
	}
	if !expected.EarliestCompletion.IsZero() && !expected.LatestCompletion.IsZero() && expected.LatestCompletion.Before(expected.EarliestCompletion) {
		return errors.New("authenticated evidence review window is invalid")
	}
	return nil
}

func ensureJSONEnds(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("authenticated evidence contains trailing or oversized content")
	}
	return nil
}

func validateIdentity(record evidence, expected Expectations) error {
	if record.SchemaVersion != currentSchemaVersion {
		return errors.New("authenticated evidence schema version is unsupported")
	}
	if !canonicalVersionPattern.MatchString(record.Candidate.Version) || record.Candidate.Version != expected.Version {
		return errors.New("authenticated evidence version does not match the candidate")
	}
	if !hexCommitPattern.MatchString(record.Candidate.SourceCommit) || record.Candidate.SourceCommit != expected.SourceCommit {
		return errors.New("authenticated evidence source commit does not match the candidate")
	}
	if !hexDigestPattern.MatchString(record.Candidate.ArchiveSHA256) || record.Candidate.ArchiveSHA256 != expected.ArchiveSHA256 {
		return errors.New("authenticated evidence archive digest does not match the candidate")
	}
	if !hexDigestPattern.MatchString(record.Candidate.ArtifactSetSHA256) || record.Candidate.ArtifactSetSHA256 != expected.ArtifactSetSHA256 {
		return errors.New("authenticated evidence artifact-set digest does not match the candidate")
	}
	archiveVersion := strings.TrimPrefix(expected.Version, "v")
	wantArchive := fmt.Sprintf("acs_%s_%s_%s.tar.gz", archiveVersion, record.Target.OS, record.Target.Arch)
	if record.Candidate.Archive != wantArchive {
		return errors.New("authenticated evidence archive name does not match the target")
	}
	if record.Candidate.VersionOutput != "acs "+expected.Version {
		return errors.New("authenticated evidence version output does not match the candidate")
	}

	targetIdentity := record.Target.OS + "/" + record.Target.Arch
	if targetIdentity != expected.Target {
		return errors.New("authenticated evidence target does not match the candidate")
	}
	switch targetIdentity {
	case "darwin/arm64":
		if record.Target.Platform != "macos-26" {
			return errors.New("authenticated evidence is not from a supported authenticated reference target")
		}
	case "linux/amd64":
		if record.Target.Platform != "ubuntu-24.04" {
			return errors.New("authenticated evidence is not from a supported authenticated reference target")
		}
	default:
		return errors.New("authenticated evidence is not from a supported authenticated reference target")
	}
	return nil
}

func validateTimes(record evidence, expected Expectations) error {
	started, err := time.Parse(time.RFC3339, record.StartedAt)
	if err != nil || !strings.HasSuffix(record.StartedAt, "Z") || started.Format(time.RFC3339) != record.StartedAt {
		return errors.New("authenticated evidence start timestamp is invalid")
	}
	completed, err := time.Parse(time.RFC3339, record.CompletedAt)
	if err != nil || !strings.HasSuffix(record.CompletedAt, "Z") || completed.Format(time.RFC3339) != record.CompletedAt {
		return errors.New("authenticated evidence completion timestamp is invalid")
	}
	if completed.Before(started) {
		return errors.New("authenticated evidence completion timestamp precedes start")
	}
	if completed.Sub(started) > maximumRunDuration {
		return errors.New("authenticated evidence run duration exceeds the review limit")
	}
	if !expected.EarliestCompletion.IsZero() && completed.Before(expected.EarliestCompletion) {
		return errors.New("authenticated evidence is stale for the review window")
	}
	if !expected.LatestCompletion.IsZero() && completed.After(expected.LatestCompletion) {
		return errors.New("authenticated evidence is outside the review window")
	}
	return nil
}

func validateCatalog(catalog []catalogReference) error {
	if len(catalog) == 0 {
		return errors.New("authenticated evidence selected catalog is empty")
	}
	identities := make([]string, 0, len(catalog))
	for _, reference := range catalog {
		if reference.Source != "devin-config" && reference.Source != "shared-agents" {
			return errors.New("authenticated evidence selected catalog entry is invalid")
		}
		if !safeRelativeCatalogPath(reference.RelativePath) {
			return errors.New("authenticated evidence selected catalog entry is invalid")
		}
		identities = append(identities, reference.Source+":"+reference.RelativePath)
	}
	if !sort.StringsAreSorted(identities) {
		return errors.New("authenticated evidence selected catalog is not in canonical order")
	}
	for index := 1; index < len(identities); index++ {
		if identities[index] == identities[index-1] {
			return errors.New("authenticated evidence selected catalog contains a duplicate")
		}
	}
	return nil
}

func safeRelativeCatalogPath(path string) bool {
	if path == "" || len(path) > 256 || strings.Contains(path, "\\") {
		return false
	}
	components := strings.Split(path, "/")
	for _, component := range components {
		if component == "" || component == "." || component == ".." {
			return false
		}
		for _, character := range component {
			if character == unicode.ReplacementChar || unicode.IsControl(character) {
				return false
			}
		}
	}
	return true
}

func validateChecks(value checks) error {
	for _, check := range []struct {
		name   string
		passed bool
	}{
		{name: "candidate_identity", passed: value.CandidateIdentity},
		{name: "visual_profile_builder", passed: value.VisualProfileBuilder},
		{name: "terminal_restored", passed: value.TerminalRestored},
		{name: "profile_created", passed: value.ProfileCreated},
		{name: "dry_run", passed: value.DryRun},
		{name: "exact_catalog", passed: value.ExactCatalog},
		{name: "authenticated_launch", passed: value.AuthenticatedLaunch},
		{name: "normal_child_exit", passed: value.NormalChildExit},
		{name: "session_created", passed: value.SessionCreated},
		{name: "session_isolated", passed: value.SessionIsolated},
		{name: "session_cleaned", passed: value.SessionCleaned},
	} {
		if !check.passed {
			return fmt.Errorf("authenticated evidence check %s did not pass", check.name)
		}
	}
	return nil
}

func validateCleanup(target target, value cleanup) error {
	for _, check := range []struct {
		name   string
		passed bool
	}{
		{name: "temporary_profile_removed", passed: value.TemporaryProfileRemoved},
		{name: "session_credentials_removed", passed: value.SessionCredentialsRemoved},
		{name: "candidate_binary_removed", passed: value.CandidateBinaryRemoved},
		{name: "logs_removed", passed: value.LogsRemoved},
	} {
		if !check.passed {
			return fmt.Errorf("authenticated evidence cleanup %s did not pass", check.name)
		}
	}
	if target.OS == "linux" && !value.DisposableHostDestroyed {
		return errors.New("authenticated evidence cleanup disposable_host_destroyed did not pass")
	}
	if target.OS == "darwin" && value.DisposableHostDestroyed {
		return errors.New("authenticated evidence cleanup incorrectly marks the retained macOS host destroyed")
	}
	return nil
}
