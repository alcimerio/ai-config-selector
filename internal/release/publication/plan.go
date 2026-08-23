// Package publication defines the forward-only state transitions for staging
// and atomically publishing one immutable ACS Release Artifact Set.
package publication

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const maximumReleaseResponseSize = 2 << 20

var (
	canonicalVersionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	commitPattern           = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type State string

const (
	StateCreateDraft  State = "create-draft"
	StateResumeDraft  State = "resume-draft"
	StatePublishDraft State = "publish-draft"
	StateComplete     State = "complete"
)

// Plan contains only allowlisted asset names and a forward-only publication
// action. It never authorizes deletion or replacement.
type PublicationPlan struct {
	State     State
	ReleaseID int64
	Upload    []string
	Publish   bool
}

type release struct {
	ID              int64          `json:"id"`
	TagName         string         `json:"tag_name"`
	TargetCommitish string         `json:"target_commitish"`
	Name            string         `json:"name"`
	Body            string         `json:"body"`
	Draft           bool           `json:"draft"`
	Prerelease      bool           `json:"prerelease"`
	Immutable       bool           `json:"immutable"`
	Assets          []releaseAsset `json:"assets"`
}

type releaseAsset struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	Digest string `json:"digest"`
	State  string `json:"state"`
}

type localAsset struct {
	name   string
	size   int64
	digest string
}

// Plan compares the exact local Release Artifact Set with the current GitHub
// Release state. A nil remote reader means no Release exists for the tag.
func Plan(candidateDirectory, version, sourceCommit, releaseNotes string, remote io.Reader) (PublicationPlan, error) {
	if !canonicalVersionPattern.MatchString(version) || !commitPattern.MatchString(sourceCommit) || strings.TrimSpace(releaseNotes) == "" {
		return PublicationPlan{}, errors.New("publication identity is invalid")
	}
	local, err := inspectCandidate(candidateDirectory, version)
	if err != nil {
		return PublicationPlan{}, err
	}
	if remote == nil {
		return PublicationPlan{State: StateCreateDraft, Upload: localAssetNames(local)}, nil
	}

	current, err := decodeRelease(remote)
	if err != nil {
		return PublicationPlan{}, err
	}
	if current.ID <= 0 || current.TagName != version || current.TargetCommitish != sourceCommit || current.Name != "ACS "+version || current.Body != releaseNotes {
		return PublicationPlan{}, errors.New("existing Release identity or source commit does not match")
	}
	if current.Prerelease {
		return PublicationPlan{}, errors.New("existing Release is unexpectedly a prerelease")
	}

	existing := make(map[string]releaseAsset, len(current.Assets))
	for _, asset := range current.Assets {
		if _, known := findLocalAsset(local, asset.Name); !known {
			return PublicationPlan{}, errors.New("existing Release contains an unexpected asset")
		}
		if _, duplicate := existing[asset.Name]; duplicate {
			return PublicationPlan{}, errors.New("existing Release contains a duplicate asset")
		}
		existing[asset.Name] = asset
	}

	missing := make([]string, 0, len(local))
	for _, expected := range local {
		observed, exists := existing[expected.name]
		if !exists {
			missing = append(missing, expected.name)
			continue
		}
		if observed.State != "uploaded" || observed.Size != expected.size || observed.Digest != expected.digest {
			return PublicationPlan{}, errors.New("existing Release asset digest mismatch")
		}
	}

	if !current.Draft {
		if !current.Immutable {
			return PublicationPlan{}, errors.New("published Release is not immutable")
		}
		if len(missing) != 0 {
			return PublicationPlan{}, errors.New("published Release artifact set is incomplete")
		}
		return PublicationPlan{State: StateComplete, ReleaseID: current.ID}, nil
	}
	if current.Immutable {
		return PublicationPlan{}, errors.New("draft Release has conflicting immutable state")
	}
	if len(missing) != 0 {
		return PublicationPlan{State: StateResumeDraft, ReleaseID: current.ID, Upload: missing}, nil
	}
	return PublicationPlan{State: StatePublishDraft, ReleaseID: current.ID, Publish: true}, nil
}

func inspectCandidate(directory, version string) ([]localAsset, error) {
	names := expectedAssetNames(version)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, errors.New("publication candidate directory is unavailable")
	}
	actual := make([]string, 0, len(entries))
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("publication candidate contains an unsafe entry")
		}
		actual = append(actual, entry.Name())
	}
	sort.Strings(actual)
	sortedExpected := append([]string(nil), names...)
	sort.Strings(sortedExpected)
	if !equalStrings(actual, sortedExpected) {
		return nil, errors.New("publication candidate asset names are incomplete or unexpected")
	}

	assets := make([]localAsset, 0, len(names))
	for _, name := range names {
		contents, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return nil, errors.New("publication candidate asset could not be read")
		}
		assets = append(assets, localAsset{
			name:   name,
			size:   int64(len(contents)),
			digest: "sha256:" + fmt.Sprintf("%x", sha256.Sum256(contents)),
		})
	}
	return assets, nil
}

func expectedAssetNames(version string) []string {
	archiveVersion := strings.TrimPrefix(version, "v")
	return []string{
		fmt.Sprintf("acs_%s_darwin_arm64.tar.gz", archiveVersion),
		fmt.Sprintf("acs_%s_darwin_amd64.tar.gz", archiveVersion),
		"SHA256SUMS",
		"install.sh",
	}
}

func decodeRelease(input io.Reader) (release, error) {
	contents, err := io.ReadAll(io.LimitReader(input, maximumReleaseResponseSize+1))
	if err != nil || len(contents) > maximumReleaseResponseSize {
		return release{}, errors.New("GitHub Release response contains trailing or oversized content")
	}
	if err := rejectDuplicateFields(contents); err != nil {
		return release{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	var current release
	if err := decoder.Decode(&current); err != nil {
		return release{}, errors.New("GitHub Release response is malformed")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return release{}, errors.New("GitHub Release response contains trailing or oversized content")
	}
	return current, nil
}

func rejectDuplicateFields(contents []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := inspectJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("GitHub Release response contains trailing content")
	}
	return nil
}

func inspectJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return errors.New("GitHub Release response is malformed")
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
				return errors.New("GitHub Release response is malformed")
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return errors.New("GitHub Release response contains a duplicate or malformed field")
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
		return errors.New("GitHub Release response is malformed")
	}
	if _, err := decoder.Token(); err != nil {
		return errors.New("GitHub Release response is malformed")
	}
	return nil
}

func localAssetNames(assets []localAsset) []string {
	names := make([]string, 0, len(assets))
	for _, asset := range assets {
		names = append(names, asset.name)
	}
	return names
}

func findLocalAsset(assets []localAsset, name string) (localAsset, bool) {
	for _, asset := range assets {
		if asset.name == name {
			return asset, true
		}
	}
	return localAsset{}, false
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
