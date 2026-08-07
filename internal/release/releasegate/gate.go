// Package releasegate binds the complete authenticated evidence set to the
// exact candidate bytes selected by an annotated release tag.
package releasegate

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/release/authenticatedevidence"
)

type Expectations struct {
	Version            string
	SourceCommit       string
	CandidateDirectory string
	EarliestCompletion time.Time
	LatestCompletion   time.Time
}

func Validate(evidence io.Reader, expected Expectations) error {
	manifestDigest, err := regularFileDigest(filepath.Join(expected.CandidateDirectory, "SHA256SUMS"))
	if err != nil {
		return errors.New("release candidate manifest is unavailable or unsafe")
	}
	archiveVersion := strings.TrimPrefix(expected.Version, "v")
	darwinDigest, err := regularFileDigest(filepath.Join(expected.CandidateDirectory, fmt.Sprintf("acs_%s_darwin_arm64.tar.gz", archiveVersion)))
	if err != nil {
		return errors.New("darwin/arm64 release candidate is unavailable or unsafe")
	}
	linuxDigest, err := regularFileDigest(filepath.Join(expected.CandidateDirectory, fmt.Sprintf("acs_%s_linux_amd64.tar.gz", archiveVersion)))
	if err != nil {
		return errors.New("linux/amd64 release candidate is unavailable or unsafe")
	}

	common := func(target, archiveDigest string) authenticatedevidence.Expectations {
		return authenticatedevidence.Expectations{
			Version:            expected.Version,
			SourceCommit:       expected.SourceCommit,
			Target:             target,
			ArchiveSHA256:      archiveDigest,
			ArtifactSetSHA256:  manifestDigest,
			EarliestCompletion: expected.EarliestCompletion,
			LatestCompletion:   expected.LatestCompletion,
		}
	}
	return authenticatedevidence.ValidateSet(evidence, authenticatedevidence.SetExpectations{
		DarwinArm64: common("darwin/arm64", darwinDigest),
		LinuxAMD64:  common("linux/amd64", linuxDigest),
	})
}

func regularFileDigest(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(contents)), nil
}
