package authenticatedevidence_test

import (
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/release/authenticatedevidence"
)

func TestValidateSetRequiresBothCandidateMatchedReferenceTargets(t *testing.T) {
	darwin := validDarwinEvidence
	linux := strings.NewReplacer(
		"acs_0.2.0_darwin_arm64.tar.gz", "acs_0.2.0_linux_amd64.tar.gz",
		`"platform": "macos-26"`, `"platform": "ubuntu-24.04"`,
		`"os": "darwin"`, `"os": "linux"`,
		`"arch": "arm64"`, `"arch": "amd64"`,
		`"archive_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"`, `"archive_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"`,
		`"disposable_host_destroyed": false`, `"disposable_host_destroyed": true`,
	).Replace(validDarwinEvidence)
	envelope := `{"schema_version":1,"darwin_arm64":` + darwin + `,"linux_amd64":` + linux + `}`

	err := authenticatedevidence.ValidateSet(strings.NewReader(envelope), authenticatedevidence.SetExpectations{
		DarwinArm64: authenticatedevidence.Expectations{
			Version: "v0.2.0", SourceCommit: "0123456789abcdef0123456789abcdef01234567", Target: "darwin/arm64",
			ArchiveSHA256: strings.Repeat("a", 64), ArtifactSetSHA256: strings.Repeat("b", 64),
		},
		LinuxAMD64: authenticatedevidence.Expectations{
			Version: "v0.2.0", SourceCommit: "0123456789abcdef0123456789abcdef01234567", Target: "linux/amd64",
			ArchiveSHA256: strings.Repeat("c", 64), ArtifactSetSHA256: strings.Repeat("b", 64),
		},
	})
	if err != nil {
		t.Fatalf("complete authenticated evidence set rejected: %v", err)
	}
}

func TestValidateSetRejectsIncompleteOrAmbiguousEvidence(t *testing.T) {
	expectations := authenticatedevidence.SetExpectations{
		DarwinArm64: authenticatedevidence.Expectations{
			Version: "v0.2.0", SourceCommit: "0123456789abcdef0123456789abcdef01234567", Target: "darwin/arm64",
			ArchiveSHA256: strings.Repeat("a", 64), ArtifactSetSHA256: strings.Repeat("b", 64),
		},
		LinuxAMD64: authenticatedevidence.Expectations{
			Version: "v0.2.0", SourceCommit: "0123456789abcdef0123456789abcdef01234567", Target: "linux/amd64",
			ArchiveSHA256: strings.Repeat("c", 64), ArtifactSetSHA256: strings.Repeat("b", 64),
		},
	}
	for _, test := range []struct {
		name string
		body string
		want string
	}{
		{name: "missing Linux", body: `{"schema_version":1,"darwin_arm64":` + validDarwinEvidence + `}`, want: "malformed"},
		{name: "extra target", body: `{"schema_version":1,"darwin_arm64":{},"linux_amd64":{},"linux_arm64":{}}`, want: "unsupported field"},
		{name: "duplicate target", body: `{"schema_version":1,"darwin_arm64":{},"darwin_arm64":{},"linux_amd64":{}}`, want: "duplicate field"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := authenticatedevidence.ValidateSet(strings.NewReader(test.body), expectations)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("invalid evidence set rejection = %v, want %q", err, test.want)
			}
		})
	}
}
