package publication_test

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/release/publication"
)

func TestPlanMovesOnlyForwardThroughAtomicReleaseStates(t *testing.T) {
	candidate, assets := writePublicationCandidate(t)

	plan, err := publication.Plan(candidate, "v0.2.0", "0123456789abcdef0123456789abcdef01234567", "notes\n", nil)
	if err != nil {
		t.Fatalf("plan absent Release: %v", err)
	}
	if plan.State != publication.StateCreateDraft || plan.ReleaseID != 0 || !reflect.DeepEqual(plan.Upload, assetNames(assets)) || plan.Publish {
		t.Fatalf("absent Release plan = %#v", plan)
	}

	partial := releaseJSON(t, assets[:2], true, false)
	plan, err = publication.Plan(candidate, "v0.2.0", "0123456789abcdef0123456789abcdef01234567", "notes\n", strings.NewReader(partial))
	if err != nil {
		t.Fatalf("plan partial draft retry: %v", err)
	}
	if plan.State != publication.StateResumeDraft || plan.ReleaseID != 42 || !reflect.DeepEqual(plan.Upload, assetNames(assets[2:])) || plan.Publish {
		t.Fatalf("partial draft plan = %#v", plan)
	}

	completeDraft := releaseJSON(t, assets, true, false)
	plan, err = publication.Plan(candidate, "v0.2.0", "0123456789abcdef0123456789abcdef01234567", "notes\n", strings.NewReader(completeDraft))
	if err != nil {
		t.Fatalf("plan complete draft: %v", err)
	}
	if plan.State != publication.StatePublishDraft || plan.ReleaseID != 42 || len(plan.Upload) != 0 || !plan.Publish {
		t.Fatalf("complete draft plan = %#v", plan)
	}

	published := releaseJSON(t, assets, false, true)
	plan, err = publication.Plan(candidate, "v0.2.0", "0123456789abcdef0123456789abcdef01234567", "notes\n", strings.NewReader(published))
	if err != nil {
		t.Fatalf("plan unchanged published retry: %v", err)
	}
	if plan.State != publication.StateComplete || plan.ReleaseID != 42 || len(plan.Upload) != 0 || plan.Publish {
		t.Fatalf("published plan = %#v", plan)
	}
}

func TestPlanRejectsReplacementOrConflictingReleaseState(t *testing.T) {
	candidate, assets := writePublicationCandidate(t)
	for _, test := range []struct {
		name   string
		remote string
		want   string
	}{
		{name: "asset digest mismatch", remote: strings.Replace(releaseJSON(t, assets, true, false), assets[0].digest, "sha256:"+strings.Repeat("f", 64), 1), want: "asset digest mismatch"},
		{name: "extra asset", remote: strings.Replace(releaseJSON(t, assets, true, false), `]}`, `,{"name":"unexpected.zip","size":1,"digest":"sha256:`+strings.Repeat("e", 64)+`","state":"uploaded"}]}`, 1), want: "unexpected asset"},
		{name: "wrong source", remote: strings.Replace(releaseJSON(t, assets, true, false), "0123456789abcdef0123456789abcdef01234567", "ffffffffffffffffffffffffffffffffffffffff", 1), want: "source commit"},
		{name: "mutable published release", remote: releaseJSON(t, assets, false, false), want: "not immutable"},
		{name: "prerelease", remote: strings.Replace(releaseJSON(t, assets, true, false), `"prerelease":false`, `"prerelease":true`, 1), want: "prerelease"},
		{name: "wrong release notes", remote: strings.Replace(releaseJSON(t, assets, true, false), `"body":"notes\n"`, `"body":"other notes\n"`, 1), want: "identity"},
		{name: "duplicate API field", remote: strings.Replace(releaseJSON(t, assets, true, false), `"id":42`, `"id":42,"id":43`, 1), want: "duplicate"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := publication.Plan(candidate, "v0.2.0", "0123456789abcdef0123456789abcdef01234567", "notes\n", strings.NewReader(test.remote)); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("conflicting release rejection = %v, want %q", err, test.want)
			}
		})
	}
}

type fixtureAsset struct {
	name   string
	size   int
	digest string
}

func writePublicationCandidate(t *testing.T) (string, []fixtureAsset) {
	t.Helper()
	directory := t.TempDir()
	names := []string{
		"acs_0.2.0_darwin_arm64.tar.gz",
		"acs_0.2.0_darwin_amd64.tar.gz",
		"acs_0.2.0_linux_amd64.tar.gz",
		"acs_0.2.0_linux_arm64.tar.gz",
		"SHA256SUMS",
		"install.sh",
	}
	assets := make([]fixtureAsset, 0, len(names))
	for _, name := range names {
		contents := []byte("fixture " + name + "\n")
		if err := os.WriteFile(filepath.Join(directory, name), contents, 0o600); err != nil {
			t.Fatal(err)
		}
		assets = append(assets, fixtureAsset{name: name, size: len(contents), digest: "sha256:" + fmt.Sprintf("%x", sha256.Sum256(contents))})
	}
	return directory, assets
}

func assetNames(assets []fixtureAsset) []string {
	names := make([]string, 0, len(assets))
	for _, asset := range assets {
		names = append(names, asset.name)
	}
	return names
}

func releaseJSON(t *testing.T, assets []fixtureAsset, draft, immutable bool) string {
	t.Helper()
	var body strings.Builder
	fmt.Fprintf(&body, `{"id":42,"tag_name":"v0.2.0","target_commitish":"0123456789abcdef0123456789abcdef01234567","name":"ACS v0.2.0","body":"notes\n","draft":%t,"prerelease":false,"immutable":%t,"assets":[`, draft, immutable)
	for index, asset := range assets {
		if index != 0 {
			body.WriteByte(',')
		}
		fmt.Fprintf(&body, `{"name":%q,"size":%d,"digest":%q,"state":"uploaded"}`, asset.name, asset.size, asset.digest)
	}
	body.WriteString(`]}`)
	return body.String()
}
