package scripts

import (
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	publicationSource    = "0123456789abcdef0123456789abcdef01234567"
	publicationTagObject = "abcdef0123456789abcdef0123456789abcdef01"
)

func TestPublisherFailsBeforeMutationWhenImmutableReleasesAreDisabled(t *testing.T) {
	candidate := publicationCandidate(t)
	notes := publicationNotes(t)
	tools, log := fakeReadOnlyGH(t, "false", "true", "")
	output, err := publicationCommand(t, candidate, notes, tools, log).CombinedOutput()
	if err == nil || !strings.Contains(string(output), "immutable Releases are not enabled") {
		t.Fatalf("immutable-setting rejection = %v, output=%q", err, output)
	}
	assertNoPublicationMutation(t, log)
}

func TestPublisherLeavesAnExactImmutableReleaseUnchanged(t *testing.T) {
	candidate := publicationCandidate(t)
	notes := publicationNotes(t)
	release := publicationReleaseJSON(t, candidate, 6, false, true)
	tools, log := fakeReadOnlyGH(t, "true", "true", release)
	output, err := publicationCommand(t, candidate, notes, tools, log).CombinedOutput()
	if err != nil {
		t.Fatalf("exact immutable retry failed: %v; output=%q", err, output)
	}
	if !strings.Contains(string(output), "status=unchanged") {
		t.Fatalf("retry output = %q", output)
	}
	assertNoPublicationMutation(t, log)
}

func TestPublisherRejectsIncompleteTagProtectionBeforeMutation(t *testing.T) {
	candidate := publicationCandidate(t)
	notes := publicationNotes(t)
	tools, log := fakeReadOnlyGH(t, "true", "false", "")
	output, err := publicationCommand(t, candidate, notes, tools, log).CombinedOutput()
	if err == nil || !strings.Contains(string(output), "tag update and deletion protection is incomplete") {
		t.Fatalf("tag-policy rejection = %v, output=%q", err, output)
	}
	assertNoPublicationMutation(t, log)
}

func TestPublisherRejectsUnsafeTagIdentityAndAuthorizationBeforeMutation(t *testing.T) {
	candidate := publicationCandidate(t)
	notes := publicationNotes(t)
	for _, test := range []struct {
		name              string
		creationProtected string
		tagObject         string
		targetSource      string
		mainStatus        string
		want              string
	}{
		{name: "creation rule missing fields or bypass", creationProtected: "false", tagObject: publicationTagObject, targetSource: publicationSource, mainStatus: "ahead", want: "creation authorization is incomplete"},
		{name: "remote tag moved", creationProtected: "true", tagObject: strings.Repeat("f", 40), targetSource: publicationSource, mainStatus: "ahead", want: "tag object does not match"},
		{name: "remote tag target changed", creationProtected: "true", tagObject: publicationTagObject, targetSource: strings.Repeat("e", 40), mainStatus: "ahead", want: "source commit does not match"},
		{name: "source outside protected main", creationProtected: "true", tagObject: publicationTagObject, targetSource: publicationSource, mainStatus: "diverged", want: "not contained in protected main"},
	} {
		t.Run(test.name, func(t *testing.T) {
			tools, log := fakeReadOnlyGHWithPolicy(t, "true", "true", test.creationProtected, test.tagObject, test.targetSource, test.mainStatus, "")
			output, err := publicationCommand(t, candidate, notes, tools, log).CombinedOutput()
			if err == nil || !strings.Contains(string(output), test.want) {
				t.Fatalf("unsafe tag rejection = %v, output=%q", err, output)
			}
			assertNoPublicationMutation(t, log)
		})
	}
}

func TestPublisherCreatesOrResumesDraftBeforeOneFinalPublish(t *testing.T) {
	for _, test := range []struct {
		name        string
		initial     string
		assetCount  int
		wantPOST    int
		wantUploads int
	}{
		{name: "absent Release", initial: "absent", assetCount: 0, wantPOST: 1, wantUploads: 6},
		{name: "partial draft retry", initial: "partial", assetCount: 2, wantPOST: 0, wantUploads: 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := publicationCandidate(t)
			notes := publicationNotes(t)
			tools, log := fakeTransitionGH(t, candidate, test.initial, test.assetCount, test.wantUploads)
			output, err := publicationCommand(t, candidate, notes, tools, log).CombinedOutput()
			if err != nil {
				t.Fatalf("forward publication failed: %v; output=%q", err, output)
			}
			if !strings.Contains(string(output), "status=published") {
				t.Fatalf("publication output = %q", output)
			}
			calls := readCalls(t, log)
			if got := strings.Count(calls, "api --method POST repos/owner/repository/releases "); got != test.wantPOST {
				t.Errorf("draft create count = %d, want %d; calls=%q", got, test.wantPOST, calls)
			}
			if got := strings.Count(calls, "release upload "); got != test.wantUploads {
				t.Errorf("asset upload count = %d, want %d; calls=%q", got, test.wantUploads, calls)
			}
			if got := strings.Count(calls, "api --method PATCH repos/owner/repository/releases/42 "); got != 1 {
				t.Errorf("publish transition count = %d, want 1; calls=%q", got, calls)
			}
			lastUpload := strings.LastIndex(calls, "release upload ")
			publish := strings.Index(calls, "api --method PATCH ")
			if lastUpload >= publish {
				t.Errorf("Release published before all uploads: %q", calls)
			}
		})
	}
}

func publicationCommand(t *testing.T, candidate, notes, tools, log string) *exec.Cmd {
	t.Helper()
	repository, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", "scripts/publish-release.sh", "v0.2.0", publicationSource, publicationTagObject, candidate, notes)
	command.Dir = repository
	command.Env = append(os.Environ(),
		"PATH="+tools+string(os.PathListSeparator)+os.Getenv("PATH"),
		"GITHUB_REPOSITORY=owner/repository", "GH_TOKEN=test-token", "ACS_RELEASE_TAG_RULESET_ID=7", "ACS_RELEASE_TAG_CREATION_RULESET_ID=8", "FAKE_GH_LOG="+log,
	)
	return command
}

func fakeReadOnlyGH(t *testing.T, immutable, protected, release string) (string, string) {
	return fakeReadOnlyGHWithPolicy(t, immutable, protected, "true", publicationTagObject, publicationSource, "ahead", release)
}

func fakeReadOnlyGHWithPolicy(t *testing.T, immutable, protected, creationProtected, tagObject, targetSource, mainStatus, release string) (string, string) {
	t.Helper()
	directory := t.TempDir()
	log := filepath.Join(directory, "calls")
	releasePath := writeFixture(t, directory, "release.json", release)
	script := fakePolicyCases(immutable, protected, creationProtected, tagObject, targetSource, mainStatus) + `
  "repos/owner/repository/releases/tags/v0.2.0") cat "` + releasePath + `" ;;
  *) exit 64 ;;
esac
`
	writeExecutable(t, directory, "gh", script)
	return directory, log
}

func fakeTransitionGH(t *testing.T, candidate, initial string, initialAssets, requiredUploads int) (string, string) {
	t.Helper()
	directory := t.TempDir()
	log := filepath.Join(directory, "calls")
	state := writeFixture(t, directory, "state", initial+"\n")
	count := writeFixture(t, directory, "count", "0\n")
	zero := writeFixture(t, directory, "zero.json", publicationReleaseJSON(t, candidate, 0, true, false))
	partial := writeFixture(t, directory, "partial.json", publicationReleaseJSON(t, candidate, initialAssets, true, false))
	complete := writeFixture(t, directory, "complete.json", publicationReleaseJSON(t, candidate, 6, true, false))
	published := writeFixture(t, directory, "published.json", publicationReleaseJSON(t, candidate, 6, false, true))
	script := fakePolicyCases("true", "true", "true", publicationTagObject, publicationSource, "ahead") + `
  "--paginate") exit 0 ;;
  "repos/owner/repository/releases/tags/v0.2.0")
    current=$(tr -d '\n' <"` + state + `")
    case "$current" in
      absent) exit 1 ;;
      partial) cat "` + partial + `" ;;
      complete) cat "` + complete + `" ;;
      published) cat "` + published + `" ;;
      *) exit 65 ;;
    esac ;;
  "--method")
    case "$3 $4" in
      "POST repos/owner/repository/releases")
        printf '%s\n' complete >"` + state + `"
        cat "` + zero + `" ;;
      "PATCH repos/owner/repository/releases/42")
        printf '%s\n' published >"` + state + `"
        cat "` + published + `" ;;
      *) exit 66 ;;
    esac ;;
  *) exit 64 ;;
esac
`
	// Insert release-upload handling before the API case dispatch.
	script = strings.Replace(script, "case \"$2\" in", `if [ "$1" = release ] && [ "$2" = upload ]; then
  observed=$(tr -d '\n' <"`+count+`")
  observed=$((observed + 1))
  printf '%s\n' "$observed" >"`+count+`"
  if [ "$observed" -eq `+fmt.Sprint(requiredUploads)+` ]; then printf '%s\n' complete >"`+state+`"; fi
  exit 0
fi
case "$2" in`, 1)
	writeExecutable(t, directory, "gh", script)
	return directory, log
}

func fakePolicyCases(immutable, protected, creationProtected, tagObject, targetSource, mainStatus string) string {
	return `#!/bin/sh
printf '%s\n' "$*" >>"$FAKE_GH_LOG"
case "$2" in
  "repos/owner/repository/immutable-releases") printf '%s\n' "` + immutable + `" ;;
  "repos/owner/repository/rulesets/7") printf '%s\n' "` + protected + `" ;;
  "repos/owner/repository/rulesets/8") printf '%s\n' "` + creationProtected + `" ;;
  "repos/owner/repository/git/ref/tags/v0.2.0") printf 'tag\t%s\n' "` + tagObject + `" ;;
  "repos/owner/repository/git/tags/` + publicationTagObject + `") printf 'commit\t%s\n' "` + targetSource + `" ;;
  "repos/owner/repository/compare/` + publicationSource + `...main") printf '%s\n' "` + mainStatus + `" ;;
`
}

func assertNoPublicationMutation(t *testing.T, log string) {
	t.Helper()
	calls := readCalls(t, log)
	if strings.Contains(calls, "--method") || strings.Contains(calls, "release upload") {
		t.Fatalf("publisher attempted mutation: %q", calls)
	}
}

func readCalls(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func writeFixture(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeExecutable(t *testing.T, directory, name, contents string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(contents), 0o700); err != nil {
		t.Fatal(err)
	}
}

func publicationCandidate(t *testing.T) string {
	t.Helper()
	directory := realTemporaryDirectory(t)
	writePromotedCandidate(t, directory)
	return directory
}

func publicationNotes(t *testing.T) string {
	t.Helper()
	return writeFixture(t, t.TempDir(), "notes.md", "Release notes\n")
}

func publicationReleaseJSON(t *testing.T, candidate string, assetCount int, draft, immutable bool) string {
	t.Helper()
	names := []string{
		"acs_0.2.0_darwin_arm64.tar.gz", "acs_0.2.0_darwin_amd64.tar.gz",
		"acs_0.2.0_linux_amd64.tar.gz", "acs_0.2.0_linux_arm64.tar.gz",
		"SHA256SUMS", "install.sh",
	}
	var assets strings.Builder
	for index, name := range names[:assetCount] {
		contents, err := os.ReadFile(filepath.Join(candidate, name))
		if err != nil {
			t.Fatal(err)
		}
		if index != 0 {
			assets.WriteByte(',')
		}
		fmt.Fprintf(&assets, `{"name":%q,"size":%d,"digest":"sha256:%x","state":"uploaded"}`, name, len(contents), sha256.Sum256(contents))
	}
	return fmt.Sprintf(`{"id":42,"tag_name":"v0.2.0","target_commitish":"%s","name":"ACS v0.2.0","body":"Release notes\n","draft":%t,"prerelease":false,"immutable":%t,"assets":[%s]}`, publicationSource, draft, immutable, assets.String())
}
