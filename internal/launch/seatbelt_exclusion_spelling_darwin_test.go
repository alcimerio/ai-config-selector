//go:build darwin

package launch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeatbeltSpellingInsensitivePatternCoversCaseAndNormalization(t *testing.T) {
	for _, test := range []struct{ path, want string }{
		{path: "/a/B.env", want: "(/[aA]/[bB][.][eE][nN][vV])"},
		{path: "/x/caf\u00e9", want: "(/[xX]/[cC][aA][fF]\u00e9|/[xX]/[cC][aA][fF][eE]\u0301)"},
		{path: "/x/[a]^$", want: "(/[xX]/[[][aA][]][$^][$])"},
	} {
		got, ok := seatbeltSpellingInsensitivePattern(test.path)
		if !ok || got != test.want {
			t.Fatalf("pattern(%q) = %q, %v; want %q", test.path, got, ok, test.want)
		}
	}
	for _, unsupported := range []string{"/x/\"", "/x/\\", "/x/\n"} {
		if _, ok := seatbeltSpellingInsensitivePattern(unsupported); ok {
			t.Fatalf("pattern(%q) unexpectedly produced a rule", unsupported)
		}
	}
}

func TestSeatbeltPolicyDeniesSpellingVariantsOfAbsentExclusions(t *testing.T) {
	request := validatedProcessRequest{
		workspace:        "/private/tmp/workspace",
		sessionDirectory: "/private/tmp/session",
		sessionHome:      "/private/tmp/session/home",
		executable:       "/usr/bin/true",
		filesystemExclusions: []FilesystemExclusion{
			{ID: "absent", path: "/private/tmp/workspace/secrets/token", logicalPath: "/tmp/workspace/secrets/token", firstMissing: "/tmp/workspace/secrets"},
			{ID: "present", path: "/private/tmp/workspace/.env", logicalPath: "/private/tmp/workspace/.env", exists: true},
		},
	}
	policy, _, err := buildSeatbeltPolicy(request)
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range []string{
		`(deny file-read* file-write* (regex #"^(/[tT][mM][pP]/[wW][oO][rR][kK][sS][pP][aA][cC][eE]/[sS][eE][cC][rR][eE][tT][sS]/[tT][oO][kK][eE][nN])(/|$)"))`,
		`(deny file-write* (regex #"^(/[tT][mM][pP]/[wW][oO][rR][kK][sS][pP][aA][cC][eE]/[sS][eE][cC][rR][eE][tT][sS])$"))`,
		`(deny file-read* file-write* (regex #"^(/[pP][rR][iI][vV][aA][tT][eE]/[tT][mM][pP]/[wW][oO][rR][kK][sS][pP][aA][cC][eE]/[sS][eE][cC][rR][eE][tT][sS]/[tT][oO][kK][eE][nN])(/|$)"))`,
		`(deny file-write* (regex #"^(/[pP][rR][iI][vV][aA][tT][eE]/[tT][mM][pP]/[wW][oO][rR][kK][sS][pP][aA][cC][eE]/[sS][eE][cC][rR][eE][tT][sS])$"))`,
	} {
		if !strings.Contains(policy, rule) {
			t.Fatalf("policy is missing %s", rule)
		}
	}
	if strings.Contains(policy, `[wW][oO][rR][kK][sS][pP][aA][cC][eE])$`) {
		t.Fatal("existing ancestor received a spelling rule")
	}
	if strings.Contains(policy, `[eE][nN][vV]`) {
		t.Fatal("existing exclusion received a spelling rule")
	}
}

func TestSeatbeltDeniesSpellingVariantsOfAbsentExclusions(t *testing.T) {
	skipSeatbeltNativeTestBinaryUnderRace(t)
	for _, test := range []struct{ name, excluded, variant string }{
		{name: "exact", excluded: ".envrc", variant: ".envrc"},
		{name: "case-file", excluded: ".envrc", variant: ".ENVRC"},
		{name: "case-directory", excluded: "secrets/token", variant: "Secrets/token"},
		{name: "case-ancestor", excluded: "secrets/token", variant: "SECRETS/other"},
		{name: "unicode-normalization", excluded: "caf\u00e9", variant: "cafe\u0301"},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := seatbeltTestRequest(t)
			request.workspaceAccess = WorkspaceAccessReadWrite
			excluded := filepath.Join(request.workspace, test.excluded)
			firstMissing := filepath.Join(request.workspace, strings.Split(test.excluded, "/")[0])
			request.filesystemExclusions = []FilesystemExclusion{{ID: "absent", path: excluded, logicalPath: excluded, firstMissing: firstMissing}}
			result := filepath.Join(request.sessionDirectory, "create-result")
			request.arguments = []string{"-test.run=^TestSeatbeltExclusionSpellingHelper$", "--", result, filepath.Join(request.workspace, test.variant)}
			settled, err := seatbeltTerminalNativeRun(request)
			if !settled || err != nil {
				t.Fatalf("spelling probe failed: settled=%v err=%v", settled, err)
			}
			outcome := string(readSeatbeltPTYFile(result))
			t.Logf("spelling variant %q of absent exclusion %q: %s", test.variant, test.excluded, outcome)
			if outcome == "created" {
				t.Fatalf("sandbox permitted creating %q despite absent exclusion %q", test.variant, test.excluded)
			}
			if outcome == "" {
				t.Fatal("spelling probe produced no result")
			}
		})
	}
}

func TestSeatbeltExclusionSpellingHelper(t *testing.T) {
	var arguments []string
	for index, argument := range os.Args {
		if argument == "--" {
			arguments = os.Args[index+1:]
			break
		}
	}
	if len(arguments) == 0 {
		return
	}
	if len(arguments) != 2 {
		os.Exit(125)
	}
	outcome := "created"
	if err := os.MkdirAll(filepath.Dir(arguments[1]), 0o700); err != nil {
		outcome = "mkdir-denied: " + err.Error()
	} else if err := os.WriteFile(arguments[1], []byte("probe"), 0o600); err != nil {
		outcome = "write-denied: " + err.Error()
	}
	if err := os.WriteFile(arguments[0], []byte(outcome), 0o600); err != nil {
		os.Exit(90)
	}
	os.Exit(0)
}
