package launch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/devinruntime"
	"github.com/alcimerio/ai-config-selector/internal/linuxprobe"
	"github.com/alcimerio/ai-config-selector/internal/skills"
)

func linuxDevinTestBinary(t *testing.T) string {
	t.Helper()
	path := os.Getenv("ACS_TEST_DEVIN_BINARY")
	if path == "" {
		linuxNativeUnavailable(t, "ACS_TEST_DEVIN_BINARY must name the checksum-locked Linux amd64 target")
	}
	if !filepath.IsAbs(path) {
		t.Fatal("ACS_TEST_DEVIN_BINARY must be absolute")
	}
	return path
}

// Reads real installed bytes, but does not execute the target or claim kernel
// containment. It also proves the generic 64 MiB limit remains unchanged.
func TestLinuxDevinPublishedBytes(t *testing.T) {
	path := linuxDevinTestBinary(t)
	files, err := linuxDevinRuntime(path)
	if err != nil || len(files) != 1 || files[0].node.identity.size != devinruntime.LinuxAMD64BinarySize {
		t.Fatal("installed Devin does not match the locked static Linux bundle")
	}
	if _, err := linuxDiscoverRuntime(path, false); err == nil {
		t.Fatal("large target bypassed the generic runtime bound")
	}
}

func TestLinuxNativeDevinPreflights(t *testing.T) {
	linuxNativePrerequisites(t)
	report := linuxprobe.Probe(context.Background())
	if !report.PrerequisitesPassed() {
		var missing []string
		for _, check := range report.Checks {
			if check.Status != "pass" {
				missing = append(missing, check.ID+":"+check.Code)
			}
		}
		linuxNativeUnavailable(t, strings.Join(missing, ", "))
	}
	binary := linuxDevinTestBinary(t)
	for _, mode := range []string{"version", "auth-absent", "auth-selected", "skills", "mcp", "mcp-project", "mcp-excluded"} {
		t.Run(mode, func(t *testing.T) {
			// Keep a failed/uncertain Session for inspection; t.TempDir would erase
			// quarantine automatically on a helper or supervisor failure.
			root, err := os.MkdirTemp("", "acs-linux-devin-")
			if err != nil {
				t.Fatal(err)
			}
			owner, client := linuxTestSocketpair(t)
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestLinuxDevinSupervisorHelper$")
			cmd.Env = []string{"LANG=C", "LC_ALL=C", "ACS_TEST_DEVIN_MODE=" + mode,
				"ACS_TEST_ROOT=" + root, "ACS_TEST_DEVIN_BINARY=" + binary,
				"HOME=" + root + "/host", "XDG_DATA_HOME=" + root + "/host/data", "XDG_CONFIG_HOME=" + root + "/host/config"}
			cmd.ExtraFiles = []*os.File{client}
			var diagnostics linuxRecipeOutput
			cmd.Stdout, cmd.Stderr = &diagnostics, &diagnostics
			process := linuxNativeStartCommand(t, cmd, diagnostics.String, func() string {
				return linuxNativeReadLogs(filepath.Join(root, "stderr"), filepath.Join(root, "output"))
			})
			_ = client.Close()
			linuxTestByte(t, owner, 'R', process.diagnostics)
			linuxTestWrite(t, owner, 'S')
			linuxTestByte(t, owner, 'E', process.diagnostics)
			linuxTestByte(t, owner, 'X', process.diagnostics)
			if err := process.Wait(); err != nil {
				t.Fatalf("contained Devin %s failed; retained %s: %v\n%s", mode, root, err, process.diagnostics())
			}
			if err := os.RemoveAll(root); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Only this test executable contains the supervisor entry point. Each probe
// uses real bwrap, Landlock/seccomp, cgroup placement and authenticated cleanup.
func TestLinuxDevinSupervisorHelper(t *testing.T) {
	mode, root := os.Getenv("ACS_TEST_DEVIN_MODE"), os.Getenv("ACS_TEST_ROOT")
	if mode == "" {
		return
	}
	write := func(path string, data []byte) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	session, err := CreateProtectedSession(filepath.Join(root, "state", "sessions"))
	if err != nil {
		t.Fatal(err)
	}
	home, tmp, work := filepath.Join(session.RootDir, "home"), filepath.Join(session.RootDir, "tmp"), filepath.Join(root, "work")
	for _, path := range []string{home, tmp, work} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	credentials, err := os.ReadFile("../../acceptance/testdata/devin-synthetic-credentials.toml")
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(credentials)) != "2c8f2a5ad094b05d10c5bf22af343521bb10225c9a9883d818cc0fb6fe814558" {
		t.Fatal("synthetic credential fixture provenance mismatch")
	}
	// The actual host home is never read. These decoys must not be fallback sources.
	write(filepath.Join(root, "host", "data", "devin", "credentials.toml"), credentials)
	write(filepath.Join(root, "host", "config", "devin", "skills", "unselected", "SKILL.md"), []byte("# unselected\n"))
	credentialPath := filepath.Join(home, ".local", "share", "devin", "credentials.toml")
	if mode == "auth-selected" {
		write(credentialPath, credentials)
	}
	for _, relative := range []string{".config/devin/skills/selected-devin", ".agents/skills/selected-agents"} {
		name := filepath.Base(relative)
		write(filepath.Join(home, filepath.FromSlash(relative), "SKILL.md"), []byte("---\nname: "+name+"\ndescription: Synthetic Linux qualification\n---\n# selected\n"))
	}
	write(filepath.Join(home, ".config", "devin", "config.json"), []byte(`{"version":1,"shell":{"setup_complete":true},"theme_mode":"dark","read_config_from":{"cursor":false,"windsurf":false,"claude":false,"opencode":false,"zed":false}}`))
	mcp := func(name string) []byte {
		data, _ := json.Marshal(map[string]any{"mcpServers": map[string]any{name: map[string]any{"command": "/bin/false", "args": []string{}}}})
		return data
	}
	write(filepath.Join(home, ".config", "devin", "mcp_config.json"), mcp("acs-selected-mcp"))
	write(filepath.Join(root, "host", "config", "devin", "mcp_config.json"), mcp("acs-host-mcp"))
	var exclusions []PathExclusionIntent
	if mode == "mcp-project" || mode == "mcp-excluded" {
		for i, name := range []string{"mcp_config.json", "mcp_config.local.json"} {
			write(filepath.Join(work, ".devin", name), mcp(fmt.Sprintf("acs-project-mcp-%d", i)))
			exclusions = append(exclusions, PathExclusionIntent{ID: fmt.Sprintf("mcp-%d", i), Type: PathTypeFile,
				ReferenceKind: PathReferenceWorkspaceRelative, Path: ".devin/" + name})
		}
	}
	f := linuxNativeFixture{base: root, wire: linuxLaunchWire{Home: home, Temporary: tmp, Directory: work, Executable: linuxDevinTestBinary(t)}}
	request, tree := linuxRecipeFixtureRequest(t, f, false)
	request.arguments = map[string][]string{"version": {"--version"}, "auth-absent": {"auth", "status"}, "auth-selected": {"auth", "status"},
		"skills": {"skills", "list", "--json"}, "mcp": {"mcp", "list"}, "mcp-project": {"mcp", "list"}, "mcp-excluded": {"mcp", "list"}}[mode]
	if mode == "mcp-excluded" {
		request.filesystemExclusions, err = ResolveFilesystemExclusions(exclusions, work, request.sessionsDirectory)
		if err != nil {
			t.Fatal(err)
		}
	}
	recipe, err := linuxCompileRecipe(linuxRecipeAdmission{true}, linuxDevinRecipe, request, tree, false)
	if err != nil {
		t.Fatal(err)
	}
	challenge := bytes.Repeat([]byte{0x4d}, RecoveryProofChallengeSize)
	if PrepareSessionCleanupProof(session.RootDir, challenge) != nil {
		t.Fatal("prepare cleanup proof")
	}
	cleanup, err := linuxPrepareCleanup(session, challenge, nil)
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.Create(filepath.Join(root, "output"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	stderr, err := os.Create(filepath.Join(root, "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	defer stderr.Close()
	helper, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	defer helper.Close()
	result, err := linuxRunRecipe(context.Background(), linuxRecipeAdmission{true}, recipe, os.NewFile(3, "owner"), helper,
		[]string{"-test.run=^TestLinuxRecipeInitHelper$", "--", "acs-recipe-init"},
		[3]*os.File{input, output, stderr}, linuxTestLease(t, nil), cleanup)
	proof, proofErr := VerifySessionCleanupProof(session.RootDir, challenge)
	if err != nil || !result.Settled || !result.Exited || proofErr != nil || !proof {
		t.Fatalf("Devin probe did not prove complete settlement; retain Session: result=%+v error=%v proof=%t proof error=%v", result, err, proof, proofErr)
	}
	data, err := os.ReadFile(output.Name())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Status.Exited() || mode != "auth-absent" && result.Status.ExitStatus() != 0 {
		t.Fatalf("Devin probe exit status: %v", result.Status)
	}
	switch mode {
	case "version":
		if !strings.Contains(string(data), devinruntime.LinuxAMD64Version) {
			t.Fatal("locked target version mismatch")
		}
	case "auth-absent", "auth-selected":
		if devinruntime.AuthenticationLoggedIn(data) != (mode == "auth-selected") || len(data) == 0 {
			t.Fatal("credential preflight did not distinguish the allowlisted file from ambient XDG credentials")
		}
		if mode == "auth-selected" {
			info, err := os.Stat(credentialPath)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatal("credential projection lost private mode")
			}
		}
	case "skills":
		observed, failure := devinruntime.InterpretCatalog(home, work, data)
		want := []skills.SkillReference{{Source: devinruntime.GlobalSourceDevinConfig, RelativePath: "selected-devin"},
			{Source: devinruntime.GlobalSourceSharedAgents, RelativePath: "selected-agents"}}
		if failure != 0 || observed.HasUnmanagedSource() || !devinruntime.EqualSkillReferences(want, observed.ManagedReferences()) {
			t.Fatal("Linux Devin did not report the exact selected global Skills")
		}
	default:
		if !strings.Contains(string(data), "acs-selected-mcp") || strings.Contains(string(data), "acs-host-mcp") {
			t.Fatal("selected/host MCP discovery mismatch")
		}
		for i := range 2 {
			if strings.Contains(string(data), fmt.Sprintf("acs-project-mcp-%d", i)) != (mode == "mcp-project") {
				t.Fatal("project MCP positive control/exclusion mismatch")
			}
		}
	}
	if bytes.Contains(data, []byte("ACS_SYNTHETIC_SESSION_TOKEN_NOT_VALID")) {
		t.Fatal("preflight printed credential bytes")
	}
	if err := session.Remove(); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}
