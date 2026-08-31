//go:build darwin

package codexauth

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func TestNativeInstalledTargetContainedStatusWithoutCredentials(t *testing.T) {
	if os.Getenv("ACS_RUN_NATIVE_AUTH_GATE") != "1" {
		t.Skip("set ACS_RUN_NATIVE_AUTH_GATE=1 to run the installed target in Seatbelt")
	}
	binary := os.Getenv("ACS_TEST_CODEX_BINARY")
	if binary == "" || !filepath.IsAbs(binary) {
		t.Fatal("ACS_TEST_CODEX_BINARY must name the absolute locked target")
	}
	if output, err := runInstalledTargetVersion(binary); err != nil || output != "codex-cli "+SupportedCodexVersion {
		t.Fatal("installed target did not report the supported version")
	}

	globalHome := t.TempDir()
	globalCodexHome := filepath.Join(globalHome, ".codex")
	if err := os.Mkdir(globalCodexHome, 0o700); err != nil {
		t.Fatal(err)
	}
	globalSentinel := filepath.Join(globalCodexHome, "auth.json")
	if err := os.WriteFile(globalSentinel, []byte("global-auth-sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", globalHome)

	root := t.TempDir()
	privateRoot := filepath.Join(root, "private")
	workspace := filepath.Join(root, "workspace")
	for _, directory := range []string{privateRoot, workspace} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	projectConfig := filepath.Join(workspace, ".codex")
	if err := os.Mkdir(projectConfig, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(projectConfig, "config.toml"), []byte(
		"cli_auth_credentials_store = \"keyring\"\n"+
			"forced_login_method = \"api\"\n"+
			"forced_chatgpt_workspace_id = \"wrong-workspace\"\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}

	name := CredentialRef("installed-target")
	auth := testChatGPTAuthJSON(t, "synthetic-user", "synthetic-workspace")
	metadata, err := validateAuthJSON(name, auth)
	if err != nil {
		t.Fatal(err)
	}
	provider := newFakeProvider()
	provider.records[name] = credentialRecord{Metadata: metadata, Auth: append([]byte(nil), auth...)}
	registry, err := newRegistry(provider, &fakeLoginRunner{}, newFileIdentityLocker(filepath.Join(privateRoot, "locks")))
	if err != nil {
		t.Fatal(err)
	}
	registry.sessionsDirectory = filepath.Join(privateRoot, "sessions")
	registry.workingDirectory = workspace
	registry.quarantine = newFileBindingQuarantine(filepath.Join(privateRoot, "quarantine"))
	registry.status = newCodexStatusRunner(codexLoginConfig{
		BinaryPath: binary, SupportedVersion: SupportedCodexVersion,
		SessionsDirectory: registry.sessionsDirectory, WorkingDirectory: workspace, PrivateRoot: privateRoot,
	}, launch.NewProcessSandbox())

	status, err := registry.Status(context.Background(), string(name))
	if err != nil {
		for _, sentinel := range []string{"global-auth-sentinel", "access-secret", "refresh-secret", "synthetic-user"} {
			if strings.Contains(err.Error(), sentinel) {
				t.Fatal("contained status error exposed a sentinel")
			}
		}
		t.Fatalf("credential-free installed status failed: %v", err)
	}
	if status.Disposition != DiscardedProjection || provider.replaceCalls != 0 {
		t.Fatalf("installed status disposition = %q, replacements = %d", status.Disposition, provider.replaceCalls)
	}
	contents, err := os.ReadFile(globalSentinel)
	if err != nil || string(contents) != "global-auth-sentinel" {
		t.Fatal("installed status changed global authentication state")
	}
	assertNoSessionDirectories(t, registry.sessionsDirectory)
	if _, exists, err := registry.quarantine.Inspect(context.Background(), name); err != nil || exists {
		t.Fatalf("installed status quarantine = (%v, %v)", exists, err)
	}
}

func runInstalledTargetVersion(binary string) (string, error) {
	output, err := exec.Command(binary, "--version").Output()
	return strings.TrimSpace(string(output)), err
}
