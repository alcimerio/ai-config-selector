//go:build darwin

package codexauthresource_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/codexauth"
	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

func TestNativeRealStoreInstalledTargetComposition(t *testing.T) {
	if os.Getenv("ACS_RUN_NATIVE_AUTH_GATE") != "1" {
		t.Skip("set ACS_RUN_NATIVE_AUTH_GATE=1 to use an isolated temporary Keychain")
	}
	binary := os.Getenv("ACS_TEST_CODEX_BINARY")
	if binary == "" || !filepath.IsAbs(binary) {
		t.Fatal("ACS_TEST_CODEX_BINARY must name the absolute locked target")
	}
	codexauthresource.UseIsolatedTestKeychainForComposition(t)

	root := t.TempDir()
	locks, markers := filepath.Join(root, "seed-locks"), filepath.Join(root, "seed-markers")
	for _, directory := range []string{locks, markers} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	store, err := codexauthresource.New(locks, markers)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := store.AcquireLogin(context.Background(), "installed-target")
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Release()
	workspace := filepath.Join(root, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	created, err := session.Create(filepath.Join(root, "seed-sessions"), workspace, nil)
	if err != nil {
		t.Fatal(err)
	}
	seedRemoved := false
	defer func() {
		if !seedRemoved {
			_ = created.Remove()
		}
	}()
	if err := binding.PublishPrepared(context.Background(), created.RootDirectory(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
		t.Fatal(err)
	}
	if err := created.ProtectForRecovery(); err != nil {
		t.Fatal(err)
	}
	authDirectory := filepath.Join(created.HomeDirectory(), ".codex")
	if err := os.Mkdir(authDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(authDirectory, "auth.json"), compositionAuth(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := binding.MarkRecoverable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := binding.CommitLogin(context.Background(), created.RootDirectory()); err != nil {
		t.Fatal(err)
	}
	if err := created.Remove(); err != nil {
		t.Fatal(err)
	}
	seedRemoved = true
	if err := binding.DeleteMarkerAfterProjectionRemoval(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := binding.Release(); err != nil {
		t.Fatal(err)
	}

	registry, err := codexauth.New(codexauth.Config{
		BinaryPath: binary, ACSHome: filepath.Join(root, "acs"),
		SessionsDirectory: filepath.Join(root, "sessions"), WorkingDirectory: workspace,
	})
	if err != nil {
		t.Fatal(err)
	}
	sessionsDirectory := filepath.Join(root, "sessions")
	status, err := registry.Status(context.Background(), "installed-target")
	if err != nil {
		t.Fatal(err)
	}
	if status.Metadata.Name != "installed-target" || status.Disposition != codexauth.DiscardedProjection {
		t.Fatalf("status = %#v", status)
	}
	entries, err := os.ReadDir(sessionsDirectory)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "session-") {
			t.Fatalf("status retained Session projection %q", entry.Name())
		}
	}
	if disposition, err := registry.Recover(context.Background(), "installed-target"); err != nil || disposition != codexauth.DiscardedProjection {
		t.Fatalf("post-status recovery = (%q, %v)", disposition, err)
	}
}

func compositionAuth(t *testing.T) []byte {
	t.Helper()
	claimsJSON, err := json.Marshal(map[string]any{
		"sub": "subject-fallback",
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_user_id": "synthetic-user", "chatgpt_account_id": "synthetic-workspace",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	claims := base64.RawURLEncoding.EncodeToString(claimsJSON)
	auth, err := json.Marshal(map[string]any{
		"auth_mode": "chatgpt",
		"tokens": map[string]any{
			"id_token": "a." + claims + ".c", "access_token": "synthetic-access",
			"refresh_token": "synthetic-refresh", "account_id": "synthetic-workspace",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return auth
}
