package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/authority"
	"github.com/alcimerio/ai-config-selector/internal/codexauthresource"
	"github.com/alcimerio/ai-config-selector/internal/codexcompat"
	"github.com/alcimerio/ai-config-selector/internal/launch"
)

func linuxCodexServiceFixture(t *testing.T, choice ...codexauthresource.ProviderID) (*CodexAuthService, codexLoginConfig) {
	t.Helper()
	// /tmp can be mapped to an untrusted owner on portable test hosts. Match
	// the provider suite's owned, ignored directory without relaxing checks.
	if err := os.MkdirAll("dist", 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("dist", ".linux-codex-")
	if err != nil {
		t.Fatal(err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root); _ = os.Remove("dist") })
	for _, key := range []string{"HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR"} {
		t.Setenv(key, filepath.Join(root, key))
	}
	provider := codexauthresource.ProviderFile
	if len(choice) != 0 {
		provider = choice[0]
	}
	if provider != "" {
		if err := codexauthresource.SelectProvider(provider); err != nil {
			t.Fatal(err)
		}
	}
	workspace := filepath.Join(root, "work")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "codex")
	for _, path := range []string{binary, binary + "-code-mode-host"} {
		if err := os.WriteFile(path, []byte("synthetic executable; never run"), 0500); err != nil {
			t.Fatal(err)
		}
	}
	service, err := NewCodexAuth(CodexAuthConfig{BinaryPath: binary, ACSHome: filepath.Join(root, "acs"),
		SessionsDirectory: filepath.Join(root, "acs", "sessions"), WorkingDirectory: workspace})
	if err != nil {
		t.Fatal(err)
	}
	config := codexLoginConfig{BinaryPath: binary, SessionsDirectory: service.sessionsDirectory, WorkingDirectory: workspace, PrivateRoot: filepath.Join(root, "acs")}
	return service, config
}

// Real file provider, locks, projection and executor lifecycle; only target
// behavior and settlement are mocked. No synthetic bytes enter native admission.
func TestLinuxCodexFileProviderLifecycle(t *testing.T) {
	for _, pair := range codexcompat.LinuxAMD64Pairs() {
		t.Run(pair.Version, func(t *testing.T) {
			ctx := context.Background()
			service, config := linuxCodexServiceFixture(t)
			auth := testChatGPTAuthJSON(t, "synthetic-user", "synthetic-workspace")
			login := &fakeLoginSandbox{version: pair.Version, auth: auth}
			service.login = newCodexLoginRunner(config, login)
			if _, err := service.Login(ctx, CodexLoginRequest{Name: "selected", DeviceAuth: true}); err != nil {
				t.Fatal(err)
			}
			assertNoSessionDirectories(t, service.sessionsDirectory)
			global := filepath.Join(os.Getenv("HOME"), ".codex", "auth.json")
			if err := os.MkdirAll(filepath.Dir(global), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(global, []byte("global-auth-sentinel"), 0600); err != nil {
				t.Fatal(err)
			}
			var current = bytes.Clone(auth)
			for _, operation := range []string{"status", "interactive", "substitution"} {
				wanted := bytes.Replace(current, []byte("access-secret"), []byte("access-refreshed"), 1)
				if operation == "interactive" {
					wanted = bytes.Replace(current, []byte("access-refreshed"), []byte("access-interactive"), 1)
				}
				if operation == "substitution" {
					wanted = testChatGPTAuthJSON(t, "other-user", "other-workspace")
				}
				observed := false
				sandbox := &executionSandbox{version: pair.Version, mutate: func(home string) error {
					observed = true
					path := filepath.Join(home, ".codex", "auth.json")
					got, err := os.ReadFile(path)
					info, statErr := os.Stat(path)
					if err != nil || statErr != nil || info.Mode().Perm() != 0600 || !bytes.Equal(got, current) {
						t.Fatal("selected projection bytes or mode changed")
					}
					return os.WriteFile(path, wanted, 0600)
				}}
				var err error
				if operation == "interactive" {
					service.execution = newCodexExecutionRunner(config, sandbox)
					plan := authority.New(nil, launch.WorkspaceAccessReadOnly, "codex", authority.TargetRequirements{
						Recipe: authority.RecipeCodex, Executable: config.BinaryPath}).WithAuthRef("selected")
					_, err = service.ExecuteCodex(ctx, CodexRequest{ResolvedPlan: &plan})
				} else {
					service.status = newCodexStatusRunner(config, sandbox)
					_, err = service.Status(ctx, "selected")
				}
				if operation == "substitution" {
					if !errors.Is(err, ErrProjectedAuthInvalid) {
						t.Fatalf("identity substitution: %v", err)
					}
				} else {
					if err != nil {
						t.Fatalf("%s: %v", operation, err)
					}
					current = wanted
				}
				if !observed {
					t.Fatal("target operation was not exercised")
				}
				assertNoSessionDirectories(t, service.sessionsDirectory)
			}
			// A reopened provider must return the durable refresh, never the
			// substituted identity. Inspect through a fresh private projection.
			reopened, err := codexauthresource.New(filepath.Join(config.PrivateRoot, "locks", "codex-auth"), filepath.Join(config.PrivateRoot, "quarantine", "codex-auth"))
			if err != nil {
				t.Fatal(err)
			}
			service.resources = productionAuthResources{store: reopened}
			service.status = &fakeStatusRunner{result: statusRunResult{cleanupProven: true}, mutate: func(home string) error {
				got, err := os.ReadFile(filepath.Join(home, ".codex", "auth.json"))
				if err != nil || !bytes.Equal(got, current) {
					t.Fatal("durable file provider did not retain the selected identity")
				}
				return nil
			}}
			if _, err := service.Status(ctx, "selected"); err != nil {
				t.Fatal(err)
			}
			if _, err := service.Status(ctx, "missing"); !errors.Is(err, ErrIdentityNotFound) {
				t.Fatal("global credentials supplied a missing named identity")
			}
			var retained string
			service.status = &fakeStatusRunner{result: statusRunResult{err: ErrBindingQuarantined, cleanupProven: false}, mutate: func(home string) error {
				retained = home
				return os.WriteFile(filepath.Join(home, ".codex", "auth.json"), auth, 0600)
			}}
			if _, err := service.Status(ctx, "selected"); !errors.Is(err, ErrBindingQuarantined) {
				t.Fatalf("uncertain cleanup: %v", err)
			}
			service.verifyCleanup = func(string, []byte) (bool, error) { return false, nil }
			if _, err := service.Recover(ctx, "selected"); !errors.Is(err, ErrIdentityBusy) {
				t.Fatal("recovery accepted missing settlement proof")
			}
			if err := service.Logout(ctx, "selected"); !errors.Is(err, ErrIdentityBusy) {
				t.Fatal("quarantine released the named identity")
			}
			if _, err := os.Stat(filepath.Join(retained, ".codex", "auth.json")); err != nil {
				t.Fatal("uncertain cleanup deleted the projection")
			}
			if got, err := os.ReadFile(global); err != nil || string(got) != "global-auth-sentinel" {
				t.Fatal("operation changed global auth")
			}
		})
	}
}

func TestLinuxCodexRecipeMatchesSharedExecutionContract(t *testing.T) {
	for _, workspace := range []string{"", "synthetic-workspace"} {
		if !reflect.DeepEqual(codexExecutionArguments(workspace, "/work"), codexcompat.LinuxArguments(workspace, "/work", "interactive")) {
			t.Fatal("Linux recipe drifted from the shared Codex security options")
		}
	}
}

func TestLinuxCodexNeverFallsBackToGlobalAuth(t *testing.T) {
	for _, provider := range []codexauthresource.ProviderID{"", codexauthresource.ProviderSecretService} {
		t.Run(string(provider), func(t *testing.T) {
			service, config := linuxCodexServiceFixture(t, provider)
			sandbox := &fakeLoginSandbox{version: codexcompat.CurrentVersion, auth: testChatGPTAuthJSON(t, "global", "global")}
			service.login = newCodexLoginRunner(config, sandbox)
			path := filepath.Join(os.Getenv("HOME"), ".codex", "auth.json")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, sandbox.auth, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := service.Login(context.Background(), CodexLoginRequest{Name: "selected", DeviceAuth: true}); !errors.Is(err, ErrProviderUnavailable) {
				t.Fatalf("unavailable provider accepted: %v", err)
			}
			if len(sandbox.requests) != 0 {
				t.Fatal("unavailable provider ran a target")
			}
			if _, err := os.Stat(service.sessionsDirectory); !os.IsNotExist(err) {
				t.Fatal("unavailable provider created a Session")
			}
			if _, err := os.Stat(os.Getenv("XDG_STATE_HOME")); !os.IsNotExist(err) {
				t.Fatal("unavailable provider silently created plaintext storage")
			}
		})
	}
}
