//go:build darwin

package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alcimerio/ai-config-selector/internal/environmentresource"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/session"
)

// Fixed research commands use the production boundary directly. This is NOT
// public ACS plugin/hook support; the public interactive proofs are unchanged.
type discoverySession struct {
	t                 *testing.T
	ctx               context.Context
	created           *session.Session
	sandbox           launch.ProcessSandbox
	target, workspace string
	calls             int
	label             string
	environment       *environmentresource.Lease
	diagnostic        string
	request           launch.ProcessRequest
	startup           *discoveryStartup
	featured          *discoveryCodexFeaturedMetadata
}

func newDiscoverySession(t *testing.T, ctx context.Context, target, kind, label string) *discoverySession {
	t.Helper()
	root, err := os.MkdirTemp("", "acs-discovery-")
	if err != nil {
		t.Fatal(err)
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	workspace := filepath.Join(root, "workspace")
	if e := os.Mkdir(workspace, 0700); e != nil {
		t.Fatal(e)
	}
	created, e := session.CreateTracked(filepath.Join(root, "sessions"), workspace, nil, "command")
	if e != nil {
		t.Fatal(e)
	}
	sandbox := launch.NewProcessSandbox()
	check, request := discoverySandboxRequests(kind, launch.ProcessRequest{Workspace: workspace, WorkspaceAccess: launch.WorkspaceAccessReadWrite, SessionsDirectory: created.SessionsDirectory(), SessionDirectory: created.RootDirectory(), SessionHome: created.HomeDirectory(), TemporaryDirectory: created.TemporaryDirectory(), Executable: target})
	if e = sandbox.Check(ctx, check); e != nil {
		t.Fatal(e)
	}
	s := &discoverySession{t: t, ctx: ctx, created: created, sandbox: sandbox, target: target, workspace: workspace, label: label, request: request}
	t.Cleanup(func() {
		if e := created.Remove(); e != nil {
			t.Error("discovery Session removal failed; preserving private root")
			return
		}
		if _, e := os.Stat(created.RootDirectory()); !os.IsNotExist(e) {
			t.Error("discovery Session not removed")
			return
		}
		_ = os.RemoveAll(root)
	})
	return s
}
func (s *discoverySession) prepare(ctx context.Context, args []string, in io.Reader, out, stderr io.Writer) (launch.Process, error) {
	s.calls++
	if s.calls > 8 {
		return nil, errors.New("discovery command budget")
	}
	challenge, e := s.created.ArmOperation(nil)
	if e != nil {
		return nil, e
	}
	request := s.request
	request.RecoveryProofChallenge = challenge
	request.Environment = s.environment
	request.Arguments = args
	request.Terminal = launch.Terminal{Input: in, Output: out, ErrorOutput: stderr}
	p, e := s.sandbox.Prepare(ctx, request)
	if e != nil {
		return nil, e
	}
	return s.created.RetainUntilProcessDone(p)
}
func discoverySettle(p launch.Process) error {
	e := p.Start()
	if e == nil {
		e = p.Wait()
	}
	if cleanup := launch.AwaitRetainedSessionCleanup(p); cleanup != nil {
		return errDiscoveryCleanup
	}
	return e
}
func (s *discoverySession) command(args ...string) ([]byte, error) {
	s.diagnostic = "stage=prepare"
	if s.startup != nil {
		if err := s.startup.begin(s.calls + 1); err != nil {
			return nil, err
		}
		defer s.startup.end()
	}
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	var out, stderr discoveryCapture
	p, e := s.prepare(ctx, args, bytes.NewReader(nil), &out, &stderr)
	if e != nil {
		return nil, e
	}
	runErr := discoverySettle(p)
	s.diagnostic = discoveryCaptureDiagnostic(&out, &stderr)
	body, e := out.bytes()
	_, se := stderr.bytes()
	if errors.Is(runErr, errDiscoveryCleanup) {
		return nil, runErr
	}
	if ctx.Err() != nil {
		return nil, errDiscoveryTimeout
	}
	if e != nil || se != nil {
		return nil, errDiscoveryCapture
	}
	return body, runErr
}
func (s *discoverySession) success(args ...string) []byte {
	s.t.Helper()
	b, e := s.command(args...)
	if e != nil {
		category, code := discoveryFailureClass(e)
		s.t.Fatalf("contained discovery %s call=%d failed category=%s exit=%d %s", s.label, s.calls, category, code, s.diagnostic)
	}
	return b
}

func TestNativeInstalledExtensionDiscovery(t *testing.T) {
	if os.Getenv("ACS_RUN_NATIVE_EXTENSION_DISCOVERY") != "1" {
		t.Skip("explicit installed discovery opt-in required")
	}
	if runtime.GOARCH != "arm64" {
		t.Fatal("locked architecture required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	codex, e := filepath.EvalSymlinks(os.Getenv("ACS_TEST_CODEX_BINARY"))
	if e != nil {
		t.Fatal("Codex target missing")
	}
	if e = verifyDiscoveryCodex(os.Getenv("ACS_TEST_CODEX_ARCHIVE"), codex); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if e := verifyDiscoveryCodex(os.Getenv("ACS_TEST_CODEX_ARCHIVE"), codex); e != nil {
			t.Error(e)
		}
	}()
	devin, e := filepath.EvalSymlinks(os.Getenv("ACS_TEST_DEVIN_BINARY"))
	if e != nil {
		t.Fatal("Devin target missing")
	}
	if _, e = verifyDevinDarwinMember(os.Getenv("ACS_TEST_DEVIN_ARCHIVE"), devin); e != nil {
		t.Fatal(e)
	}
	defer func() {
		if _, e := verifyDevinDarwinMember(os.Getenv("ACS_TEST_DEVIN_ARCHIVE"), devin); e != nil {
			t.Error(e)
		}
	}()
	t.Run("codex-local-plugin", func(t *testing.T) {
		s := newDiscoverySession(t, ctx, codex, "codex", "codex-plugin")
		seedDiscoveryCodexConfig(t, s)
		catalog := filepath.Join(s.workspace, "catalog")
		if e := seedDiscoveryCatalog(catalog); e != nil {
			t.Fatal(e)
		}
		keepDiscoveryFixtures(t, filepath.Join(catalog, ".agents", "plugins", "marketplace.json"), filepath.Join(catalog, "plugins", "acs-local", "plugin.json"), filepath.Join(catalog, "plugins", "acs-local", "skills", "receipt", "SKILL.md"))
		if strings.TrimSpace(string(s.success("--version"))) != "codex-cli 0.149.1" {
			t.Fatal("locked version mismatch")
		}
		s.success("plugin", "marketplace", "add", catalog, "--json")
		checkDiscoveryPluginList(t, s.success("plugin", "list", "--marketplace", "acs-assessment", "--available", "--json"), false)
		b := s.success("plugin", "add", "acs-local@acs-assessment", "--json")
		var added struct {
			Name        string `json:"name"`
			Marketplace string `json:"marketplaceName"`
			Path        string `json:"installedPath"`
		}
		if json.Unmarshal(b, &added) != nil || added.Name != "acs-local" || added.Marketplace != "acs-assessment" {
			t.Fatal("plugin install identity/path mismatch")
		}
		installIdentity, e := discoveryInstalledDirectory(s.created.HomeDirectory(), added.Path)
		if e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() {
			final, e := discoveryInstalledDirectory(s.created.HomeDirectory(), added.Path)
			if e != nil || !os.SameFile(installIdentity, final) {
				t.Error("installed plugin directory identity changed")
			}
		})
		checkDiscoveryPluginList(t, s.success("plugin", "list", "--marketplace", "acs-assessment", "--json"), true)
		_, negativeErr := s.command("plugin", "add", "acs-absent@acs-assessment", "--json")
		requireDiscoveryNaturalRefusal(t, negativeErr)
		checkDiscoveryPluginList(t, s.success("plugin", "list", "--marketplace", "acs-assessment", "--json"), true)
	})
	t.Run("codex-untrusted-hook-discovery", func(t *testing.T) {
		s := newDiscoverySession(t, ctx, codex, "codex", "codex-hooks")
		s.featured = &discoveryCodexFeaturedMetadata{}
		seedDiscoveryCodexConfig(t, s)
		tripwire := filepath.Join(s.workspace, "UNEXPECTED_HOOK")
		command := "/bin/sh -c " + devinShellLiteral("printf unexpected > "+devinShellLiteral(tripwire))
		definition := map[string]any{"hooks": map[string]any{"SessionStart": []any{map[string]any{"hooks": []any{map[string]any{"type": "command", "command": command, "timeout": 1}}}}}}
		b, _ := json.Marshal(definition)
		source := filepath.Join(s.created.HomeDirectory(), ".codex", "hooks.json")
		if e := discoveryWrite(source, b); e != nil {
			t.Fatal(e)
		}
		keepDiscoveryFixtures(t, source)
		result, e := s.hooksList()
		if e != nil {
			t.Fatalf("contained hook discovery failed %s", s.diagnostic)
		}
		if e = checkDiscoveryHooks(result, s.workspace, source, command); e != nil {
			t.Fatal(e)
		}
		if _, e = os.Lstat(tripwire); !os.IsNotExist(e) {
			t.Fatal("discovery executed hook")
		}
		negativeSession := newDiscoverySession(t, ctx, codex, "codex", "codex-hooks-malformed")
		negativeSession.featured = &discoveryCodexFeaturedMetadata{}
		seedDiscoveryCodexConfig(t, negativeSession)
		negativeSource := filepath.Join(negativeSession.created.HomeDirectory(), ".codex", "hooks.json")
		if e = discoveryWrite(negativeSource, []byte("{broken")); e != nil {
			t.Fatal(e)
		}
		keepDiscoveryFixtures(t, negativeSource)
		negative, e := negativeSession.hooksList()
		if e != nil {
			t.Fatalf("malformed hook discovery protocol failed %s", negativeSession.diagnostic)
		}
		var invalid struct {
			Data []struct {
				Cwd      string
				Hooks    []json.RawMessage
				Warnings []string
				Errors   []json.RawMessage
			}
		}
		if json.Unmarshal(negative, &invalid) != nil || len(invalid.Data) != 1 || invalid.Data[0].Cwd != negativeSession.workspace || len(invalid.Data[0].Hooks) != 0 || len(invalid.Data[0].Warnings)+len(invalid.Data[0].Errors) == 0 {
			t.Fatal("malformed hook source not reported")
		}
		if _, e = os.Lstat(tripwire); !os.IsNotExist(e) {
			t.Fatal("negative discovery executed hook")
		}

	})
	t.Run("devin-local-plugin", func(t *testing.T) {
		s := newDiscoverySession(t, ctx, devin, "devin", "devin-plugin")
		endpoint, e := copyDevinSyntheticCredentials(s.created.HomeDirectory())
		if e != nil {
			t.Fatal(e)
		}
		s.environment, e = discoveryDevinEnvironment(endpoint)
		if e != nil {
			t.Fatal("synthetic endpoint lease invalid")
		}
		t.Cleanup(s.environment.Release)
		listener, e := net.Listen("tcp", endpoint)
		if e != nil {
			t.Fatal("synthetic endpoint unavailable")
		}
		s.startup = &discoveryStartup{}
		var requests atomic.Int64
		server := &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second, MaxHeaderBytes: 8192}
		server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if requests.Add(1) > 20 {
				s.startup.mu.Lock()
				s.startup.failLocked("request-total")
				s.startup.mu.Unlock()
				_ = server.Close()
				return
			}
			s.startup.ServeHTTP(w, r)
		})
		done := make(chan error, 1)
		go func() { done <- server.Serve(listener) }()
		t.Cleanup(func() {
			c, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			_ = server.Shutdown(c)
			_ = server.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("synthetic listener did not settle")
			}
			if summary, failed := s.startup.summary(); failed {
				t.Errorf("synthetic startup contract failed %s", summary)
			}
		})
		pkg := filepath.Join(s.workspace, "package")
		if e = seedDiscoveryPlugin(pkg, false); e != nil {
			t.Fatal(e)
		}
		keepDiscoveryFixtures(t, filepath.Join(pkg, ".devin-plugin", "plugin.json"), filepath.Join(pkg, "skills", "receipt", "SKILL.md"))
		bad := filepath.Join(s.workspace, "invalid-package")
		if e = discoveryWrite(filepath.Join(bad, ".devin-plugin", "plugin.json"), []byte(`{"name":42}`)); e != nil {
			t.Fatal(e)
		}
		keepDiscoveryFixtures(t, filepath.Join(bad, ".devin-plugin", "plugin.json"))
		s.success("plugins", "install", "--local", "--yes", pkg)
		beforeInventory := s.success("plugins", "list")
		if discoveryTokenCount(beforeInventory, "acs-local") != 1 {
			t.Fatal("selected Devin plugin inventory identity ambiguous")
		}
		info := s.success("plugins", "info", "acs-local")
		if !discoveryHasToken(info, "acs-local") || !discoveryHasToken(info, "receipt") {
			t.Fatal("selected Devin plugin info absent")
		}

		_, negativeErr := s.command("plugins", "install", "--local", "--yes", bad)
		requireDiscoveryNaturalRefusal(t, negativeErr)
		afterInventory := s.success("plugins", "list")
		if e := verifyDiscoveryDevinInventory(beforeInventory, afterInventory); e != nil {
			t.Fatal(e)
		}
	})
}
func (s *discoverySession) hooksList() (json.RawMessage, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	wire := &discoveryWire{lines: make(chan []byte, 32)}
	var stderr discoveryCapture
	var stage atomic.Int32
	var initialized, listed atomic.Bool
	var exchangeErr, waitErr, cleanupErr error
	waited := false
	defer func() {
		s.diagnostic = discoveryHookDiagnostic(stage.Load(), initialized.Load(), listed.Load(), ctx.Err() != nil, waited, exchangeErr, waitErr, cleanupErr, &wire.capture, &stderr)
	}()
	p, e := s.prepare(ctx, []string{"app-server"}, reader, wire, &stderr)
	if e != nil {
		exchangeErr = e
		return nil, e
	}
	stage.Store(1)
	if e = p.Start(); e != nil {
		waitErr = e
		cleanupErr = launch.AwaitRetainedSessionCleanup(p)
		return nil, errors.Join(e, cleanupErr)
	}
	type settlement struct{ wait, cleanup error }
	wait := make(chan settlement, 1)
	go func() { waitErr := p.Wait(); wait <- settlement{waitErr, launch.AwaitRetainedSessionCleanup(p)} }()
	exchange := func() (json.RawMessage, error) {
		stage.Store(2)
		if _, e := io.WriteString(writer, "{\"id\":1,\"method\":\"initialize\",\"params\":{\"clientInfo\":{\"name\":\"acs_assessment\",\"version\":\"0.1.0\"},\"capabilities\":{\"experimentalApi\":true}}}\n"); e != nil {
			return nil, e
		}
		stage.Store(3)
		if _, e := wire.response(ctx, 1); e != nil {
			return nil, e
		}
		initialized.Store(true)
		stage.Store(4)
		request, _ := json.Marshal(map[string]any{"id": 2, "method": "hooks/list", "params": map[string]any{"cwds": []string{s.workspace}}})
		if _, e := io.WriteString(writer, "{\"method\":\"initialized\",\"params\":{}}\n"+string(request)+"\n"); e != nil {
			return nil, e
		}
		stage.Store(5)
		result, err := wire.response(ctx, 2)
		if err == nil {
			listed.Store(true)
		}
		return result, err
	}
	exchangeDone := make(chan struct{})
	var result json.RawMessage
	go func() { result, exchangeErr = exchange(); close(exchangeDone) }()
	select {
	case <-exchangeDone:
	case <-ctx.Done():
		_ = reader.Close()
		_ = writer.Close()
		<-exchangeDone
		exchangeErr = errors.New("discovery exchange deadline")
	}
	if exchangeErr == nil {
		stage.Store(6)
	}
	_ = writer.Close()
	settled := <-wait
	waitErr, cleanupErr = settled.wait, settled.cleanup
	waited = true
	_, captureErr := wire.capture.bytes()
	_, stderrErr := stderr.bytes()
	if cleanupErr != nil {
		return nil, errDiscoveryCleanup
	}
	if ctx.Err() != nil {
		return nil, errors.New("app-server did not naturally settle")
	}
	if wire.failure || len(wire.pending) != 0 {
		return nil, errors.New("incomplete discovery wire")
	}
	return result, errors.Join(exchangeErr, waitErr, captureErr, stderrErr)
}
func requireDiscoveryNaturalRefusal(t *testing.T, err error) {
	t.Helper()
	var exit *exec.ExitError
	var boundary *launch.SandboxError
	if errors.As(err, &boundary) || !errors.As(err, &exit) || exit.ExitCode() <= 0 {
		t.Fatal("expected natural nonzero refusal, not timeout/capture/cleanup failure")
	}
}

// All possible model calls for this explicit provider terminate at an error-only
// listener; any received request fails the case. File auth excludes host Keychain.
func seedDiscoveryCodexConfig(t *testing.T, s *discoverySession) {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var server *http.Server
	handler := &discoveryCodexHTTPHandler{featured: s.featured, hook: s.featured != nil}
	server = &http.Server{ReadHeaderTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second, MaxHeaderBytes: 8192, Handler: handler}
	handler.onOverflow = func() { _ = server.Close() }
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		shutdownErr := server.Shutdown(ctx)
		cancel()
		if shutdownErr != nil {
			t.Error("metadata listener graceful shutdown failed")
			_ = server.Close()
		}
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("model tripwire listener did not settle")
		}
		total, forbidden, overflow := handler.summary()
		t.Logf("codex-discovery-http total=%d forbidden=%d overflow=%d", total, forbidden, overflow)
		if forbidden != 0 || overflow != 0 {
			t.Errorf("Codex discovery HTTP contract total=%d forbidden=%d overflow=%d", total, forbidden, overflow)
		}
		if s.featured != nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if e := s.featured.wait(ctx); e != nil {
				t.Error(e)
			}
			seen, failure := s.featured.summary()
			t.Logf("codex-featured-metadata-count=%d", seen)
			if failure != "" {
				t.Errorf("Codex featured metadata contract failure=%s", failure)
			}
		}
	})
	endpoint := "http://" + listener.Addr().String()
	cfg := "cli_auth_credentials_store = \"file\"\nmodel = \"acs-discovery\"\nmodel_provider = \"acs-discovery\"\nchatgpt_base_url = " + strconv.Quote(endpoint) + "\n[model_providers.acs-discovery]\nname = \"ACS discovery tripwire\"\nbase_url = " + strconv.Quote(endpoint) + "\nwire_api = \"responses\"\nrequires_openai_auth = false\n"
	if e = discoveryWrite(filepath.Join(s.created.HomeDirectory(), ".codex", "config.toml"), []byte(cfg)); e != nil {
		t.Fatal(e)
	}
}
