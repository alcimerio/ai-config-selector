//go:build darwin && arm64

package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/alcimerio/ai-config-selector/internal/launch"
	"github.com/alcimerio/ai-config-selector/internal/selfupdate"
	"github.com/alcimerio/ai-config-selector/internal/session"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A copied test binary runs the public dispatcher while replacing its own
// executable. The release client and certificate exist only in this test.
func TestNativeDisposablePublicUpdate(t *testing.T) {
	if os.Getenv("ACS_TEST_UPDATE_CHILD") == "1" {
		nativeUpdateChild(t)
		return
	}
	dir, e := os.MkdirTemp(".", "acs-update-native-")
	if e != nil {
		t.Fatal(e)
	}
	complete := false
	defer func() {
		if complete {
			_ = os.RemoveAll(dir)
		} else {
			t.Logf("preserved disposable native fixture for uncertain cleanup: %s", dir)
		}
	}()
	dir, e = filepath.Abs(dir)
	if e != nil {
		t.Fatal(e)
	}
	installed := filepath.Join(dir, "acs")
	old, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	input, e := os.Open(old)
	if e != nil {
		t.Fatal(e)
	}
	defer input.Close()
	output, e := os.OpenFile(installed, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = io.Copy(output, input); e != nil {
		t.Fatal(e)
	}
	if e = output.Close(); e != nil {
		t.Fatal(e)
	}
	oldInfo, e := os.Stat(installed)
	if e != nil {
		t.Fatal(e)
	}
	oldBytes, e := os.ReadFile(installed)
	if e != nil {
		t.Fatal(e)
	}
	oldDigest := sha256.Sum256(oldBytes)
	candidate := filepath.Join(dir, "candidate")
	buildContext, cancelBuild := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancelBuild()
	build := exec.CommandContext(buildContext, "go", "build", "-ldflags=-X main.releaseVersion=v0.5.0", "-o", candidate, "../../cmd/acs")
	if b, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build fixture: %v: %s", e, b)
	}
	binary, e := os.ReadFile(candidate)
	if e != nil {
		t.Fatal(e)
	}
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for _, entry := range []struct {
		name string
		data []byte
		mode int64
	}{{"acs", binary, 0755}, {"README.md", []byte("fixture"), 0644}, {"LICENSE", []byte("fixture"), 0644}} {
		if e = tw.WriteHeader(&tar.Header{Name: entry.name, Mode: entry.mode, Typeflag: tar.TypeReg, Size: int64(len(entry.data))}); e != nil {
			t.Fatal(e)
		}
		if _, e = tw.Write(entry.data); e != nil {
			t.Fatal(e)
		}
	}
	if e = tw.Close(); e != nil {
		t.Fatal(e)
	}
	if e = gz.Close(); e != nil {
		t.Fatal(e)
	}
	hash := sha256.Sum256(archive.Bytes())
	manifest := hex.EncodeToString(hash[:]) + "  acs_0.5.0_darwin_arm64.tar.gz\n"
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/latest":
			fmt.Fprintf(w, `{"tag_name":"v0.5.0","assets":[{"name":"acs_0.5.0_darwin_arm64.tar.gz","browser_download_url":"%s/archive"},{"name":"SHA256SUMS","browser_download_url":"%s/manifest"}]}`, server.URL, server.URL)
		case "/archive":
			w.Write(archive.Bytes())
		case "/manifest":
			io.WriteString(w, manifest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	childContext, cancelChild := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancelChild()
	child := exec.CommandContext(childContext, installed, "-test.run=^TestNativeDisposablePublicUpdate$", "-test.v")
	child.Env = append(os.Environ(), "ACS_TEST_UPDATE_CHILD=1", "ACS_TEST_UPDATE_URL="+server.URL, "ACS_TEST_UPDATE_CERT="+base64.StdEncoding.EncodeToString(certificate), "ACS_TEST_UPDATE_ROOT="+dir, "PATH="+dir+":"+os.Getenv("PATH"))
	childOutput, e := child.CombinedOutput()
	if e != nil {
		t.Fatalf("native self-update child: %v: %s", e, childOutput)
	}
	for _, witness := range []string{"Update available: true", "Installed acs v0.5.0", "live Session settled", "delayed helper settled"} {
		if !bytes.Contains(childOutput, []byte(witness)) {
			t.Fatalf("missing witness %q: %s", witness, childOutput)
		}
	}
	newInfo, e := os.Stat(installed)
	if e != nil {
		t.Fatal(e)
	}
	newBytes, e := os.ReadFile(installed)
	if e != nil {
		t.Fatal(e)
	}
	newDigest := sha256.Sum256(newBytes)
	candidateDigest := sha256.Sum256(binary)
	if os.SameFile(oldInfo, newInfo) || newDigest != candidateDigest || newDigest == oldDigest {
		t.Fatal("native fixture did not replace the running executable identity and bytes")
	}
	versionContext, cancelVersion := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelVersion()
	version, e := exec.CommandContext(versionContext, installed, "version").CombinedOutput()
	if e != nil || strings.TrimSpace(string(version)) != "acs v0.5.0" {
		t.Fatalf("published candidate: %v %s", e, version)
	}
	complete = true
}

func TestMain(m *testing.M) {
	// Darwin seatbelt proxy/supervisor dispatch occurs in launch's init before
	// testing parses helper flags. These remaining public helper routes mirror main.
	if handled, err := launch.RunMCPHelper(os.Args[1:]); handled {
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	if handled, err := launch.RunBubblewrapHelper(os.Args[1:]); handled {
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func nativeUpdateChild(t *testing.T) {
	cert, e := base64.StdEncoding.DecodeString(os.Getenv("ACS_TEST_UPDATE_CERT"))
	if e != nil {
		t.Fatal(e)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		t.Fatal("fixture certificate")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}, Timeout: 15 * time.Second}
	cfg := selfupdate.Config{APIBase: os.Getenv("ACS_TEST_UPDATE_URL"), Client: client}
	var out, errs bytes.Buffer
	app := App{Version: "v0.4.0", Output: &out, ErrorOutput: &errs}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	handled, code := app.RunUpdate(ctx, []string{"update", "--check"}, cfg)
	if !handled || code != 0 || !strings.Contains(out.String(), "Update available: true") {
		t.Fatalf("check: %d %s", code, errs.String())
	}
	fmt.Print(out.String())
	out.Reset()
	errs.Reset()
	root := os.Getenv("ACS_TEST_UPDATE_ROOT")
	workspace := filepath.Join(root, "workspace")
	if e := os.Mkdir(workspace, 0700); e != nil {
		t.Fatal(e)
	}
	marker := filepath.Join(workspace, "live-heartbeat")
	stopMarker := filepath.Join(workspace, "live-stop")
	script := filepath.Join(workspace, "heartbeat.sh")
	if e := os.WriteFile(script, []byte("#!/bin/sh\nwhile :; do printf x >> \"$1\"; if [ -f \"$2\" ]; then exit 0; fi; /bin/sleep 0.1; done\n"), 0700); e != nil {
		t.Fatal(e)
	}
	live := nativePreparedSession(t, ctx, root, workspace, "live", "/bin/sh", []string{script, marker, stopMarker})
	defer live.cleanup(t)
	if e = live.process.Start(); e != nil {
		t.Fatalf("start live Session: %v", e)
	}
	live.started = true
	ready := false
	for i := 0; i < 50; i++ {
		body, _ := os.ReadFile(marker)
		if len(body) >= 2 {
			ready = true
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("live Session readiness timeout")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatal("live contained Session produced no heartbeat")
	}
	fmt.Println("live Session heartbeat observed")
	delayed := nativePreparedSession(t, ctx, root, workspace, "delayed", "/usr/bin/true", nil)
	defer delayed.cleanup(t)
	handled, code = app.RunUpdate(ctx, []string{"update"}, cfg)
	if !handled || code != 0 {
		t.Fatalf("update: %d %s", code, errs.String())
	}
	fmt.Print(out.String())
	baseline, e := os.ReadFile(marker)
	if e != nil {
		t.Fatalf("read post-update heartbeat: %v", e)
	}
	advanced := false
	for i := 0; i < 50; i++ {
		after, _ := os.ReadFile(marker)
		if heartbeatAdvanced(baseline, after) {
			advanced = true
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("post-update heartbeat timed out")
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !advanced {
		t.Fatal("live Session did not advance heartbeat after update")
	}
	fmt.Println("post-update live heartbeat advanced")
	if e = os.WriteFile(stopMarker, []byte("stop"), 0600); e != nil {
		t.Fatalf("request normal live stop: %v", e)
	}
	if e = live.process.Wait(); e != nil {
		live.waited = true
		t.Fatalf("live Session did not exit normally after stop: %v", e)
	}
	live.waited = true
	if e = launch.AwaitRetainedSessionCleanup(live.process); e != nil {
		t.Fatalf("live cleanup: %v", e)
	}
	live.settled = true
	fmt.Println("live Session settled")
	if e = delayed.process.Start(); e != nil {
		t.Fatalf("start delayed helper: %v", e)
	}
	delayed.started = true
	if e = delayed.process.Wait(); e != nil {
		delayed.waited = true
		t.Fatalf("delayed helper wait: %v", e)
	}
	delayed.waited = true
	if e = launch.AwaitRetainedSessionCleanup(delayed.process); e != nil {
		t.Fatalf("delayed helper cleanup: %v", e)
	}
	delayed.settled = true
	fmt.Println("delayed helper settled")
}
func heartbeatAdvanced(before, after []byte) bool { return len(after) > len(before) }
func TestNativeHeartbeatAdvancePredicate(t *testing.T) {
	if heartbeatAdvanced([]byte("xx"), []byte("xx")) {
		t.Fatal("accepted stale heartbeat")
	}
	if heartbeatAdvanced([]byte("xx"), nil) {
		t.Fatal("accepted absent heartbeat after early death")
	}
	if !heartbeatAdvanced([]byte("xx"), []byte("xxx")) {
		t.Fatal("missed new heartbeat")
	}
}

type nativeUpdateSession struct {
	record                   *session.Session
	process                  launch.Process
	started, waited, settled bool
}

func (s *nativeUpdateSession) cleanup(t *testing.T) {
	if s.started && !s.waited {
		_ = s.process.Signal(syscall.SIGTERM)
		_ = s.process.Wait()
		s.waited = true
		if e := launch.AwaitRetainedSessionCleanup(s.process); e == nil {
			s.settled = true
		}
	}
	if !s.settled {
		t.Errorf("fixture Session cleanup is unproven; preserved %s", s.record.RootDirectory())
		return
	}
	if e := s.record.Remove(); e != nil {
		t.Errorf("remove fixture Session: %v", e)
	}
}
func nativePreparedSession(t *testing.T, ctx context.Context, root, workspace, label, target string, args []string) *nativeUpdateSession {
	t.Helper()
	created, e := session.CreateTracked(filepath.Join(root, label+"-sessions"), workspace, nil, "command")
	if e != nil {
		t.Fatal(e)
	}
	sandbox := launch.NewProcessSandbox()
	check := launch.SandboxCheck{Workspace: workspace, WorkspaceAccess: launch.WorkspaceAccessReadWrite, SessionsDirectory: created.SessionsDirectory(), Executable: target}
	if e = sandbox.Check(ctx, check); e != nil {
		t.Fatal(e)
	}
	challenge, e := created.ArmOperation(nil)
	if e != nil {
		t.Fatal(e)
	}
	request := launch.ProcessRequest{Workspace: workspace, WorkspaceAccess: launch.WorkspaceAccessReadWrite, SessionsDirectory: created.SessionsDirectory(), SessionDirectory: created.RootDirectory(), SessionHome: created.HomeDirectory(), TemporaryDirectory: created.TemporaryDirectory(), Executable: target, Arguments: args, RecoveryProofChallenge: challenge, Terminal: launch.Terminal{Input: bytes.NewReader(nil), Output: io.Discard, ErrorOutput: io.Discard}}
	process, e := sandbox.Prepare(ctx, request)
	if e != nil {
		t.Fatal(e)
	}
	process, e = created.RetainUntilProcessDone(process)
	if e != nil {
		t.Fatal(e)
	}
	return &nativeUpdateSession{record: created, process: process}
}
