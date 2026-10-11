//go:build linux && amd64

package scripts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/selfupdate"
)

// No sandbox features are needed: every production launch must be refused.
func TestLinuxCandidateNativePackaging(t *testing.T) {
	binaryPath := filepath.Join(t.TempDir(), "acs")
	build := exec.Command("go", "build", "-buildvcs=false", "-ldflags=-X main.releaseVersion=v0.2.0", "-o", binaryPath, "../cmd/acs")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}
	dir := realTemporaryDirectory(t)
	archive := filepath.Join(dir, "acs_0.2.0_linux_amd64.tar.gz")
	writeArchive := func(contents []byte) {
		t.Helper()
		writeInstallerArchive(t, archive, string(contents))
		b, err := os.ReadFile(archive)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(fmt.Sprintf("%x  acs_0.2.0_linux_amd64.tar.gz\n", sha256.Sum256(b))), 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeArchive(binary)
	template, err := os.ReadFile("install.sh.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	installer := filepath.Join(dir, "install.sh")
	if err := os.WriteFile(installer, []byte(strings.ReplaceAll(string(template), "__ACS_RELEASE_VERSION__", "v0.2.0")), 0755); err != nil {
		t.Fatal(err)
	}
	installDir := filepath.Join(realTemporaryDirectory(t), "bin")
	cmd := exec.Command("sh", "validate-promoted-artifact.sh", "v0.2.0", "linux", "amd64", dir, installDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("native packaging: %v\n%s", err, output)
	}
	installed := filepath.Join(installDir, "acs")
	got, err := os.ReadFile(installed)
	if err != nil || !bytes.Equal(got, binary) {
		t.Fatalf("installed bytes differ: %v", err)
	}

	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "unexpected network request", 500)
	}))
	defer server.Close()
	config := selfupdate.Config{CandidateDirectory: dir, Executable: installed, APIBase: server.URL, Client: server.Client()}
	// Use distinct old bytes to prove the updater replaces the actual installation.
	if err := os.WriteFile(installed, []byte("old candidate"), 0755); err != nil {
		t.Fatal(err)
	}
	result, err := selfupdate.Run(context.Background(), "v0.1.0", "v0.2.0", false, config)
	if err != nil || !result.Changed || !result.Available {
		t.Fatalf("local update: %+v, %v", result, err)
	}
	got, err = os.ReadFile(installed)
	if err != nil || !bytes.Equal(got, binary) {
		t.Fatalf("updated bytes differ: %v", err)
	}
	for _, test := range []struct {
		name    string
		mutate  func()
		restore func()
	}{
		{"altered archive", func() {
			if err := os.WriteFile(archive, []byte("corrupt"), 0600); err != nil {
				t.Fatal(err)
			}
		}, func() { writeArchive(binary) }},
		{"altered manifest", func() {
			if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte("corrupt"), 0600); err != nil {
				t.Fatal(err)
			}
		}, func() { writeArchive(binary) }},
		{"wrong architecture", func() { b := append([]byte(nil), binary...); b[18] = 183; b[19] = 0; writeArchive(b) }, func() { writeArchive(binary) }},
		{"incomplete set", func() {
			if err := os.Remove(installer); err != nil {
				t.Fatal(err)
			}
		}, func() {
			if err := os.WriteFile(installer, []byte(strings.ReplaceAll(string(template), "__ACS_RELEASE_VERSION__", "v0.2.0")), 0755); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			test.mutate()
			defer test.restore()
			if _, err := selfupdate.Run(context.Background(), "v0.1.0", "v0.2.0", false, config); err == nil {
				t.Fatal("unsafe candidate update accepted")
			}
			got, err := os.ReadFile(installed)
			if err != nil || !bytes.Equal(got, binary) {
				t.Fatalf("failed update changed installation: %v", err)
			}
			failedDir := filepath.Join(realTemporaryDirectory(t), "bin")
			cmd := exec.Command("sh", filepath.Join(dir, "install.sh"), "--candidate-dir", dir, "--bin-dir", failedDir)
			if output, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("unsafe candidate install accepted: %s", output)
			}
			if _, err := os.Stat(failedDir); !os.IsNotExist(err) {
				t.Fatalf("failed install created state: %v", err)
			}
		})
	}
	if requests != 0 {
		t.Fatalf("candidate operations made %d network requests", requests)
	}
}
