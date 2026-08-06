package scripts

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const installerVersion = "v0.2.0"

func TestInstallerDownloadsPinnedArchiveAndInstallsToCustomDirectory(t *testing.T) {
	fixture := newInstallerFixture(t, "Darwin", "arm64")
	destination := filepath.Join(realTemporaryDirectory(t), "custom bin")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture.path = fixture.toolsDirectory + string(os.PathListSeparator) + destination

	output, err := fixture.run("--bin-dir", destination)
	if err != nil {
		t.Fatalf("installer failed: %v\n%s", err, output)
	}
	wantOutput := fmt.Sprintf("Installed acs %s to %s\n", installerVersion, filepath.Join(destination, "acs"))
	if output != wantOutput {
		t.Fatalf("output = %q, want %q", output, wantOutput)
	}
	installedOutput, err := exec.Command(filepath.Join(destination, "acs"), "version").CombinedOutput()
	if err != nil {
		t.Fatalf("installed executable failed: %v\n%s", err, installedOutput)
	}
	if string(installedOutput) != "acs v0.2.0\n" {
		t.Fatalf("installed version output = %q", installedOutput)
	}
	urls, err := os.ReadFile(fixture.urlLog)
	if err != nil {
		t.Fatal(err)
	}
	wantURLs := strings.Join([]string{
		"https://github.com/alcimerio/ai-config-selector/releases/download/v0.2.0/acs_0.2.0_darwin_arm64.tar.gz",
		"https://github.com/alcimerio/ai-config-selector/releases/download/v0.2.0/SHA256SUMS",
		"",
	}, "\n")
	if string(urls) != wantURLs {
		t.Fatalf("downloaded URLs = %q, want %q", urls, wantURLs)
	}
}

func TestInstallerSelectsOnlySupportedReleaseTargets(t *testing.T) {
	tests := []struct {
		name        string
		hostOS      string
		hostArch    string
		archiveName string
	}{
		{name: "Darwin arm64", hostOS: "Darwin", hostArch: "arm64", archiveName: "acs_0.2.0_darwin_arm64.tar.gz"},
		{name: "Darwin amd64", hostOS: "Darwin", hostArch: "x86_64", archiveName: "acs_0.2.0_darwin_amd64.tar.gz"},
		{name: "Linux amd64", hostOS: "Linux", hostArch: "amd64", archiveName: "acs_0.2.0_linux_amd64.tar.gz"},
		{name: "Linux arm64", hostOS: "Linux", hostArch: "aarch64", archiveName: "acs_0.2.0_linux_arm64.tar.gz"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInstallerFixture(t, test.hostOS, test.hostArch)
			destination := filepath.Join(realTemporaryDirectory(t), "bin")
			if err := os.Mkdir(destination, 0o700); err != nil {
				t.Fatal(err)
			}
			fixture.path = fixture.toolsDirectory + string(os.PathListSeparator) + destination
			if output, err := fixture.run("--bin-dir", destination); err != nil {
				t.Fatalf("installer failed: %v\n%s", err, output)
			}
			urls, err := os.ReadFile(fixture.urlLog)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(urls), "/"+test.archiveName+"\n") {
				t.Fatalf("archive URL does not select %s: %q", test.archiveName, urls)
			}
		})
	}
}

func TestInstallerDefaultsToLocalBinAndPrintsExactPATHInstruction(t *testing.T) {
	fixture := newInstallerFixture(t, "Darwin", "arm64")
	destination := filepath.Join(fixture.home, ".local", "bin")
	output, err := fixture.run()
	if err != nil {
		t.Fatalf("installer failed: %v\n%s", err, output)
	}
	want := fmt.Sprintf(
		"Installed acs v0.2.0 to %s\nAdd ACS to PATH for this shell with:\nexport PATH='%s':\"$PATH\"\n",
		filepath.Join(destination, "acs"), destination,
	)
	if output != want {
		t.Fatalf("output = %q, want %q", output, want)
	}
	if _, err := os.Stat(filepath.Join(destination, "acs")); err != nil {
		t.Fatalf("default installation is unavailable: %v", err)
	}
}

func TestInstallerRunsWithDash(t *testing.T) {
	dash, err := exec.LookPath("dash")
	if err != nil {
		t.Skip("dash is unavailable")
	}
	fixture := newInstallerFixture(t, "Linux", "amd64")
	fixture.shell = dash
	destination := filepath.Join(realTemporaryDirectory(t), "bin")
	if err := os.Mkdir(destination, 0o700); err != nil {
		t.Fatal(err)
	}
	fixture.path = fixture.toolsDirectory + string(os.PathListSeparator) + destination
	if output, err := fixture.run("--bin-dir", destination); err != nil {
		t.Fatalf("dash installer failed: %v\n%s", err, output)
	}
}

func TestInstallerRejectsUnsupportedInputsBeforeDownloading(t *testing.T) {
	tests := []struct {
		name     string
		hostOS   string
		hostArch string
		args     func(*testing.T, *installerFixture) []string
		mutate   func(*testing.T, *installerFixture)
		want     string
	}{
		{name: "unsupported operating system", hostOS: "FreeBSD", hostArch: "amd64", want: "unsupported operating system"},
		{name: "unsupported architecture", hostOS: "Darwin", hostArch: "riscv64", want: "unsupported architecture"},
		{name: "unknown argument", hostOS: "Darwin", hostArch: "arm64", args: func(_ *testing.T, _ *installerFixture) []string { return []string{"--version", "v9.9.9"} }, want: "unknown argument"},
		{name: "missing option value", hostOS: "Darwin", hostArch: "arm64", args: func(_ *testing.T, _ *installerFixture) []string { return []string{"--bin-dir"} }, want: "--bin-dir requires a value"},
		{name: "relative destination", hostOS: "Darwin", hostArch: "arm64", args: func(_ *testing.T, _ *installerFixture) []string { return []string{"--bin-dir", "relative/bin"} }, want: "must be an absolute path"},
		{name: "traversal destination", hostOS: "Darwin", hostArch: "arm64", args: func(_ *testing.T, fixture *installerFixture) []string {
			return []string{"--bin-dir", fixture.home + "/safe/../escape"}
		}, want: "installation directory is malformed"},
		{name: "symbolic link destination", hostOS: "Darwin", hostArch: "arm64", args: func(t *testing.T, fixture *installerFixture) []string {
			realDirectory := filepath.Join(fixture.home, "real-bin")
			if err := os.Mkdir(realDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(fixture.home, "linked-bin")
			if err := os.Symlink(realDirectory, link); err != nil {
				t.Fatal(err)
			}
			return []string{"--bin-dir", link}
		}, want: "contains a symbolic link"},
		{name: "conflicting destination", hostOS: "Darwin", hostArch: "arm64", args: func(t *testing.T, fixture *installerFixture) []string {
			destination := filepath.Join(fixture.home, "bin")
			if err := os.Mkdir(destination, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(destination, "acs"), []byte("preserve me"), 0o600); err != nil {
				t.Fatal(err)
			}
			return []string{"--bin-dir", destination}
		}, want: "installation destination already exists"},
		{name: "missing tar", hostOS: "Darwin", hostArch: "arm64", mutate: func(t *testing.T, fixture *installerFixture) { fixture.removeTool(t, "tar") }, want: "required tool is unavailable: tar"},
		{name: "missing download tool", hostOS: "Darwin", hostArch: "arm64", mutate: func(t *testing.T, fixture *installerFixture) { fixture.removeTool(t, "curl") }, want: "required download tool is unavailable"},
		{name: "missing checksum tool", hostOS: "Darwin", hostArch: "arm64", mutate: func(t *testing.T, fixture *installerFixture) {
			fixture.removeTool(t, "sha256sum")
			fixture.removeTool(t, "shasum")
		}, want: "required SHA-256 tool is unavailable"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInstallerFixture(t, test.hostOS, test.hostArch)
			if test.mutate != nil {
				test.mutate(t, fixture)
			}
			var arguments []string
			if test.args != nil {
				arguments = test.args(t, fixture)
			}
			output, err := fixture.run(arguments...)
			if err == nil {
				t.Fatalf("invalid installation accepted:\n%s", output)
			}
			if !strings.Contains(output, test.want) {
				t.Fatalf("output = %q, want substring %q", output, test.want)
			}
			fixture.assertNoTemporaryOutput()
			if urls, readErr := os.ReadFile(fixture.urlLog); readErr == nil && len(urls) != 0 {
				t.Fatalf("preflight failure downloaded URLs: %q", urls)
			}
		})
	}
}

func TestInstallerFailureStagesLeaveNoVisibleOrTemporaryExecutable(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *installerFixture)
		want   string
	}{
		{name: "archive download", mutate: func(_ *testing.T, fixture *installerFixture) {
			fixture.extraEnvironment = append(fixture.extraEnvironment, "FAKE_CURL_FAIL_MATCH=.tar.gz")
		}, want: "archive download failed"},
		{name: "checksum manifest download", mutate: func(_ *testing.T, fixture *installerFixture) {
			fixture.extraEnvironment = append(fixture.extraEnvironment, "FAKE_CURL_FAIL_MATCH=SHA256SUMS")
		}, want: "checksum manifest download failed"},
		{name: "malformed checksum manifest", mutate: func(t *testing.T, fixture *installerFixture) {
			if err := os.WriteFile(filepath.Join(fixture.releaseDirectory, "SHA256SUMS"), []byte("not a manifest\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: "checksum manifest is malformed"},
		{name: "extra checksum entry", mutate: func(t *testing.T, fixture *installerFixture) {
			path := filepath.Join(fixture.releaseDirectory, "SHA256SUMS")
			file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fmt.Fprintf(file, "%s  unrelated.tar.gz\n", strings.Repeat("0", 64)); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}, want: "checksum manifest is malformed"},
		{name: "checksum mismatch", mutate: func(t *testing.T, fixture *installerFixture) {
			path := filepath.Join(fixture.releaseDirectory, fixture.archiveName)
			file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write([]byte("corrupt")); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}, want: "archive checksum mismatch"},
		{name: "malformed archive", mutate: func(t *testing.T, fixture *installerFixture) {
			if err := os.WriteFile(filepath.Join(fixture.releaseDirectory, fixture.archiveName), []byte("not an archive"), 0o600); err != nil {
				t.Fatal(err)
			}
			fixture.updateManifestChecksum()
		}, want: "archive structure could not be read"},
		{name: "nested archive", mutate: func(t *testing.T, fixture *installerFixture) {
			writeInstallerArchiveEntries(t, filepath.Join(fixture.releaseDirectory, fixture.archiveName), []installerArchiveEntry{
				{name: "bin/acs", mode: 0o755, body: "fixture", typeflag: tar.TypeReg},
				{name: "README.md", mode: 0o644, body: "readme", typeflag: tar.TypeReg},
				{name: "LICENSE", mode: 0o644, body: "license", typeflag: tar.TypeReg},
			})
			fixture.updateManifestChecksum()
		}, want: "archive structure is unsafe"},
		{name: "symbolic link archive entry", mutate: func(t *testing.T, fixture *installerFixture) {
			writeInstallerArchiveEntries(t, filepath.Join(fixture.releaseDirectory, fixture.archiveName), []installerArchiveEntry{
				{name: "acs", mode: 0o755, typeflag: tar.TypeSymlink, linkname: "/tmp/unrelated"},
				{name: "README.md", mode: 0o644, body: "readme", typeflag: tar.TypeReg},
				{name: "LICENSE", mode: 0o644, body: "license", typeflag: tar.TypeReg},
			})
			fixture.updateManifestChecksum()
		}, want: "archive contains an unsafe entry"},
		{name: "non-executable archive entry", mutate: func(t *testing.T, fixture *installerFixture) {
			writeInstallerArchiveEntries(t, filepath.Join(fixture.releaseDirectory, fixture.archiveName), []installerArchiveEntry{
				{name: "acs", mode: 0o644, body: "fixture", typeflag: tar.TypeReg},
				{name: "README.md", mode: 0o644, body: "readme", typeflag: tar.TypeReg},
				{name: "LICENSE", mode: 0o644, body: "license", typeflag: tar.TypeReg},
			})
			fixture.updateManifestChecksum()
		}, want: "archive executable is not executable"},
		{name: "executable wrong version", mutate: func(t *testing.T, fixture *installerFixture) {
			writeInstallerArchive(t, filepath.Join(fixture.releaseDirectory, fixture.archiveName), "#!/bin/sh\nprintf 'acs v9.9.9\\n'\n")
			fixture.updateManifestChecksum()
		}, want: "archive executable reported an unexpected version"},
		{name: "executable failure", mutate: func(t *testing.T, fixture *installerFixture) {
			writeInstallerArchive(t, filepath.Join(fixture.releaseDirectory, fixture.archiveName), "#!/bin/sh\nexit 1\n")
			fixture.updateManifestChecksum()
		}, want: "archive executable validation failed"},
		{name: "checksum tool failure", mutate: func(t *testing.T, fixture *installerFixture) {
			tool := "sha256sum"
			if runtime.GOOS == "darwin" {
				tool = "shasum"
			}
			fixture.replaceTool(t, tool, "#!/bin/sh\nexit 1\n")
		}, want: "archive checksum could not be computed"},
		{name: "extraction failure", mutate: func(t *testing.T, fixture *installerFixture) {
			path, err := exec.LookPath("tar")
			if err != nil {
				t.Fatal(err)
			}
			fixture.replaceTool(t, "tar", fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = \"-xzf\" ]; then exit 1; fi\nexec %q \"$@\"\n", path))
		}, want: "archive extraction failed"},
		{name: "installation copy failure", mutate: func(t *testing.T, fixture *installerFixture) {
			path, err := exec.LookPath("cp")
			if err != nil {
				t.Fatal(err)
			}
			fixture.replaceTool(t, "cp", fmt.Sprintf("#!/bin/sh\ncase \"$1\" in \"$FAKE_RELEASE_DIR\"/*) exec %q \"$@\" ;; *) exit 1 ;; esac\n", path))
		}, want: "installation copy failed"},
		{name: "installation permission failure", mutate: func(t *testing.T, fixture *installerFixture) {
			path, err := exec.LookPath("chmod")
			if err != nil {
				t.Fatal(err)
			}
			fixture.replaceTool(t, "chmod", fmt.Sprintf("#!/bin/sh\nif [ \"$1\" = \"0755\" ]; then exit 1; fi\nexec %q \"$@\"\n", path))
		}, want: "installation permission update failed"},
		{name: "final placement failure", mutate: func(t *testing.T, fixture *installerFixture) {
			fixture.replaceTool(t, "ln", "#!/bin/sh\nexit 1\n")
		}, want: "installation destination changed during installation"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInstallerFixture(t, "Darwin", "arm64")
			destination := filepath.Join(realTemporaryDirectory(t), "bin")
			if err := os.Mkdir(destination, 0o700); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, fixture)
			output, err := fixture.run("--bin-dir", destination)
			if err == nil {
				t.Fatalf("failed installation reported success:\n%s", output)
			}
			if !strings.Contains(output, test.want) {
				t.Fatalf("output = %q, want substring %q", output, test.want)
			}
			if _, err := os.Lstat(filepath.Join(destination, "acs")); !os.IsNotExist(err) {
				t.Fatalf("failed installation left visible destination: %v", err)
			}
			entries, err := os.ReadDir(destination)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("failed installation left destination output: %v", entries)
			}
			fixture.assertNoTemporaryOutput()
		})
	}
}

func TestInstallerPreservesExistingDestinations(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string) string
	}{
		{name: "regular file", setup: func(t *testing.T, destination string) string {
			path := filepath.Join(destination, "acs")
			if err := os.WriteFile(path, []byte("existing executable"), 0o700); err != nil {
				t.Fatal(err)
			}
			return path
		}},
		{name: "symbolic link", setup: func(t *testing.T, destination string) string {
			unrelated := filepath.Join(realTemporaryDirectory(t), "unrelated")
			if err := os.WriteFile(unrelated, []byte("unrelated target"), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(destination, "acs")
			if err := os.Symlink(unrelated, path); err != nil {
				t.Fatal(err)
			}
			return path
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newInstallerFixture(t, "Darwin", "arm64")
			destination := filepath.Join(realTemporaryDirectory(t), "bin")
			if err := os.Mkdir(destination, 0o700); err != nil {
				t.Fatal(err)
			}
			path := test.setup(t, destination)
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			output, err := fixture.run("--bin-dir", destination)
			if err == nil || !strings.Contains(output, "installation destination already exists") {
				t.Fatalf("existing destination was not rejected: err=%v output=%q", err, output)
			}
			after, err := os.Lstat(path)
			if err != nil {
				t.Fatalf("existing destination was removed: %v", err)
			}
			if before.Mode() != after.Mode() || before.Size() != after.Size() {
				t.Fatalf("existing destination changed: before=%v after=%v", before, after)
			}
			fixture.assertNoTemporaryOutput()
		})
	}
}

func TestInstallerRejectsNonWritableDestination(t *testing.T) {
	fixture := newInstallerFixture(t, "Darwin", "arm64")
	destination := filepath.Join(realTemporaryDirectory(t), "bin")
	if err := os.Mkdir(destination, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(destination, 0o700) })
	output, err := fixture.run("--bin-dir", destination)
	if err == nil || !strings.Contains(output, "installation directory is not writable") {
		t.Fatalf("non-writable destination was not rejected: err=%v output=%q", err, output)
	}
	fixture.assertNoTemporaryOutput()
}

type installerFixture struct {
	t                *testing.T
	installer        string
	releaseDirectory string
	toolsDirectory   string
	urlLog           string
	home             string
	temporary        string
	path             string
	extraEnvironment []string
	archiveName      string
	shell            string
}

func newInstallerFixture(t *testing.T, hostOS, hostArch string) *installerFixture {
	t.Helper()
	root := realTemporaryDirectory(t)
	fixture := &installerFixture{
		t:                t,
		installer:        filepath.Join(root, "install.sh"),
		releaseDirectory: filepath.Join(root, "release"),
		toolsDirectory:   filepath.Join(root, "tools"),
		urlLog:           filepath.Join(root, "urls.log"),
		home:             filepath.Join(root, "home"),
		temporary:        filepath.Join(root, "tmp"),
		shell:            "/bin/sh",
	}
	for _, directory := range []string{fixture.releaseDirectory, fixture.toolsDirectory, fixture.home, fixture.temporary} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	template, err := os.ReadFile("install.sh.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	rendered := strings.ReplaceAll(string(template), "__ACS_RELEASE_VERSION__", installerVersion)
	if err := os.WriteFile(fixture.installer, []byte(rendered), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, tool := range []string{"awk", "chmod", "cp", "ln", "mkdir", "mktemp", "rm", "tar"} {
		fixture.linkTool(tool)
	}
	checksumTool := "sha256sum"
	if runtime.GOOS == "darwin" {
		checksumTool = "shasum"
	}
	fixture.linkTool(checksumTool)
	fixture.writeTool("uname", fmt.Sprintf(`#!/bin/sh
case "$1" in
  -s) printf '%%s\n' %q ;;
  -m) printf '%%s\n' %q ;;
  *) exit 1 ;;
esac
`, hostOS, hostArch))
	fixture.writeTool("curl", `#!/bin/sh
output=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    *) url="$1"; shift ;;
  esac
done
name="${url##*/}"
printf '%s\n' "$url" >>"$FAKE_URL_LOG"
if [ -n "${FAKE_CURL_FAIL_MATCH:-}" ]; then
  case "$url" in
    *"$FAKE_CURL_FAIL_MATCH"*) exit 22 ;;
  esac
fi
cp "$FAKE_RELEASE_DIR/$name" "$output"
`)
	fixture.path = fixture.toolsDirectory
	fixture.writeReleaseAssets(hostOS, hostArch)
	return fixture
}

func realTemporaryDirectory(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func (fixture *installerFixture) run(arguments ...string) (string, error) {
	fixture.t.Helper()
	command := exec.Command(fixture.shell, append([]string{fixture.installer}, arguments...)...)
	command.Env = []string{
		"FAKE_RELEASE_DIR=" + fixture.releaseDirectory,
		"FAKE_URL_LOG=" + fixture.urlLog,
		"HOME=" + fixture.home,
		"LC_ALL=C",
		"PATH=" + fixture.path,
		"TMPDIR=" + fixture.temporary,
	}
	command.Env = append(command.Env, fixture.extraEnvironment...)
	output, err := command.CombinedOutput()
	return string(output), err
}

func (fixture *installerFixture) linkTool(name string) {
	fixture.t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		fixture.t.Fatalf("required test tool %s: %v", name, err)
	}
	if err := os.Symlink(path, filepath.Join(fixture.toolsDirectory, name)); err != nil {
		fixture.t.Fatal(err)
	}
}

func (fixture *installerFixture) writeTool(name, contents string) {
	fixture.t.Helper()
	if err := os.WriteFile(filepath.Join(fixture.toolsDirectory, name), []byte(contents), 0o700); err != nil {
		fixture.t.Fatal(err)
	}
}

func (fixture *installerFixture) removeTool(t *testing.T, name string) {
	t.Helper()
	err := os.Remove(filepath.Join(fixture.toolsDirectory, name))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func (fixture *installerFixture) replaceTool(t *testing.T, name, contents string) {
	t.Helper()
	fixture.removeTool(t, name)
	fixture.writeTool(name, contents)
}

func (fixture *installerFixture) assertNoTemporaryOutput() {
	fixture.t.Helper()
	entries, err := os.ReadDir(fixture.temporary)
	if err != nil {
		fixture.t.Fatal(err)
	}
	if len(entries) != 0 {
		fixture.t.Fatalf("installer left temporary output: %v", entries)
	}
}

func (fixture *installerFixture) writeReleaseAssets(hostOS, hostArch string) {
	fixture.t.Helper()
	goos := strings.ToLower(hostOS)
	if goos == "darwin" {
		goos = "darwin"
	}
	goarch := hostArch
	if goarch == "x86_64" {
		goarch = "amd64"
	}
	if goarch == "aarch64" {
		goarch = "arm64"
	}
	archiveName := fmt.Sprintf("acs_0.2.0_%s_%s.tar.gz", goos, goarch)
	fixture.archiveName = archiveName
	archivePath := filepath.Join(fixture.releaseDirectory, archiveName)
	writeInstallerArchive(fixture.t, archivePath, "#!/bin/sh\nprintf 'acs v0.2.0\\n'\n")
	archive, err := os.ReadFile(archivePath)
	if err != nil {
		fixture.t.Fatal(err)
	}
	selectedChecksum := fmt.Sprintf("%x", sha256.Sum256(archive))
	var manifest strings.Builder
	for _, target := range []string{"darwin_arm64", "darwin_amd64", "linux_amd64", "linux_arm64"} {
		name := "acs_0.2.0_" + target + ".tar.gz"
		checksum := strings.Repeat("0", 64)
		if name == archiveName {
			checksum = selectedChecksum
		}
		fmt.Fprintf(&manifest, "%s  %s\n", checksum, name)
	}
	if err := os.WriteFile(filepath.Join(fixture.releaseDirectory, "SHA256SUMS"), []byte(manifest.String()), 0o600); err != nil {
		fixture.t.Fatal(err)
	}
}

func (fixture *installerFixture) updateManifestChecksum() {
	fixture.t.Helper()
	archive, err := os.ReadFile(filepath.Join(fixture.releaseDirectory, fixture.archiveName))
	if err != nil {
		fixture.t.Fatal(err)
	}
	selectedChecksum := fmt.Sprintf("%x", sha256.Sum256(archive))
	var manifest strings.Builder
	for _, target := range []string{"darwin_arm64", "darwin_amd64", "linux_amd64", "linux_arm64"} {
		name := "acs_0.2.0_" + target + ".tar.gz"
		checksum := strings.Repeat("0", 64)
		if name == fixture.archiveName {
			checksum = selectedChecksum
		}
		fmt.Fprintf(&manifest, "%s  %s\n", checksum, name)
	}
	if err := os.WriteFile(filepath.Join(fixture.releaseDirectory, "SHA256SUMS"), []byte(manifest.String()), 0o600); err != nil {
		fixture.t.Fatal(err)
	}
}

func writeInstallerArchive(t *testing.T, path, executable string) {
	t.Helper()
	writeInstallerArchiveEntries(t, path, []installerArchiveEntry{
		{name: "acs", mode: 0o755, body: executable, typeflag: tar.TypeReg},
		{name: "README.md", mode: 0o644, body: "readme\n", typeflag: tar.TypeReg},
		{name: "LICENSE", mode: 0o644, body: "license\n", typeflag: tar.TypeReg},
	})
}

type installerArchiveEntry struct {
	name     string
	mode     int64
	body     string
	typeflag byte
	linkname string
}

func writeInstallerArchiveEntries(t *testing.T, path string, entries []installerArchiveEntry) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		if err := tarWriter.WriteHeader(&tar.Header{Name: entry.name, Mode: entry.mode, Size: int64(len(entry.body)), Typeflag: entry.typeflag, Linkname: entry.linkname}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write([]byte(entry.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
