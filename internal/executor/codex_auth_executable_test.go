package executor

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func writeTestExecutable(t *testing.T, path string, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
}

func TestResolveCodeModeCompanionLayoutsAndAbsence(t *testing.T) {
	t.Run("absent is compatible", func(t *testing.T) {
		dir := t.TempDir()
		codex := filepath.Join(dir, "codex")
		writeTestExecutable(t, codex, "codex")
		p := newPinnedExecutable(codex)
		if _, err := p.Resolve(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("package resources wins", func(t *testing.T) {
		root, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		bin := filepath.Join(root, "bin")
		resources := filepath.Join(root, "codex-resources")
		if err := os.MkdirAll(bin, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(resources, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "codex-package.json"), []byte(`{"version":"1.0.0"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		codex := filepath.Join(bin, "codex")
		writeTestExecutable(t, codex, "codex")
		host := filepath.Join(resources, "codex-code-mode-host")
		writeTestExecutable(t, host, "resources")
		p := newPinnedExecutable(codex)
		if _, err := p.Resolve(); err != nil {
			t.Fatal(err)
		}
		if p.companion != host {
			t.Fatalf("companion=%q want %q", p.companion, host)
		}
	})
	t.Run("legacy resources", func(t *testing.T) {
		home, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		t.Setenv("CODEX_HOME", filepath.Join(home, ".codex"))
		root := filepath.Join(home, ".codex", "packages", "standalone", "releases", "channel", "r1")
		if err := os.MkdirAll(filepath.Join(root, "codex-resources"), 0o700); err != nil {
			t.Fatal(err)
		}
		codex := filepath.Join(root, "codex")
		writeTestExecutable(t, codex, "codex")
		host := filepath.Join(root, "codex-resources", "codex-code-mode-host")
		writeTestExecutable(t, host, "legacy")
		p := newPinnedExecutable(codex)
		if _, err := p.Resolve(); err != nil {
			t.Fatal(err)
		}
		if p.companion != host {
			t.Fatalf("companion=%q want %q", p.companion, host)
		}
	})
}

func TestResolveCodeModeCompanionRejectsPresentInvalidAndRetargeted(t *testing.T) {
	dir := t.TempDir()
	codex := filepath.Join(dir, "codex")
	writeTestExecutable(t, codex, "codex")
	invalid := filepath.Join(dir, "codex-code-mode-host")
	if err := os.Mkdir(invalid, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := newPinnedExecutable(codex).Resolve(); err == nil {
		t.Fatal("present directory companion was accepted")
	}
	if err := os.Remove(invalid); err != nil {
		t.Fatal(err)
	}
	targetA := filepath.Join(dir, "host-a")
	targetB := filepath.Join(dir, "host-b")
	writeTestExecutable(t, targetA, "a")
	writeTestExecutable(t, targetB, "b")
	if err := os.Symlink(targetA, invalid); err != nil {
		t.Fatal(err)
	}
	p := newPinnedExecutable(codex)
	if _, err := p.Resolve(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(invalid); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetB, invalid); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Resolve(); err == nil {
		t.Fatal("retargeted companion was accepted")
	}
}

func TestOpenExecutableRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, err := openExecutable(path)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("FIFO result=%v", err)
	}
}

func TestCodeModeCompanionPinnedPackageLookupOrder(t *testing.T) {
	for _, tc := range []struct {
		name, entry               string
		binKind                   string
		marker                    bool
		resourceKind              string
		binHost, bogusBinResource bool
		want                      string
	}{
		{name: "package resource beats bin and bogus nested resource", entry: "bin", binKind: "directory", marker: true, resourceKind: "host", binHost: true, bogusBinResource: true, want: "codex-resources"},
		{name: "package bin beats bogus bin resources", entry: "bin", binKind: "directory", marker: true, resourceKind: "directory", binHost: true, bogusBinResource: true, want: "bin"},
		{name: "resources entrypoint falls back to package bin", entry: "codex-resources", binKind: "directory", marker: true, resourceKind: "directory", binHost: true, want: "bin"},
		{name: "resources entrypoint prefers own resource host", entry: "codex-resources", binKind: "directory", marker: true, resourceKind: "host", binHost: true, want: "codex-resources"},
		{name: "resources entrypoint missing bin is not a package", entry: "codex-resources", binKind: "missing", marker: true, resourceKind: "directory"},
		{name: "resources entrypoint bin file is not a package", entry: "codex-resources", binKind: "file", marker: true, resourceKind: "directory"},
		{name: "resource directory file does not mask bin host", entry: "bin", binKind: "directory", marker: true, resourceKind: "file", binHost: true, want: "bin"},
		{name: "directory marker is not package metadata", entry: "bin", binKind: "directory", marker: false, resourceKind: "host", binHost: true, want: "bin"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("CODEX_HOME", home)
			// Deliberately inside the legacy boundary: package release_dir must be root,
			// not root/bin, even when a bogus bin/codex-resources host exists.
			root := filepath.Join(home, "packages", "standalone", "releases", "0.149.1")
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			bin := filepath.Join(root, "bin")
			resources := filepath.Join(root, "codex-resources")
			switch tc.binKind {
			case "directory":
				if err := os.Mkdir(bin, 0700); err != nil {
					t.Fatal(err)
				}
			case "file":
				writeTestExecutable(t, bin, "not a directory")
			}
			if tc.resourceKind == "file" {
				writeTestExecutable(t, resources, "not a directory")
			} else {
				if err := os.Mkdir(resources, 0700); err != nil {
					t.Fatal(err)
				}
				if tc.resourceKind == "host" {
					writeTestExecutable(t, filepath.Join(resources, "codex-code-mode-host"), "resource host")
				}
			}
			marker := filepath.Join(root, "codex-package.json")
			if tc.marker {
				if err := os.WriteFile(marker, []byte(`{"version":"0.149.1"}`), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Mkdir(marker, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if tc.binHost {
				writeTestExecutable(t, filepath.Join(bin, "codex-code-mode-host"), "bin host")
			}
			if tc.bogusBinResource {
				bogus := filepath.Join(bin, "codex-resources")
				if err := os.Mkdir(bogus, 0700); err != nil {
					t.Fatal(err)
				}
				writeTestExecutable(t, filepath.Join(bogus, "codex-code-mode-host"), "wrong host")
			}
			cli := filepath.Join(root, tc.entry, "codex")
			writeTestExecutable(t, cli, "cli")
			pinned := newPinnedExecutable(cli)
			if _, err := pinned.Resolve(); err != nil {
				t.Fatal(err)
			}
			want := ""
			if tc.want != "" {
				want = filepath.Join(root, tc.want, "codex-code-mode-host")
			}
			if pinned.companion != want {
				t.Fatalf("selected host=%q want=%q", pinned.companion, want)
			}
		})
	}
}

func TestCodeModeCompanionLegacyHomeAndBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, relative, homeMode string
		wantResource             bool
	}{
		{"release root equality", ".", "explicit", true},
		{"nested legacy release", "0.149.1/arm64", "explicit", true},
		{"symlinked CODEX_HOME", "0.149.1", "alias", true},
		{"default HOME context", "0.149.1", "default", true},
		{"outside lookalike boundary", "../releases-other/version", "explicit", false},
		{"missing CODEX_HOME only disables legacy recognition", "0.149.1", "missing", false},
		{"file CODEX_HOME only disables legacy recognition", "0.149.1", "file", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			home := filepath.Join(root, ".codex")
			releases := filepath.Join(home, "packages", "standalone", "releases")
			release := filepath.Join(releases, filepath.FromSlash(tc.relative))
			if err := os.MkdirAll(filepath.Join(release, "codex-resources"), 0700); err != nil {
				t.Fatal(err)
			}
			cli := filepath.Join(release, "codex")
			resource := filepath.Join(release, "codex-resources", "codex-code-mode-host")
			sibling := filepath.Join(release, "codex-code-mode-host")
			writeTestExecutable(t, cli, "cli")
			writeTestExecutable(t, resource, "resource host")
			writeTestExecutable(t, sibling, "sibling host")
			switch tc.homeMode {
			case "explicit":
				t.Setenv("CODEX_HOME", home)
			case "alias":
				alias := filepath.Join(root, "home-alias")
				if err := os.Symlink(home, alias); err != nil {
					t.Fatal(err)
				}
				t.Setenv("CODEX_HOME", alias)
			case "default":
				t.Setenv("CODEX_HOME", "")
				t.Setenv("HOME", root)
			case "missing":
				t.Setenv("CODEX_HOME", filepath.Join(root, "missing"))
			case "file":
				path := filepath.Join(root, "home-file")
				writeTestExecutable(t, path, "file")
				t.Setenv("CODEX_HOME", path)
			}
			pinned := newPinnedExecutable(cli)
			if _, err := pinned.Resolve(); err != nil {
				t.Fatal(err)
			}
			want := sibling
			if tc.wantResource {
				want = resource
			}
			if pinned.companion != want {
				t.Fatalf("selected host=%q want=%q", pinned.companion, want)
			}
		})
	}
}
