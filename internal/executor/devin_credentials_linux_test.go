package executor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/launch"
)

// This is an executor unit test with mocked process observations. Actual Linux
// target behavior is exercised by the launch package's native qualification.
func TestLinuxDevinProjectsOnlyTheAllowlistedCredential(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent", true: "present"}[present], func(t *testing.T) {
			f := newCatalogFixture(t)
			host := t.TempDir()
			f.request.ExistingHomeDirectory = host
			write := func(path, value string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			credential := filepath.Join(".local", "share", "devin", "credentials.toml")
			if present {
				write(filepath.Join(host, credential), "selected-synthetic-credential")
			}
			xdg := t.TempDir()
			t.Setenv("XDG_DATA_HOME", xdg)
			write(filepath.Join(xdg, "devin", "credentials.toml"), "ambient-xdg-credential")
			for _, relative := range []string{".local/share/cognition/credentials.toml", ".local/share/devin/other-token", ".config/devin/config.json", ".ssh/id_ed25519"} {
				write(filepath.Join(host, filepath.FromSlash(relative)), "unselected-host-data")
			}
			f.beforeCatalog = func(request launch.ProcessRequest) {
				path := filepath.Join(request.SessionHome, credential)
				data, err := os.ReadFile(path)
				if !present {
					if !os.IsNotExist(err) {
						t.Fatal("absent allowlisted credential fell back to another host source")
					}
				} else {
					info, statErr := os.Lstat(path)
					if err != nil || string(data) != "selected-synthetic-credential" || statErr != nil || info.Mode().Perm() != 0600 {
						t.Fatal("allowlisted credential bytes or private mode changed")
					}
				}
				for _, relative := range []string{".local/share/cognition", ".local/share/devin/other-token", ".ssh/id_ed25519"} {
					if _, err := os.Lstat(filepath.Join(request.SessionHome, filepath.FromSlash(relative))); !os.IsNotExist(err) {
						t.Fatal("unselected host data reached the Session")
					}
				}
			}
			if err := f.verify(t); err != nil {
				t.Fatal(err)
			}
		})
	}
}
