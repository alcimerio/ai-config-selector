package codexauthresource

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func fileProviderFixture(t *testing.T) (*fileCredentialProvider, string, credentialRecord) {
	t.Helper()
	providerTestConfig(t)
	if err := SelectProvider(ProviderFile); err != nil {
		t.Fatal(err)
	}
	provider := newFileCredentialProvider()
	auth := testChatGPTAuthJSON(t, "user", "workspace")
	metadata, err := validateAuthJSON("work", auth)
	if err != nil {
		t.Fatal(err)
	}
	return provider, filepath.Join(provider.statePath, "credentials"), credentialRecord{Metadata: metadata, Auth: auth}
}

func TestLinuxFileProviderConformance(t *testing.T) {
	testProviderConformance(t, func() credentialProvider {
		provider, _, _ := fileProviderFixture(t)
		return provider
	})
}

func TestLinuxFileProviderRequiresDurableOptIn(t *testing.T) {
	for _, choice := range []ProviderID{"", ProviderSecretService} {
		t.Run(string(choice), func(t *testing.T) {
			providerTestConfig(t)
			if choice != "" {
				if err := SelectProvider(choice); err != nil {
					t.Fatal(err)
				}
			}
			auth := testChatGPTAuthJSON(t, "user", "workspace")
			metadata, _ := validateAuthJSON("work", auth)
			testProviderFailures(t, newFileCredentialProvider(), context.Background(), credentialRecord{Metadata: metadata, Auth: auth}, ErrProviderUnavailable)
			if _, err := os.Stat(os.Getenv("XDG_STATE_HOME")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unselected provider provisioned state: %v", err)
			}
		})
	}
}

func TestLinuxFileProviderHeadlessPersistenceAndModes(t *testing.T) {
	_, directory, record := fileProviderFixture(t)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/private-canary")
	t.Setenv("DISPLAY", "")
	t.Setenv("WAYLAND_DISPLAY", "")
	provider := newPlatformProvider()
	if _, ok := provider.(*fileCredentialProvider); !ok {
		t.Fatal("selected file provider was not constructed")
	}
	if err := provider.Create(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	assertFileCredential(t, newPlatformProvider(), record)
	for path, mode := range map[string]os.FileMode{
		filepath.Dir(directory):               0o700,
		directory:                             0o700,
		filepath.Join(directory, "work.json"): 0o600,
	} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("storage mode mismatch: %v", err)
		}
	}
	for _, variable := range []string{"XDG_DATA_HOME", "XDG_RUNTIME_DIR"} {
		if _, err := os.Stat(os.Getenv(variable)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("provider used %s: %v", variable, err)
		}
	}
	store, err := New(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if rows, err := store.List(context.Background()); err != nil || len(rows) != 1 || rows[0] != record.Metadata {
		t.Fatalf("reopened Store list: %v", err)
	}
	if binding, err := store.AcquireLogin(context.Background(), "work"); binding != nil || !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("existing identity login: %v", err)
	}
	if err := store.Logout(context.Background(), "work"); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := newPlatformProvider().Load(context.Background(), "work"); exists || err != nil {
		t.Fatalf("logout was not durable: %v", err)
	}
}

func TestLinuxFileProviderXDGPathsAndSelectionRevalidation(t *testing.T) {
	provider, _, record := fileProviderFixture(t)
	t.Setenv("XDG_STATE_HOME", "")
	want := filepath.Join(os.Getenv("HOME"), ".local", "state", "acs")
	if path, err := credentialStateDirectory(); err != nil || path != want {
		t.Fatalf("default state directory: %v", err)
	}
	for _, variable := range []string{"XDG_STATE_HOME", "HOME"} {
		t.Setenv(variable, "private-relative-canary")
		_, err := newFileCredentialProvider().List(context.Background())
		if !errors.Is(err, ErrProviderUnavailable) || strings.Contains(err.Error(), "private-relative-canary") {
			t.Fatalf("relative state error: %v", err)
		}
		t.Setenv(variable, "")
	}
	// The already constructed provider retains its absolute paths, but must
	// still refuse a removed or externally changed durable selection.
	if err := provider.Create(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	selection := filepath.Join(provider.configPath, providerSelectionFilename)
	if err := os.WriteFile(selection, []byte(`{"version":1,"provider":"secret-service"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	testProviderFailures(t, provider, context.Background(), record, ErrProviderUnavailable)
}

func TestLinuxFileProviderRejectsUnsafeRecordsWithoutRepair(t *testing.T) {
	for name, mutate := range map[string]func(string) error{
		"public":    func(path string) error { return os.Chmod(path, 0o644) },
		"read only": func(path string) error { return os.Chmod(path, 0o400) },
		"setuid":    func(path string) error { return os.Chmod(path, 0o600|os.ModeSetuid) },
		"hard link": func(path string) error { return os.Link(path, path+".alias") },
		"symlink": func(path string) error {
			if err := os.Rename(path, path+".target"); err != nil {
				return err
			}
			return os.Symlink(path+".target", path)
		},
		"directory": func(path string) error {
			if err := os.Remove(path); err != nil {
				return err
			}
			return os.Mkdir(path, 0o700)
		},
		"fifo": func(path string) error {
			if err := os.Remove(path); err != nil {
				return err
			}
			return unix.Mkfifo(path, 0o600)
		},
		"empty":     func(path string) error { return os.Truncate(path, 0) },
		"oversized": func(path string) error { return os.Truncate(path, maximumFileCredentialSize+1) },
		"malformed": func(path string) error { return os.WriteFile(path, []byte(`private-token-canary`), 0o600) },
		"duplicates": func(path string) error {
			return os.WriteFile(path, []byte(`{"version":1,"version":1,"auth":{}}`), 0o600)
		},
		"alias": func(path string) error { return os.WriteFile(path, []byte(`{"version":1,"Auth":{}}`), 0o600) },
		"unknown": func(path string) error {
			return os.WriteFile(path, []byte(`{"version":1,"auth":{},"secret":"private-token-canary"}`), 0o600)
		},
		"version": func(path string) error { return os.WriteFile(path, []byte(`{"version":2,"auth":{}}`), 0o600) },
		"auth": func(path string) error {
			return os.WriteFile(path, []byte(`{"version":1,"auth":{"OPENAI_API_KEY":"private-token-canary"}}`), 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			provider, directory, record := fileProviderFixture(t)
			if err := provider.Create(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, "work.json")
			if err := mutate(path); err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			testProviderFailures(t, provider, context.Background(), record, ErrProviderUnavailable)
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
				t.Fatalf("unsafe record was repaired or removed: %v", err)
			}
		})
	}
}

func TestLinuxFileProviderRejectsUnsafeAndReplacedDirectories(t *testing.T) {
	for name, mutate := range map[string]func(string) error{
		"public credential directory": func(path string) error { return os.Chmod(path, 0o755) },
		"read only directory":         func(path string) error { return os.Chmod(path, 0o500) },
		"public ACS directory":        func(path string) error { return os.Chmod(filepath.Dir(path), 0o755) },
		"writable ancestor":           func(path string) error { return os.Chmod(filepath.Dir(filepath.Dir(path)), 0o777) },
		"symlink ancestor": func(path string) error {
			parent := filepath.Dir(path)
			if err := os.Rename(parent, parent+".old"); err != nil {
				return err
			}
			return os.Symlink(parent+".old", parent)
		},
		"replaced directory": func(path string) error {
			if err := os.Rename(path, path+".old"); err != nil {
				return err
			}
			return os.Mkdir(path, 0o700)
		},
		"missing directory": func(path string) error { return os.RemoveAll(path) },
	} {
		t.Run(name, func(t *testing.T) {
			provider, directory, record := fileProviderFixture(t)
			if err := provider.Create(context.Background(), record); err != nil {
				t.Fatal(err)
			}
			if err := mutate(directory); err != nil {
				t.Fatal(err)
			}
			if name == "read only directory" {
				t.Cleanup(func() {
					if err := os.Chmod(directory, 0o700); err != nil {
						t.Error(err)
					}
				})
			}
			testProviderFailures(t, provider, context.Background(), record, ErrProviderUnavailable)
			// A fresh instance must also refuse unsafe permissions and aliases.
			if name != "replaced directory" && name != "missing directory" {
				testProviderFailures(t, newFileCredentialProvider(), context.Background(), record, ErrProviderUnavailable)
			}
			if name == "missing directory" {
				if _, err := os.Stat(directory); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("missing directory was recreated: %v", err)
				}
			}
		})
	}
}

func TestLinuxFileProviderOwnershipAndMetadataChecks(t *testing.T) {
	base := unix.Stat_t{Mode: unix.S_IFREG | 0o600, Uid: uint32(os.Geteuid()), Nlink: 1, Size: 1}
	if !validCredentialFile(base, false) {
		t.Fatal("valid descriptor rejected")
	}
	for _, mutate := range []func(*unix.Stat_t){
		func(stat *unix.Stat_t) { stat.Uid++ },
		func(stat *unix.Stat_t) { stat.Nlink++ },
		func(stat *unix.Stat_t) { stat.Mode |= 0o040 },
		func(stat *unix.Stat_t) { stat.Mode |= unix.S_ISGID },
		func(stat *unix.Stat_t) { stat.Mode = unix.S_IFSOCK | 0o600 },
		func(stat *unix.Stat_t) { stat.Size = -1 },
		func(stat *unix.Stat_t) { stat.Size = maximumFileCredentialSize + 1 },
	} {
		stat := base
		mutate(&stat)
		if validCredentialFile(stat, false) {
			t.Fatal("unsafe descriptor accepted")
		}
	}
	provider, directory, record := fileProviderFixture(t)
	if err := provider.Create(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	for _, name := range []CredentialRef{"../private-token-canary", "/private-token-canary", "", "Work"} {
		if _, _, err := provider.Load(context.Background(), name); !errors.Is(err, ErrInvalidCredentialRef) || strings.Contains(err.Error(), "private-token-canary") {
			t.Fatalf("unsafe name error: %v", err)
		}
		if err := provider.Delete(context.Background(), name); !errors.Is(err, ErrInvalidCredentialRef) {
			t.Fatalf("unsafe delete: %v", err)
		}
	}
	otherAuth := testChatGPTAuthJSON(t, "other-user", "workspace")
	otherMetadata, _ := validateAuthJSON("work", otherAuth)
	if err := provider.Replace(context.Background(), credentialRecord{Metadata: otherMetadata, Auth: otherAuth}); !errors.Is(err, ErrUnsupportedAuth) {
		t.Fatalf("identity substitution: %v", err)
	}
	assertFileCredential(t, provider, record)
	// No parser error or private path is included in any provider diagnostic.
	if err := os.WriteFile(filepath.Join(directory, "work.json"), []byte("private-token-canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := provider.Load(context.Background(), "work")
	if err == nil || strings.Contains(err.Error(), directory) || strings.Contains(err.Error(), "private-token-canary") || strings.Contains(err.Error(), "access-secret") {
		t.Fatal("provider error exposed private data")
	}
}

func TestLinuxFileProviderAtomicWriteFailures(t *testing.T) {
	for _, stage := range []string{"file sync", "rename", "directory sync", "cancel before rename"} {
		t.Run(stage, func(t *testing.T) {
			provider, directory, original := fileProviderFixture(t)
			if err := provider.Create(context.Background(), original); err != nil {
				t.Fatal(err)
			}
			refreshed := original
			refreshed.Auth = bytes.Replace(original.Auth, []byte("access-secret"), []byte("access-refreshed"), 1)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wantError := ErrProviderUnavailable
			wantRecord := original
			switch stage {
			case "file sync":
				provider.syncFile = func(*os.File) error { return errors.New("private-token-canary") }
			case "rename":
				provider.rename = func(*privateDirectory, string, string, bool) error { return unix.EROFS }
			case "directory sync":
				provider.syncDirectory = func(*privateDirectory) error { return unix.EIO }
				wantRecord = refreshed
			case "cancel before rename":
				provider.syncFile = func(file *os.File) error { cancel(); return file.Sync() }
				wantError = context.Canceled
			}
			if err := provider.Replace(ctx, refreshed); !errors.Is(err, wantError) || strings.Contains(err.Error(), "private-token-canary") {
				t.Fatalf("failed transaction error: %v", err)
			}
			assertFileCredential(t, newFileCredentialProvider(), wantRecord)
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 1 || entries[0].Name() != "work.json" {
				t.Fatalf("failed transaction left a temporary: %v", err)
			}
		})
	}
}

func TestLinuxFileProviderInterruptedTemporaryIsNeverPromoted(t *testing.T) {
	provider, directory, record := fileProviderFixture(t)
	if err := provider.Create(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	for index, contents := range [][]byte{nil, []byte(`{"version":1,"auth":`), record.Auth} {
		path := filepath.Join(directory, credentialTemporaryPrefix+fmt.Sprintf("%032x", index))
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := newFileCredentialProvider().List(context.Background())
	if err != nil || len(rows) != 1 || rows[0] != record.Metadata {
		t.Fatalf("interrupted transaction changed identity list: %v", err)
	}
	assertFileCredential(t, newFileCredentialProvider(), record)
	if err := os.WriteFile(filepath.Join(directory, "unknown.json"), record.Auth, 0o600); err != nil {
		t.Fatal(err)
	}
	if rows, err := provider.List(context.Background()); len(rows) != 0 || !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("corrupt identity produced partial list: %v", err)
	}
}

func TestLinuxFileProviderPublishesOnlySyncedTemporary(t *testing.T) {
	provider, directory, original := fileProviderFixture(t)
	if err := provider.Create(context.Background(), original); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "work.json")
	old, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	refreshed := original
	refreshed.Auth = bytes.Replace(original.Auth, []byte("access-secret"), []byte("access-refreshed"), 1)
	var stages []string
	nativeRename, nativeSync := provider.rename, provider.syncDirectory
	provider.syncFile = func(file *os.File) error {
		var stat unix.Stat_t
		if err := unix.Fstat(int(file.Fd()), &stat); err != nil || !validCredentialFile(stat, false) {
			t.Fatal("temporary is not a private regular file")
		}
		stages = append(stages, "file sync")
		return file.Sync()
	}
	provider.rename = func(directory *privateDirectory, from, to string, create bool) error {
		if strings.Join(stages, ",") != "file sync" || create {
			t.Fatal("replacement preceded file sync")
		}
		stages = append(stages, "rename")
		return nativeRename(directory, from, to, create)
	}
	provider.syncDirectory = func(directory *privateDirectory) error {
		if strings.Join(stages, ",") != "file sync,rename" {
			t.Fatal("directory sync preceded rename")
		}
		stages = append(stages, "directory sync")
		return nativeSync(directory)
	}
	if err := provider.Replace(context.Background(), refreshed); err != nil {
		t.Fatal(err)
	}
	if strings.Join(stages, ",") != "file sync,rename,directory sync" {
		t.Fatalf("publication stages = %v", stages)
	}
	contents, err := io.ReadAll(old)
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(contents)
	auth, err := decodeEnvelope(contents)
	defer clearBytes(auth)
	if err != nil || !bytes.Equal(auth, original.Auth) {
		t.Fatal("replacement mutated the original inode")
	}
	assertFileCredential(t, provider, refreshed)
}

func TestLinuxFileProviderConcurrentCreate(t *testing.T) {
	_, _, record := fileProviderFixture(t)
	var workers sync.WaitGroup
	results := make(chan error, 12)
	for range cap(results) {
		workers.Go(func() { results <- newFileCredentialProvider().Create(context.Background(), record) })
	}
	workers.Wait()
	close(results)
	created := 0
	for err := range results {
		if err == nil {
			created++
		} else if !errors.Is(err, ErrIdentityExists) {
			t.Fatalf("concurrent create: %v", err)
		}
	}
	if created != 1 {
		t.Fatalf("created %d records, want one", created)
	}
	assertFileCredential(t, newFileCredentialProvider(), record)
}

func TestLinuxFileProviderProcessLockAndOwnerExit(t *testing.T) {
	provider, _, record := fileProviderFixture(t)
	if err := provider.Create(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLinuxFileProviderSubprocess$")
	command.Env = append(os.Environ(), "ACS_FILE_PROVIDER_TEST_HELPER=lock")
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "locked\n" {
		t.Fatalf("lock helper did not start: %v", err)
	}
	blocked, cancelBlocked := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelBlocked()
	if _, _, err := provider.Load(blocked, "work"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("operation bypassed process lock: %v", err)
	}
	if err := command.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = command.Wait()
	assertFileCredential(t, provider, record)
}

func TestLinuxFileProviderSubprocess(t *testing.T) {
	if os.Getenv("ACS_FILE_PROVIDER_TEST_HELPER") != "lock" {
		return
	}
	directory, err := newFileCredentialProvider().open()
	if err != nil {
		t.Fatal(err)
	}
	defer directory.file.Close()
	if err := unix.Flock(int(directory.file.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(os.Stdout, "locked")
	_, _ = io.Copy(io.Discard, os.Stdin)
}

func assertFileCredential(t *testing.T, provider credentialProvider, expected credentialRecord) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	record, exists, err := provider.Load(ctx, expected.Metadata.Name)
	defer clearBytes(record.Auth)
	if err != nil || !exists || record.Metadata != expected.Metadata || !bytes.Equal(record.Auth, expected.Auth) {
		t.Fatalf("stored record mismatch: exists=%v err=%v", exists, err)
	}
}
