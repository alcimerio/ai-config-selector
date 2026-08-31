//go:build darwin

package codexauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestNativeKeychainFrameworkLoads(t *testing.T) {
	if _, err := newNativeKeychainClient(); err != nil {
		t.Fatalf("load native Keychain client: %v", err)
	}
}

func TestNativeKeychainCredentialFreeContract(t *testing.T) {
	if os.Getenv("ACS_RUN_NATIVE_AUTH_GATE") != "1" {
		t.Skip("set ACS_RUN_NATIVE_AUTH_GATE=1 to use an isolated temporary Keychain")
	}
	useIsolatedTestKeychain(t)
	clientValue, err := newNativeKeychainClient()
	if err != nil {
		t.Fatal(err)
	}
	client := clientValue.(*nativeKeychainClient)
	stamp := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	accountOne := "native-one-" + stamp
	accountTwo := "native-two-" + stamp
	otherService := keychainService + ".test." + stamp
	comment := `{"version":1,"kind":"credential-free-native-test"}`
	secret := bytes.Repeat([]byte("s"), maximumKeychainRecordSize)

	if err := client.Add(keychainService, accountOne, comment, secret); err != nil {
		t.Fatal(err)
	}
	if err := client.Add(keychainService, accountOne, comment, secret); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("duplicate add error = %v", err)
	}
	if err := client.Add(keychainService, accountTwo, comment, []byte("second-synthetic-record")); err != nil {
		t.Fatal(err)
	}
	if err := client.Add(otherService, accountOne, comment, []byte("isolated-synthetic-record")); err != nil {
		t.Fatal(err)
	}

	attributes, err := client.Attributes(keychainService, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(attributes) != 2 {
		t.Fatalf("production namespace item count = %d", len(attributes))
	}
	sort.Slice(attributes, func(left, right int) bool { return attributes[left].Account < attributes[right].Account })
	wantAccounts := []string{accountOne, accountTwo}
	sort.Strings(wantAccounts)
	gotAccounts := []string{attributes[0].Account, attributes[1].Account}
	if !reflect.DeepEqual(gotAccounts, wantAccounts) {
		t.Fatal("production namespace accounts did not match the isolated records")
	}
	wantAccessibility, err := client.api.goString(client.api.secAttrAccessibleWhenUnlockedThisDeviceOnly)
	if err != nil {
		t.Fatal("read expected Keychain accessibility")
	}
	for _, item := range attributes {
		// File-backed temporary Keychains can omit the accessibility attribute
		// from returned metadata. When present it must be the exact policy ACS
		// requested; query policy and error mapping are tested deterministically.
		if (item.Accessible != "" && item.Accessible != wantAccessibility) || item.Synchronizable {
			t.Fatal("Keychain item did not retain the required device-only accessibility")
		}
	}
	otherAttributes, err := client.Attributes(otherService, nil)
	if err != nil || len(otherAttributes) != 1 || otherAttributes[0].Account != accountOne {
		t.Fatal("service/account isolation was not preserved")
	}
	gotSecret, err := client.Data(keychainService, accountOne)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSecret, secret) {
		t.Fatal("Keychain changed the maximum-size opaque payload")
	}
	clearBytes(gotSecret)

	tooLargeAccount := "native-too-large-" + stamp
	tooLarge := bytes.Repeat([]byte("x"), maximumKeychainRecordSize+1)
	if err := client.Add(keychainService, tooLargeAccount, comment, tooLarge); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("oversized add error = %v", err)
	}
	if _, err := client.Attributes(keychainService, &tooLargeAccount); !errors.Is(err, errKeychainItemNotFound) {
		t.Fatalf("oversized add created an item: %v", err)
	}
	if err := client.Update(keychainService, accountOne, comment, tooLarge); !errors.Is(err, ErrProviderUnavailable) {
		t.Fatalf("oversized update error = %v", err)
	}
	gotSecret, err = client.Data(keychainService, accountOne)
	if err != nil || !bytes.Equal(gotSecret, secret) {
		t.Fatal("failed oversized update changed the previous payload")
	}
	clearBytes(gotSecret)

}

func TestIsolatedKeychainSetupRestoresAfterConfigurationFailure(t *testing.T) {
	for name, failurePoint := range map[string]string{
		"after search":  "list-keychains",
		"after default": "default-keychain",
		"after unlock":  "unlock-keychain",
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeSecurityCommand()
			directory := filepath.Join(t.TempDir(), "recoverable")
			keychain := filepath.Join(directory, "native-auth-gate.keychain-db")
			recoveryPath := filepath.Join(directory, isolatedKeychainRecoveryFilename)
			fake.keychainPath = keychain
			failedCommand := map[string]string{
				"create-keychain":  "create-keychain -p synthetic-password " + keychain,
				"list-keychains":   "list-keychains -d user -s " + keychain,
				"default-keychain": "default-keychain -d user -s " + keychain,
				"unlock-keychain":  "unlock-keychain -p synthetic-password " + keychain,
			}[failurePoint]
			fake.failuresAfter[failedCommand] = errors.New("injected post-mutation failure")
			var cleanup func()
			var cleanupErrors []error
			removed := false
			err := configureIsolatedTestKeychain(isolatedKeychainSetup{
				runSecurity: fake.run,
				makeDirectory: func() (string, error) {
					fake.events = append(fake.events, "mkdir")
					return directory, os.Mkdir(directory, 0o700)
				},
				removeDirectory: func(path string) error {
					fake.events = append(fake.events, "remove "+path)
					removed = true
					return os.Remove(path)
				},
				persistRecovery: func(path string, recovery isolatedKeychainRecovery) error {
					fake.events = append(fake.events, "persist recovery")
					return persistIsolatedKeychainRecovery(path, recovery)
				},
				registerCleanup: func(function func()) {
					fake.events = append(fake.events, "register cleanup")
					cleanup = function
				},
				reportCleanup: func(err error) { cleanupErrors = append(cleanupErrors, err) },
				password:      "synthetic-password",
			})
			if err == nil {
				t.Fatal("setup succeeded despite injected failure")
			}
			if cleanup == nil {
				t.Fatal("setup did not register fail-safe cleanup")
			}
			assertEventBefore(t, fake.events, "default-keychain -d user", "create-keychain -p synthetic-password "+keychain)
			assertEventBefore(t, fake.events, "list-keychains -d user", "create-keychain -p synthetic-password "+keychain)
			assertEventBefore(t, fake.events, "register cleanup", "mkdir")
			assertEventBefore(t, fake.events, "register cleanup", "create-keychain -p synthetic-password "+keychain)
			assertEventBefore(t, fake.events, "persist recovery", "create-keychain -p synthetic-password "+keychain)

			recovery, readErr := readIsolatedKeychainRecovery(recoveryPath)
			if readErr != nil {
				t.Fatalf("read recovery artifact: %v", readErr)
			}
			wantRecovery := isolatedKeychainRecovery{
				Version:         1,
				OriginalDefault: "/original/login.keychain-db",
				OriginalSearch:  []string{"/original/login.keychain-db", "/original/system.keychain"},
				Directory:       directory,
				Keychain:        keychain,
				Guidance:        isolatedKeychainRecoveryGuidance,
			}
			if !reflect.DeepEqual(recovery, wantRecovery) {
				t.Fatalf("recovery artifact = %#v, want %#v", recovery, wantRecovery)
			}
			info, statErr := os.Stat(recoveryPath)
			if statErr != nil || info.Mode().Perm() != 0o600 {
				t.Fatalf("recovery artifact mode = (%v, %v), want 0600", info, statErr)
			}

			cleanup()
			if len(cleanupErrors) != 0 {
				t.Fatalf("cleanup errors = %v", cleanupErrors)
			}
			searchRestore := "list-keychains -d user -s /original/login.keychain-db /original/system.keychain"
			defaultRestore := "default-keychain -d user -s /original/login.keychain-db"
			deleteKeychain := "delete-keychain " + keychain
			assertEventBefore(t, fake.events, searchRestore, deleteKeychain)
			assertEventBefore(t, fake.events, defaultRestore, deleteKeychain)
			if !removed {
				t.Fatal("successful restoration did not remove disposable directory")
			}
			if _, statErr := os.Stat(recoveryPath); !os.IsNotExist(statErr) {
				t.Fatalf("successful cleanup retained recovery artifact: %v", statErr)
			}
		})
	}
}

func TestIsolatedKeychainCleanupRetainsStateUntilBothRestorationsSucceed(t *testing.T) {
	for name, failedRestore := range map[string]string{
		"search":  "list-keychains -d user -s /original/login.keychain-db /original/system.keychain",
		"default": "default-keychain -d user -s /original/login.keychain-db",
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeSecurityCommand()
			directory := filepath.Join(t.TempDir(), "recoverable")
			keychain := filepath.Join(directory, "native-auth-gate.keychain-db")
			recoveryPath := filepath.Join(directory, isolatedKeychainRecoveryFilename)
			fake.keychainPath = keychain
			fake.failures[failedRestore] = errors.New("injected restoration failure")
			var cleanup func()
			var cleanupErrors []error
			removed := false
			err := configureIsolatedTestKeychain(isolatedKeychainSetup{
				runSecurity:   fake.run,
				makeDirectory: func() (string, error) { return directory, os.Mkdir(directory, 0o700) },
				removeDirectory: func(string) error {
					removed = true
					return os.Remove(directory)
				},
				registerCleanup: func(function func()) { cleanup = function },
				reportCleanup:   func(err error) { cleanupErrors = append(cleanupErrors, err) },
				password:        "synthetic-password",
			})
			if err != nil {
				t.Fatalf("setup: %v", err)
			}
			cleanup()
			if len(cleanupErrors) != 1 {
				t.Fatalf("cleanup errors = %v, want one", cleanupErrors)
			}
			for _, restored := range []string{
				"list-keychains -d user -s /original/login.keychain-db /original/system.keychain",
				"default-keychain -d user -s /original/login.keychain-db",
			} {
				if eventIndex(fake.events, restored) < 0 {
					t.Fatalf("cleanup did not attempt %q; events=%q", restored, fake.events)
				}
			}
			if eventIndex(fake.events, "delete-keychain "+keychain) >= 0 || removed {
				t.Fatalf("cleanup deleted recoverable state before restoration succeeded; events=%q", fake.events)
			}
			if _, statErr := os.Stat(recoveryPath); statErr != nil {
				t.Fatalf("failed restoration lost recovery artifact: %v", statErr)
			}
			if _, statErr := os.Stat(keychain); statErr != nil {
				t.Fatalf("failed restoration lost disposable Keychain: %v", statErr)
			}
			if !strings.Contains(cleanupErrors[0].Error(), recoveryPath) {
				t.Fatalf("cleanup error does not surface retained recovery artifact: %v", cleanupErrors[0])
			}
		})
	}
}

func TestIsolatedKeychainRecoverySurvivesLossOfInMemorySetup(t *testing.T) {
	fake := newFakeSecurityCommand()
	directory := filepath.Join(t.TempDir(), "recoverable")
	keychain := filepath.Join(directory, "native-auth-gate.keychain-db")
	recoveryPath := filepath.Join(directory, isolatedKeychainRecoveryFilename)
	fake.keychainPath = keychain
	var cleanup func()
	err := configureIsolatedTestKeychain(isolatedKeychainSetup{
		runSecurity:     fake.run,
		makeDirectory:   func() (string, error) { return directory, os.Mkdir(directory, 0o700) },
		removeDirectory: os.Remove,
		registerCleanup: func(function func()) { cleanup = function },
		reportCleanup:   func(error) {},
		password:        "synthetic-password",
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if cleanup == nil {
		t.Fatal("setup did not register cleanup")
	}

	// Recover solely from the durable artifact, as a new process would after
	// the original setup state and cleanup closure have disappeared.
	if err := recoverIsolatedTestKeychain(recoveryPath, fake.run, os.Remove); err != nil {
		t.Fatalf("recover from artifact: %v", err)
	}
	for _, path := range []string{recoveryPath, keychain, directory} {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("recovery retained %s: %v", path, statErr)
		}
	}
}

type fakeSecurityCommand struct {
	events        []string
	failures      map[string]error
	failuresAfter map[string]error
	keychainPath  string
}

func newFakeSecurityCommand() *fakeSecurityCommand {
	return &fakeSecurityCommand{failures: make(map[string]error), failuresAfter: make(map[string]error)}
}

func (fake *fakeSecurityCommand) run(arguments ...string) (string, error) {
	command := strings.Join(arguments, " ")
	fake.events = append(fake.events, command)
	if err := fake.failures[command]; err != nil {
		return "", err
	}
	if strings.HasPrefix(command, "create-keychain ") && fake.keychainPath != "" {
		if err := os.WriteFile(fake.keychainPath, []byte("synthetic disposable Keychain"), 0o600); err != nil {
			return "", err
		}
	}
	if strings.HasPrefix(command, "delete-keychain ") && fake.keychainPath != "" {
		if err := os.Remove(fake.keychainPath); err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	var output string
	switch command {
	case "default-keychain -d user":
		output = "\"/original/login.keychain-db\"\n"
	case "list-keychains -d user":
		output = "    \"/original/login.keychain-db\"\n    \"/original/system.keychain\"\n"
	}
	if err := fake.failuresAfter[command]; err != nil {
		return output, err
	}
	return output, nil
}

func assertEventBefore(t *testing.T, events []string, first, second string) {
	t.Helper()
	firstIndex := eventIndex(events, first)
	secondIndex := eventIndex(events, second)
	if firstIndex < 0 || secondIndex < 0 || firstIndex >= secondIndex {
		t.Fatalf("event %q must precede %q; events=%q", first, second, events)
	}
}

func eventIndex(events []string, wanted string) int {
	for index, event := range events {
		if event == wanted {
			return index
		}
	}
	return -1
}

func useIsolatedTestKeychain(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/security"); err != nil {
		t.Fatal("system Keychain tool is unavailable")
	}
	password := fmt.Sprintf("synthetic-%d-%d", os.Getpid(), time.Now().UnixNano())
	if err := configureIsolatedTestKeychain(isolatedKeychainSetup{
		runSecurity: func(arguments ...string) (string, error) {
			output, err := exec.Command("/usr/bin/security", arguments...).CombinedOutput()
			return string(output), err
		},
		makeDirectory: func() (string, error) {
			return os.MkdirTemp("", "acs-native-auth-gate-")
		},
		removeDirectory: os.Remove,
		registerCleanup: t.Cleanup,
		reportCleanup: func(err error) {
			t.Errorf("restore isolated Keychain state: %v", err)
		},
		password: password,
	}); err != nil {
		t.Fatal(err)
	}
}

type isolatedKeychainSetup struct {
	runSecurity     func(...string) (string, error)
	makeDirectory   func() (string, error)
	removeDirectory func(string) error
	persistRecovery func(string, isolatedKeychainRecovery) error
	registerCleanup func(func())
	reportCleanup   func(error)
	password        string
}

type isolatedKeychainState struct {
	setup            isolatedKeychainSetup
	originalDefault  string
	originalSearch   []string
	directory        string
	keychain         string
	recoveryPath     string
	keychainMayExist bool
}

const (
	isolatedKeychainRecoveryFilename = "native-auth-gate.recovery.json"
	isolatedKeychainRecoveryGuidance = "Restore the user Keychain search list and default from this file with /usr/bin/security, then delete the disposable Keychain and this directory only after both restorations succeed."
)

type isolatedKeychainRecovery struct {
	Version         int      `json:"version"`
	OriginalDefault string   `json:"originalDefault"`
	OriginalSearch  []string `json:"originalSearch"`
	Directory       string   `json:"directory"`
	Keychain        string   `json:"keychain"`
	Guidance        string   `json:"guidance"`
}

func configureIsolatedTestKeychain(setup isolatedKeychainSetup) error {
	originalDefaultOutput, err := setup.runSecurity("default-keychain", "-d", "user")
	if err != nil {
		return errors.New("inspect default Keychain configuration")
	}
	originalDefault := strings.Trim(originalDefaultOutput, "\"\n \t\r")
	if originalDefault == "" {
		return errors.New("default Keychain configuration is empty")
	}
	originalSearchOutput, err := setup.runSecurity("list-keychains", "-d", "user")
	if err != nil {
		return errors.New("inspect Keychain search configuration")
	}
	state := &isolatedKeychainState{
		setup:           setup,
		originalDefault: originalDefault,
		originalSearch:  parseSecurityKeychainList(originalSearchOutput),
	}
	setup.registerCleanup(func() {
		if err := state.cleanup(); err != nil {
			setup.reportCleanup(err)
		}
	})

	state.directory, err = setup.makeDirectory()
	if err != nil {
		return errors.New("create isolated Keychain directory")
	}
	state.keychain = filepath.Join(state.directory, "native-auth-gate.keychain-db")
	state.recoveryPath = filepath.Join(state.directory, isolatedKeychainRecoveryFilename)
	persistRecovery := setup.persistRecovery
	if persistRecovery == nil {
		persistRecovery = persistIsolatedKeychainRecovery
	}
	if err := persistRecovery(state.recoveryPath, isolatedKeychainRecovery{
		Version:         1,
		OriginalDefault: state.originalDefault,
		OriginalSearch:  append([]string(nil), state.originalSearch...),
		Directory:       state.directory,
		Keychain:        state.keychain,
		Guidance:        isolatedKeychainRecoveryGuidance,
	}); err != nil {
		return errors.New("persist isolated Keychain recovery state")
	}
	state.keychainMayExist = true
	for _, command := range [][]string{
		{"create-keychain", "-p", setup.password, state.keychain},
		{"list-keychains", "-d", "user", "-s", state.keychain},
		{"default-keychain", "-d", "user", "-s", state.keychain},
		{"unlock-keychain", "-p", setup.password, state.keychain},
	} {
		if _, err := setup.runSecurity(command...); err != nil {
			return errors.New("configure isolated Keychain")
		}
	}
	return nil
}

func (state *isolatedKeychainState) cleanup() error {
	searchArguments := []string{"list-keychains", "-d", "user", "-s"}
	searchArguments = append(searchArguments, state.originalSearch...)
	_, searchErr := state.setup.runSecurity(searchArguments...)
	_, defaultErr := state.setup.runSecurity("default-keychain", "-d", "user", "-s", state.originalDefault)
	if searchErr != nil || defaultErr != nil {
		return fmt.Errorf("recovery state retained at %s: %w", state.recoveryPath, errors.Join(
			cleanupError("restore Keychain search list", searchErr),
			cleanupError("restore default Keychain", defaultErr),
		))
	}
	if state.keychainMayExist {
		if _, err := state.setup.runSecurity("delete-keychain", state.keychain); err != nil {
			return errors.New("delete isolated Keychain after restoration")
		}
	}
	if state.directory != "" {
		if state.recoveryPath != "" {
			if err := os.Remove(state.recoveryPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("delete isolated Keychain recovery artifact %s: %w", state.recoveryPath, err)
			}
		}
		if err := state.setup.removeDirectory(state.directory); err != nil {
			return errors.New("delete isolated Keychain directory after restoration")
		}
	}
	return nil
}

func persistIsolatedKeychainRecovery(path string, recovery isolatedKeychainRecovery) (resultErr error) {
	contents, err := json.Marshal(recovery)
	if err != nil {
		return err
	}
	contents = append(contents, '\n')
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
		if resultErr != nil {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(contents); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func readIsolatedKeychainRecovery(path string) (isolatedKeychainRecovery, error) {
	var recovery isolatedKeychainRecovery
	info, err := os.Lstat(path)
	if err != nil {
		return recovery, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		return recovery, errors.New("recovery artifact is not a private regular file")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return recovery, err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&recovery); err != nil {
		return isolatedKeychainRecovery{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return isolatedKeychainRecovery{}, errors.New("recovery artifact has trailing data")
	}
	if recovery.Version != 1 || recovery.OriginalDefault == "" || len(recovery.OriginalSearch) == 0 ||
		recovery.Directory == "" || recovery.Keychain != filepath.Join(recovery.Directory, "native-auth-gate.keychain-db") ||
		path != filepath.Join(recovery.Directory, isolatedKeychainRecoveryFilename) || recovery.Guidance != isolatedKeychainRecoveryGuidance {
		return isolatedKeychainRecovery{}, errors.New("recovery artifact is invalid")
	}
	return recovery, nil
}

func recoverIsolatedTestKeychain(
	recoveryPath string,
	runSecurity func(...string) (string, error),
	removeDirectory func(string) error,
) error {
	recovery, err := readIsolatedKeychainRecovery(recoveryPath)
	if err != nil {
		return fmt.Errorf("read isolated Keychain recovery artifact: %w", err)
	}
	state := isolatedKeychainState{
		setup: isolatedKeychainSetup{
			runSecurity:     runSecurity,
			removeDirectory: removeDirectory,
		},
		originalDefault:  recovery.OriginalDefault,
		originalSearch:   recovery.OriginalSearch,
		directory:        recovery.Directory,
		keychain:         recovery.Keychain,
		recoveryPath:     recoveryPath,
		keychainMayExist: true,
	}
	return state.cleanup()
}

func cleanupError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}

func parseSecurityKeychainList(output string) []string {
	var paths []string
	for _, line := range strings.Split(output, "\n") {
		path := strings.Trim(line, "\" \t\r")
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}
