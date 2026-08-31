//go:build darwin

package codexauth

import (
	"bytes"
	"errors"
	"fmt"
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
	keychain := "/recoverable/native-auth-gate.keychain-db"
	for name, failurePoint := range map[string]string{
		"after search":  "list-keychains",
		"after default": "default-keychain",
		"after unlock":  "unlock-keychain",
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeSecurityCommand()
			var cleanup func()
			var cleanupErrors []error
			removed := false
			err := configureIsolatedTestKeychain(isolatedKeychainSetup{
				runSecurity: fake.run,
				makeDirectory: func() (string, error) {
					fake.events = append(fake.events, "mkdir")
					return "/recoverable", nil
				},
				removeDirectory: func(path string) error {
					fake.events = append(fake.events, "remove "+path)
					removed = true
					return nil
				},
				registerCleanup: func(function func()) {
					fake.events = append(fake.events, "register cleanup")
					cleanup = function
				},
				reportCleanup: func(err error) { cleanupErrors = append(cleanupErrors, err) },
				afterMutation: func(operation string) error {
					if operation == failurePoint {
						return errors.New("injected post-mutation failure")
					}
					return nil
				},
				password: "synthetic-password",
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
		})
	}
}

func TestIsolatedKeychainCleanupRetainsStateUntilBothRestorationsSucceed(t *testing.T) {
	keychain := "/recoverable/native-auth-gate.keychain-db"
	for name, failedRestore := range map[string]string{
		"search":  "list-keychains -d user -s /original/login.keychain-db /original/system.keychain",
		"default": "default-keychain -d user -s /original/login.keychain-db",
	} {
		t.Run(name, func(t *testing.T) {
			fake := newFakeSecurityCommand()
			fake.failures[failedRestore] = errors.New("injected restoration failure")
			var cleanup func()
			var cleanupErrors []error
			removed := false
			err := configureIsolatedTestKeychain(isolatedKeychainSetup{
				runSecurity:   fake.run,
				makeDirectory: func() (string, error) { return "/recoverable", nil },
				removeDirectory: func(string) error {
					removed = true
					return nil
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
		})
	}
}

type fakeSecurityCommand struct {
	events   []string
	failures map[string]error
}

func newFakeSecurityCommand() *fakeSecurityCommand {
	return &fakeSecurityCommand{failures: make(map[string]error)}
}

func (fake *fakeSecurityCommand) run(arguments ...string) (string, error) {
	command := strings.Join(arguments, " ")
	fake.events = append(fake.events, command)
	if err := fake.failures[command]; err != nil {
		return "", err
	}
	switch command {
	case "default-keychain -d user":
		return "\"/original/login.keychain-db\"\n", nil
	case "list-keychains -d user":
		return "    \"/original/login.keychain-db\"\n    \"/original/system.keychain\"\n", nil
	default:
		return "", nil
	}
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
	registerCleanup func(func())
	reportCleanup   func(error)
	afterMutation   func(string) error
	password        string
}

type isolatedKeychainState struct {
	setup            isolatedKeychainSetup
	originalDefault  string
	originalSearch   []string
	directory        string
	keychain         string
	keychainMayExist bool
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
		if setup.afterMutation != nil {
			if err := setup.afterMutation(command[0]); err != nil {
				return errors.New("configure isolated Keychain")
			}
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
		return errors.Join(
			cleanupError("restore Keychain search list", searchErr),
			cleanupError("restore default Keychain", defaultErr),
		)
	}
	if state.keychainMayExist {
		if _, err := state.setup.runSecurity("delete-keychain", state.keychain); err != nil {
			return errors.New("delete isolated Keychain after restoration")
		}
	}
	if state.directory != "" {
		if err := state.setup.removeDirectory(state.directory); err != nil {
			return errors.New("delete isolated Keychain directory after restoration")
		}
	}
	return nil
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
