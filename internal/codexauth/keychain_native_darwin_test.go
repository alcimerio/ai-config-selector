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
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
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
			recoveryRoot := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
			directory := filepath.Join(recoveryRoot, "state-test")
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
				recoveryRoot: recoveryRoot,
				runSecurity:  fake.run,
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
			recoveryRoot := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
			directory := filepath.Join(recoveryRoot, "state-test")
			keychain := filepath.Join(directory, "native-auth-gate.keychain-db")
			recoveryPath := filepath.Join(directory, isolatedKeychainRecoveryFilename)
			locatorPath := filepath.Join(recoveryRoot, isolatedKeychainLocatorFilename)
			fake.keychainPath = keychain
			fake.failures[failedRestore] = errors.New("injected restoration failure")
			var cleanup func()
			var cleanupErrors []error
			removed := false
			err := configureIsolatedTestKeychain(isolatedKeychainSetup{
				recoveryRoot:  recoveryRoot,
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
			if !strings.Contains(cleanupErrors[0].Error(), locatorPath) {
				t.Fatalf("cleanup error does not surface retained recovery locator: %v", cleanupErrors[0])
			}
		})
	}
}

func TestIsolatedKeychainRecoverySurvivesLossOfInMemorySetup(t *testing.T) {
	fake := newFakeSecurityCommand()
	recoveryRoot := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
	directory := filepath.Join(recoveryRoot, "state-test")
	keychain := filepath.Join(directory, "native-auth-gate.keychain-db")
	recoveryPath := filepath.Join(directory, isolatedKeychainRecoveryFilename)
	fake.keychainPath = keychain
	var cleanup func()
	err := configureIsolatedTestKeychain(isolatedKeychainSetup{
		recoveryRoot:    recoveryRoot,
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

func TestIsolatedKeychainRecoveryRestoresOriginallyEmptySearchList(t *testing.T) {
	fake := newFakeSecurityCommand()
	directory := filepath.Join(canonicalTestTemporaryDirectory(t), "recoverable")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	keychain := filepath.Join(directory, "native-auth-gate.keychain-db")
	if err := os.WriteFile(keychain, []byte("synthetic disposable Keychain"), 0o600); err != nil {
		t.Fatal(err)
	}
	fake.keychainPath = keychain
	recoveryPath := filepath.Join(directory, isolatedKeychainRecoveryFilename)
	if err := persistIsolatedKeychainRecovery(recoveryPath, isolatedKeychainRecovery{
		Version:         1,
		OriginalDefault: "/original/login.keychain-db",
		OriginalSearch:  []string{},
		Directory:       directory,
		Keychain:        keychain,
		Guidance:        isolatedKeychainRecoveryGuidance,
	}); err != nil {
		t.Fatal(err)
	}

	if err := recoverIsolatedTestKeychain(recoveryPath, fake.run, os.Remove); err != nil {
		t.Fatalf("recover empty search list: %v", err)
	}
	if eventIndex(fake.events, "list-keychains -d user -s") < 0 {
		t.Fatalf("empty search list was not restored explicitly; events=%q", fake.events)
	}
}

func TestIsolatedKeychainSetupPersistsOriginallyEmptySearchList(t *testing.T) {
	fake := newFakeSecurityCommand()
	fake.originalSearchOutput = new(string)
	recoveryRoot := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
	directory := filepath.Join(recoveryRoot, "state-empty")
	keychain := filepath.Join(directory, "native-auth-gate.keychain-db")
	fake.keychainPath = keychain
	var cleanup func()
	if err := configureIsolatedTestKeychain(isolatedKeychainSetup{
		recoveryRoot:    recoveryRoot,
		runSecurity:     fake.run,
		makeDirectory:   func() (string, error) { return directory, os.Mkdir(directory, 0o700) },
		removeDirectory: os.Remove,
		registerCleanup: func(function func()) { cleanup = function },
		reportCleanup:   func(error) {},
		password:        "synthetic-password",
	}); err != nil {
		t.Fatalf("setup empty search list: %v", err)
	}
	recovery, err := readIsolatedKeychainRecovery(filepath.Join(directory, isolatedKeychainRecoveryFilename))
	if err != nil {
		t.Fatalf("read empty search recovery: %v", err)
	}
	if recovery.OriginalSearch == nil || len(recovery.OriginalSearch) != 0 {
		t.Fatalf("persisted search list = %#v, want explicit empty list", recovery.OriginalSearch)
	}
	cleanup()
	if eventIndex(fake.events, "list-keychains -d user -s") < 0 {
		t.Fatalf("empty search list was not restored explicitly; events=%q", fake.events)
	}
}

func TestIsolatedKeychainRecoveryRunsInFreshProcess(t *testing.T) {
	fake := newFakeSecurityCommand()
	fake.originalSearchOutput = new(string)
	recoveryRoot := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
	directory := filepath.Join(recoveryRoot, "state-fresh")
	keychain := filepath.Join(directory, "native-auth-gate.keychain-db")
	fake.keychainPath = keychain
	if err := configureIsolatedTestKeychain(isolatedKeychainSetup{
		recoveryRoot:    recoveryRoot,
		runSecurity:     fake.run,
		makeDirectory:   func() (string, error) { return directory, os.Mkdir(directory, 0o700) },
		removeDirectory: os.Remove,
		registerCleanup: func(func()) {},
		reportCleanup:   func(error) {},
		password:        "synthetic-password",
	}); err != nil {
		t.Fatal(err)
	}

	events := filepath.Join(t.TempDir(), "security.events")
	securityTool := filepath.Join(t.TempDir(), "security")
	if err := os.WriteFile(securityTool, []byte("#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >>\"$ACS_NATIVE_AUTH_SECURITY_EVENTS\"\nif [ \"$1\" = delete-keychain ]; then rm -f -- \"$2\"; fi\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestNativeKeychainRecoveryEntrypoint$", "-test.count=1")
	command.Env = append(os.Environ(),
		"ACS_RUN_NATIVE_AUTH_RECOVERY=1",
		"ACS_NATIVE_AUTH_RECOVERY_ROOT="+recoveryRoot,
		"ACS_NATIVE_AUTH_SECURITY_TOOL="+securityTool,
		"ACS_NATIVE_AUTH_SECURITY_EVENTS="+events,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fresh-process recovery: %v; output=%q", err, output)
	}
	if _, err := os.Lstat(recoveryRoot); !os.IsNotExist(err) {
		t.Fatalf("fresh-process recovery retained root: %v", err)
	}
	contents, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"list-keychains -d user -s",
		"default-keychain -d user -s /original/login.keychain-db",
		"delete-keychain " + keychain,
	} {
		if !strings.Contains(string(contents), want+"\n") {
			t.Errorf("fresh-process recovery events %q omit %q", contents, want)
		}
	}
}

func TestNativeKeychainRecoveryEntrypointRejectsSymlinkedIntermediateParentWithoutHostCalls(t *testing.T) {
	base := canonicalTestTemporaryDirectory(t)
	parent := filepath.Join(base, "parent")
	root := filepath.Join(parent, "recovery-root")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	prepareFreshRecoveryState(t, root, "state-parent-link")
	realParent := filepath.Join(base, "real-parent")
	if err := os.Rename(parent, realParent); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realParent, parent); err != nil {
		t.Fatal(err)
	}

	output, events, err := runNativeRecoveryEntrypoint(t, root)
	if err == nil {
		t.Fatalf("fresh recovery accepted a symlinked intermediate parent; output=%q", output)
	}
	if len(events) != 0 {
		t.Fatalf("unsafe fresh recovery called host security: %q", events)
	}
}

func TestNativeKeychainRecoveryEntrypointRejectsSymlinkedStateDirectoryWithoutHostCalls(t *testing.T) {
	base := canonicalTestTemporaryDirectory(t)
	root := filepath.Join(base, "recovery-root")
	directory := prepareFreshRecoveryState(t, root, "state-directory-link")
	realDirectory := filepath.Join(base, "real-state")
	if err := os.Rename(directory, realDirectory); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realDirectory, directory); err != nil {
		t.Fatal(err)
	}

	output, events, err := runNativeRecoveryEntrypoint(t, root)
	if err == nil {
		t.Fatalf("fresh recovery accepted a symlinked state directory; output=%q", output)
	}
	if len(events) != 0 {
		t.Fatalf("unsafe fresh recovery called host security: %q", events)
	}
}

func TestNativeKeychainRecoveryEntrypointSanitizesMalformedArtifactErrors(t *testing.T) {
	root := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
	directory := prepareFreshRecoveryState(t, root, "state-malformed")
	artifact := filepath.Join(directory, isolatedKeychainRecoveryFilename)
	privateDefault := "/Users/private-person/Library/Keychains/login.keychain-db"
	privateSearch := "/Volumes/private-search/custom.keychain-db"
	privateContents := "artifact-secret-marker"
	if err := os.Remove(artifact); err != nil {
		t.Fatal(err)
	}
	if err := persistIsolatedKeychainRecovery(artifact, isolatedKeychainRecovery{
		Version:         1,
		OriginalDefault: privateDefault,
		OriginalSearch:  []string{privateSearch},
		Directory:       directory,
		Keychain:        filepath.Join(directory, "native-auth-gate.keychain-db"),
		Guidance:        privateContents,
	}); err != nil {
		t.Fatal(err)
	}

	output, events, err := runNativeRecoveryEntrypoint(t, root)
	if err == nil {
		t.Fatal("fresh recovery accepted a malformed artifact")
	}
	if !strings.Contains(output, "isolated Keychain recovery artifact is invalid") {
		t.Fatalf("fresh recovery returned an unstable malformed-artifact error: %q", output)
	}
	for _, privateValue := range []string{privateDefault, privateSearch, privateContents, directory, artifact} {
		if strings.Contains(output, privateValue) {
			t.Fatalf("fresh recovery error leaked private recovery data %q: %q", privateValue, output)
		}
	}
	if len(events) != 0 {
		t.Fatalf("malformed fresh recovery called host security: %q", events)
	}
}

func prepareFreshRecoveryState(t *testing.T, root, stateName string) string {
	t.Helper()
	fake := newFakeSecurityCommand()
	directory := filepath.Join(root, stateName)
	fake.keychainPath = filepath.Join(directory, "native-auth-gate.keychain-db")
	if err := configureIsolatedTestKeychain(isolatedKeychainSetup{
		recoveryRoot:    root,
		runSecurity:     fake.run,
		makeDirectory:   func() (string, error) { return directory, os.Mkdir(directory, 0o700) },
		removeDirectory: os.Remove,
		registerCleanup: func(func()) {},
		reportCleanup:   func(error) {},
		password:        "synthetic-password",
	}); err != nil {
		t.Fatal(err)
	}
	return directory
}

func runNativeRecoveryEntrypoint(t *testing.T, root string) (string, []byte, error) {
	t.Helper()
	events := filepath.Join(t.TempDir(), "security.events")
	securityTool := filepath.Join(t.TempDir(), "security")
	if err := os.WriteFile(securityTool, []byte("#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >>\"$ACS_NATIVE_AUTH_SECURITY_EVENTS\"\nif [ \"$1\" = delete-keychain ]; then rm -f -- \"$2\"; fi\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestNativeKeychainRecoveryEntrypoint$", "-test.count=1")
	command.Env = append(os.Environ(),
		"ACS_RUN_NATIVE_AUTH_RECOVERY=1",
		"ACS_NATIVE_AUTH_RECOVERY_ROOT="+root,
		"ACS_NATIVE_AUTH_SECURITY_TOOL="+securityTool,
		"ACS_NATIVE_AUTH_SECURITY_EVENTS="+events,
	)
	output, err := command.CombinedOutput()
	eventContents, readErr := os.ReadFile(events)
	if readErr != nil && !os.IsNotExist(readErr) {
		t.Fatal(readErr)
	}
	return string(output), eventContents, err
}

func TestIsolatedKeychainRecoveryCompletesAfterDisposableKeychainWasDeleted(t *testing.T) {
	setupFake := newFakeSecurityCommand()
	root := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
	directory := filepath.Join(root, "state-deleted")
	keychain := filepath.Join(directory, "native-auth-gate.keychain-db")
	setupFake.keychainPath = keychain
	if err := configureIsolatedTestKeychain(isolatedKeychainSetup{
		recoveryRoot:    root,
		runSecurity:     setupFake.run,
		makeDirectory:   func() (string, error) { return directory, os.Mkdir(directory, 0o700) },
		removeDirectory: os.Remove,
		registerCleanup: func(func()) {},
		reportCleanup:   func(error) {},
		password:        "synthetic-password",
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keychain); err != nil {
		t.Fatal(err)
	}

	recoveryFake := newFakeSecurityCommand()
	if err := recoverIsolatedTestKeychainFromRoot(root, recoveryFake.run, os.Remove); err != nil {
		t.Fatalf("recover after disposable Keychain deletion: %v", err)
	}
	if eventIndex(recoveryFake.events, "list-keychains -d user -s /original/login.keychain-db /original/system.keychain") < 0 ||
		eventIndex(recoveryFake.events, "default-keychain -d user -s /original/login.keychain-db") < 0 {
		t.Fatalf("recovery did not restore both host settings: %q", recoveryFake.events)
	}
	if eventIndex(recoveryFake.events, "delete-keychain "+keychain) >= 0 {
		t.Fatalf("recovery tried to delete an already absent Keychain: %q", recoveryFake.events)
	}
}

func TestNativeKeychainRecoveryEntrypoint(t *testing.T) {
	if os.Getenv("ACS_RUN_NATIVE_AUTH_RECOVERY") != "1" {
		t.Skip("fresh-process native Keychain recovery entrypoint")
	}
	recoveryRoot := os.Getenv("ACS_NATIVE_AUTH_RECOVERY_ROOT")
	if recoveryRoot == "" {
		t.Fatal("ACS_NATIVE_AUTH_RECOVERY_ROOT is required")
	}
	securityTool := os.Getenv("ACS_NATIVE_AUTH_SECURITY_TOOL")
	if securityTool == "" {
		securityTool = "/usr/bin/security"
	}
	runSecurity := func(arguments ...string) (string, error) {
		output, err := exec.Command(securityTool, arguments...).CombinedOutput()
		return string(output), err
	}
	if err := recoverIsolatedTestKeychainFromRoot(recoveryRoot, runSecurity, os.Remove); err != nil {
		t.Fatal(err)
	}
}

func TestIsolatedKeychainRecoveryRejectsUnsafeLocatorWithoutHostMutation(t *testing.T) {
	for name, prepare := range map[string]func(*testing.T, string){
		"symlink": func(t *testing.T, locator string) {
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, locator); err != nil {
				t.Fatal(err)
			}
		},
		"hard link": func(t *testing.T, locator string) {
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(target, locator); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			locator := filepath.Join(root, isolatedKeychainLocatorFilename)
			prepare(t, locator)
			fake := newFakeSecurityCommand()
			err := recoverIsolatedTestKeychainFromRoot(root, fake.run, os.Remove)
			if err == nil || err.Error() != "isolated Keychain recovery locator is invalid" {
				t.Fatalf("unsafe locator recovery = %v", err)
			}
			if len(fake.events) != 0 {
				t.Fatalf("unsafe locator mutated host state: %q", fake.events)
			}
		})
	}
}

func TestIsolatedKeychainRecoveryRejectsLinkedArtifactWithoutHostMutation(t *testing.T) {
	for name, link := range map[string]func(string, string) error{
		"symlink":   os.Symlink,
		"hard link": os.Link,
	} {
		t.Run(name, func(t *testing.T) {
			setupFake := newFakeSecurityCommand()
			root := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
			directory := filepath.Join(root, "state-linked")
			keychain := filepath.Join(directory, "native-auth-gate.keychain-db")
			setupFake.keychainPath = keychain
			if err := configureIsolatedTestKeychain(isolatedKeychainSetup{
				recoveryRoot:    root,
				runSecurity:     setupFake.run,
				makeDirectory:   func() (string, error) { return directory, os.Mkdir(directory, 0o700) },
				removeDirectory: os.Remove,
				registerCleanup: func(func()) {},
				reportCleanup:   func(error) {},
				password:        "synthetic-password",
			}); err != nil {
				t.Fatal(err)
			}
			artifact := filepath.Join(directory, isolatedKeychainRecoveryFilename)
			contents, err := os.ReadFile(artifact)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(artifact); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "artifact")
			if err := os.WriteFile(target, contents, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := link(target, artifact); err != nil {
				t.Fatal(err)
			}

			recoveryFake := newFakeSecurityCommand()
			if err := recoverIsolatedTestKeychainFromRoot(root, recoveryFake.run, os.Remove); err == nil {
				t.Fatal("linked recovery artifact was accepted")
			}
			if len(recoveryFake.events) != 0 {
				t.Fatalf("linked recovery artifact mutated host state: %q", recoveryFake.events)
			}
		})
	}
}

func TestIsolatedKeychainSetupFailsClosedOnStaleOrUnsafeRecoveryRoot(t *testing.T) {
	for name, prepare := range map[string]func(*testing.T, string){
		"stale state": func(t *testing.T, root string) {
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "stale"), []byte("retained\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"symlink root": func(t *testing.T, root string) {
			target := filepath.Join(t.TempDir(), "target")
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, root); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
			prepare(t, root)
			fake := newFakeSecurityCommand()
			madeDirectory := false
			var cleanup func()
			err := configureIsolatedTestKeychain(isolatedKeychainSetup{
				recoveryRoot: root,
				runSecurity:  fake.run,
				makeDirectory: func() (string, error) {
					madeDirectory = true
					return "", errors.New("must not create state")
				},
				removeDirectory: os.Remove,
				registerCleanup: func(function func()) { cleanup = function },
				reportCleanup:   func(error) {},
				password:        "synthetic-password",
			})
			if err == nil || !strings.Contains(err.Error(), root) {
				t.Fatalf("unsafe recovery root setup = %v", err)
			}
			if madeDirectory {
				t.Fatal("unsafe recovery root created disposable state")
			}
			cleanup()
			for _, event := range fake.events {
				if strings.Contains(event, " -s ") || strings.HasPrefix(event, "create-keychain") || strings.HasPrefix(event, "delete-keychain") {
					t.Fatalf("unsafe recovery root mutated host state: %q", fake.events)
				}
			}
		})
	}
}

func TestPrivateRecoveryMetadataRejectsForeignOwnership(t *testing.T) {
	err := validatePrivateRecoveryMetadata(privateRecoveryMetadata{
		regular: true,
		mode:    0o600,
		owner:   uint32(os.Geteuid() + 1),
		links:   1,
	}, false, uint32(os.Geteuid()))
	if err == nil {
		t.Fatal("foreign-owned recovery file was accepted")
	}
}

type fakeSecurityCommand struct {
	events               []string
	failures             map[string]error
	failuresAfter        map[string]error
	keychainPath         string
	originalSearchOutput *string
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
		if fake.originalSearchOutput != nil {
			output = *fake.originalSearchOutput
		} else {
			output = "    \"/original/login.keychain-db\"\n    \"/original/system.keychain\"\n"
		}
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

func canonicalTestTemporaryDirectory(t *testing.T) string {
	t.Helper()
	directory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func useIsolatedTestKeychain(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/security"); err != nil {
		t.Fatal("system Keychain tool is unavailable")
	}
	password := fmt.Sprintf("synthetic-%d-%d", os.Getpid(), time.Now().UnixNano())
	recoveryRoot := os.Getenv("ACS_NATIVE_AUTH_RECOVERY_ROOT")
	if recoveryRoot == "" {
		temporaryBase, err := filepath.EvalSymlinks(os.TempDir())
		if err != nil {
			t.Fatalf("canonicalize temporary recovery base: %v", err)
		}
		recoveryRoot = filepath.Join(temporaryBase, fmt.Sprintf("acs-native-auth-recovery-%d", os.Geteuid()))
	}
	if err := configureIsolatedTestKeychain(isolatedKeychainSetup{
		recoveryRoot: recoveryRoot,
		runSecurity: func(arguments ...string) (string, error) {
			output, err := exec.Command("/usr/bin/security", arguments...).CombinedOutput()
			return string(output), err
		},
		makeDirectory: func() (string, error) {
			return os.MkdirTemp(recoveryRoot, "state-")
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
	recoveryRoot    string
	runSecurity     func(...string) (string, error)
	makeDirectory   func() (string, error)
	removeDirectory func(string) error
	persistRecovery func(string, isolatedKeychainRecovery) error
	registerCleanup func(func())
	reportCleanup   func(error)
	password        string
}

type isolatedKeychainState struct {
	setup               isolatedKeychainSetup
	originalDefault     string
	originalSearch      []string
	directory           string
	keychain            string
	recoveryPath        string
	recoveryRoot        string
	locatorPath         string
	keychainMayExist    bool
	cleanupArmed        bool
	hostMutationStarted bool
}

const (
	isolatedKeychainRecoveryFilename = "native-auth-gate.recovery.json"
	isolatedKeychainLocatorFilename  = "active-recovery.json"
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

type isolatedKeychainRecoveryLocator struct {
	Version      int    `json:"version"`
	RecoveryPath string `json:"recoveryPath"`
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

	if setup.recoveryRoot == "" {
		return errors.New("isolated Keychain recovery root is unavailable")
	}
	state.recoveryRoot, err = prepareIsolatedKeychainRecoveryRoot(setup.recoveryRoot)
	if err != nil {
		return fmt.Errorf("prepare isolated Keychain recovery root %s: %w", setup.recoveryRoot, err)
	}
	state.locatorPath = filepath.Join(state.recoveryRoot, isolatedKeychainLocatorFilename)
	entries, err := os.ReadDir(state.recoveryRoot)
	if err != nil || len(entries) != 0 {
		return fmt.Errorf("stale or unsafe isolated Keychain recovery state at %s", state.locatorPath)
	}
	state.cleanupArmed = true
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
		OriginalSearch:  append([]string{}, state.originalSearch...),
		Directory:       state.directory,
		Keychain:        state.keychain,
		Guidance:        isolatedKeychainRecoveryGuidance,
	}); err != nil {
		return errors.New("persist isolated Keychain recovery state")
	}
	if err := persistIsolatedKeychainRecoveryLocator(state.locatorPath, isolatedKeychainRecoveryLocator{
		Version:      1,
		RecoveryPath: state.recoveryPath,
	}); err != nil {
		return errors.New("persist isolated Keychain recovery locator")
	}
	locator, err := readIsolatedKeychainRecoveryLocator(state.recoveryRoot)
	if err != nil || locator.RecoveryPath != state.recoveryPath {
		return errors.New("validate isolated Keychain recovery locator")
	}
	if _, err := readIsolatedKeychainRecovery(state.recoveryPath); err != nil {
		return errors.New("validate isolated Keychain recovery state")
	}
	state.keychainMayExist = true
	state.hostMutationStarted = true
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
	if !state.cleanupArmed {
		return nil
	}
	if state.hostMutationStarted {
		searchArguments := []string{"list-keychains", "-d", "user", "-s"}
		searchArguments = append(searchArguments, state.originalSearch...)
		_, searchErr := state.setup.runSecurity(searchArguments...)
		_, defaultErr := state.setup.runSecurity("default-keychain", "-d", "user", "-s", state.originalDefault)
		if searchErr != nil || defaultErr != nil {
			return fmt.Errorf("recovery state retained at %s: %w", state.locatorPath, errors.Join(
				cleanupError("restore Keychain search list", searchErr),
				cleanupError("restore default Keychain", defaultErr),
			))
		}
	}
	if state.keychainMayExist {
		if err := validatePrivateRecoveryPath(state.keychain, false); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("recovery state retained at %s: disposable Keychain is unsafe", state.locatorPath)
		} else if err == nil {
			if _, err := state.setup.runSecurity("delete-keychain", state.keychain); err != nil {
				return fmt.Errorf("recovery state retained at %s: delete isolated Keychain after restoration", state.locatorPath)
			}
		}
	}
	if state.directory != "" {
		if state.recoveryPath != "" {
			if err := os.Remove(state.recoveryPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("recovery state retained at %s: delete isolated Keychain recovery artifact: %w", state.locatorPath, err)
			}
		}
		if err := state.setup.removeDirectory(state.directory); err != nil {
			return fmt.Errorf("recovery state retained at %s: delete isolated Keychain directory after restoration", state.locatorPath)
		}
	}
	if state.locatorPath != "" {
		if err := os.Remove(state.locatorPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("delete isolated Keychain recovery locator %s: %w", state.locatorPath, err)
		}
	}
	if state.recoveryRoot != "" {
		if err := os.Remove(state.recoveryRoot); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("delete isolated Keychain recovery root %s: %w", state.recoveryRoot, err)
		}
	}
	return nil
}

func persistIsolatedKeychainRecovery(path string, recovery isolatedKeychainRecovery) error {
	contents, err := json.Marshal(recovery)
	if err != nil {
		return err
	}
	return persistPrivateRecoveryFile(path, append(contents, '\n'))
}

func persistIsolatedKeychainRecoveryLocator(path string, locator isolatedKeychainRecoveryLocator) error {
	contents, err := json.Marshal(locator)
	if err != nil {
		return err
	}
	return persistPrivateRecoveryFile(path, append(contents, '\n'))
}

func persistPrivateRecoveryFile(path string, contents []byte) (resultErr error) {
	parent, err := openPrivateRecoveryDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	temporary := filepath.Base(path) + ".tmp"
	descriptor, err := unix.Openat(int(parent.Fd()), temporary, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(descriptor), "private recovery temporary")
	if file == nil {
		_ = unix.Close(descriptor)
		return errors.New("open private recovery file")
	}
	defer func() {
		_ = file.Close()
		if resultErr != nil {
			_ = unix.Unlinkat(int(parent.Fd()), temporary, 0)
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
	if err := unix.Renameat(int(parent.Fd()), temporary, int(parent.Fd()), filepath.Base(path)); err != nil {
		return err
	}
	return parent.Sync()
}

func readIsolatedKeychainRecovery(path string) (isolatedKeychainRecovery, error) {
	contents, err := readPrivateRecoveryFile(path)
	if err != nil {
		return isolatedKeychainRecovery{}, err
	}
	return decodeIsolatedKeychainRecovery(contents, path)
}

func decodeIsolatedKeychainRecovery(contents []byte, path string) (isolatedKeychainRecovery, error) {
	var recovery isolatedKeychainRecovery
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&recovery); err != nil {
		return isolatedKeychainRecovery{}, errors.New("recovery artifact is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return isolatedKeychainRecovery{}, errors.New("recovery artifact has trailing data")
	}
	if recovery.Version != 1 || recovery.OriginalDefault == "" || recovery.OriginalSearch == nil ||
		recovery.Directory == "" || recovery.Keychain != filepath.Join(recovery.Directory, "native-auth-gate.keychain-db") ||
		path != filepath.Join(recovery.Directory, isolatedKeychainRecoveryFilename) || recovery.Guidance != isolatedKeychainRecoveryGuidance {
		return isolatedKeychainRecovery{}, errors.New("recovery artifact is invalid")
	}
	return recovery, nil
}

func readIsolatedKeychainRecoveryLocator(root string) (isolatedKeychainRecoveryLocator, error) {
	canonicalRoot, err := canonicalIsolatedKeychainRecoveryRoot(root)
	if err != nil {
		return isolatedKeychainRecoveryLocator{}, err
	}
	if err := validatePrivateRecoveryPath(canonicalRoot, true); err != nil {
		return isolatedKeychainRecoveryLocator{}, err
	}
	contents, err := readPrivateRecoveryFile(filepath.Join(canonicalRoot, isolatedKeychainLocatorFilename))
	if err != nil {
		return isolatedKeychainRecoveryLocator{}, err
	}
	locator, err := decodeIsolatedKeychainRecoveryLocator(contents, canonicalRoot)
	if err != nil {
		return isolatedKeychainRecoveryLocator{}, err
	}
	if err := validatePrivateRecoveryPath(filepath.Dir(locator.RecoveryPath), true); err != nil {
		return isolatedKeychainRecoveryLocator{}, err
	}
	return locator, nil
}

func decodeIsolatedKeychainRecoveryLocator(contents []byte, canonicalRoot string) (isolatedKeychainRecoveryLocator, error) {
	var locator isolatedKeychainRecoveryLocator
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&locator); err != nil {
		return isolatedKeychainRecoveryLocator{}, errors.New("recovery locator is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return isolatedKeychainRecoveryLocator{}, errors.New("recovery locator has trailing data")
	}
	directory := filepath.Dir(locator.RecoveryPath)
	if locator.Version != 1 || filepath.Dir(directory) != canonicalRoot ||
		!strings.HasPrefix(filepath.Base(directory), "state-") ||
		filepath.Base(locator.RecoveryPath) != isolatedKeychainRecoveryFilename {
		return isolatedKeychainRecoveryLocator{}, errors.New("recovery locator is invalid")
	}
	return locator, nil
}

func readPrivateRecoveryFile(path string) ([]byte, error) {
	parent, err := openRecoveryDirectoryNoFollow(filepath.Dir(path), false)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return readPrivateRecoveryFileAt(parent, filepath.Base(path))
}

func readPrivateRecoveryFileAt(parent *os.File, name string) ([]byte, error) {
	file, err := openPrivateRecoveryFileAt(parent, name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, 64*1024))
}

func openPrivateRecoveryFileAt(parent *os.File, name string) (*os.File, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, errors.New("recovery path is unsafe")
	}
	descriptor, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), "private recovery file")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("open private recovery file")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := validatePrivateRecoveryInfo(info, false); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func prepareIsolatedKeychainRecoveryRoot(root string) (string, error) {
	canonicalRoot, err := canonicalIsolatedKeychainRecoveryRoot(root)
	if err != nil {
		return "", err
	}
	parent, err := openRecoveryDirectoryNoFollow(filepath.Dir(canonicalRoot), false)
	if err != nil {
		return "", err
	}
	defer parent.Close()
	if err := unix.Mkdirat(int(parent.Fd()), filepath.Base(canonicalRoot), 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return "", err
	}
	rootDirectory, err := openPrivateRecoveryDirectoryAt(parent, filepath.Base(canonicalRoot))
	if err != nil {
		return "", err
	}
	_ = rootDirectory.Close()
	return canonicalRoot, nil
}

func canonicalIsolatedKeychainRecoveryRoot(root string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", errors.New("recovery root is not an absolute clean path")
	}
	return root, nil
}

func validatePrivateRecoveryPath(path string, directory bool) error {
	parent, err := openRecoveryDirectoryNoFollow(filepath.Dir(path), false)
	if err != nil {
		return err
	}
	defer parent.Close()
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if directory {
		flags |= unix.O_DIRECTORY
	}
	descriptor, err := unix.Openat(int(parent.Fd()), filepath.Base(path), flags, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(descriptor), "private recovery path")
	if file == nil {
		_ = unix.Close(descriptor)
		return errors.New("open private recovery path")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	return validatePrivateRecoveryInfo(info, directory)
}

func openPrivateRecoveryDirectory(path string) (*os.File, error) {
	return openRecoveryDirectoryNoFollow(path, true)
}

func openRecoveryDirectoryNoFollow(path string, private bool) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("recovery path is unsafe")
	}
	current, err := os.Open("/")
	if err != nil {
		return nil, err
	}
	for _, component := range strings.Split(strings.TrimPrefix(path, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		descriptor, openErr := unix.Openat(int(current.Fd()), component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = current.Close()
		if openErr != nil {
			return nil, openErr
		}
		current = os.NewFile(uintptr(descriptor), "recovery directory")
		if current == nil {
			_ = unix.Close(descriptor)
			return nil, errors.New("open recovery directory")
		}
	}
	if private {
		info, statErr := current.Stat()
		if statErr != nil {
			_ = current.Close()
			return nil, statErr
		}
		if validationErr := validatePrivateRecoveryInfo(info, true); validationErr != nil {
			_ = current.Close()
			return nil, validationErr
		}
	}
	return current, nil
}

func openPrivateRecoveryDirectoryAt(parent *os.File, name string) (*os.File, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, errors.New("recovery path is unsafe")
	}
	descriptor, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(descriptor), "private recovery directory")
	if directory == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("open private recovery directory")
	}
	info, err := directory.Stat()
	if err != nil {
		_ = directory.Close()
		return nil, err
	}
	if err := validatePrivateRecoveryInfo(info, true); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return directory, nil
}

type privateRecoveryMetadata struct {
	directory bool
	regular   bool
	mode      os.FileMode
	owner     uint32
	links     uint64
}

func validatePrivateRecoveryInfo(info os.FileInfo, directory bool) error {
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("recovery metadata is unavailable")
	}
	return validatePrivateRecoveryMetadata(privateRecoveryMetadata{
		directory: info.IsDir(),
		regular:   info.Mode().IsRegular(),
		mode:      info.Mode(),
		owner:     native.Uid,
		links:     uint64(native.Nlink),
	}, directory, uint32(os.Geteuid()))
}

func validatePrivateRecoveryMetadata(metadata privateRecoveryMetadata, directory bool, effectiveUID uint32) error {
	validType := metadata.regular && metadata.links == 1
	mode := os.FileMode(0o600)
	if directory {
		validType = metadata.directory && metadata.links >= 2
		mode = 0o700
	}
	if !validType || metadata.mode.Perm() != mode || metadata.owner != effectiveUID {
		return errors.New("recovery path is unsafe")
	}
	return nil
}

func recoverIsolatedTestKeychain(
	recoveryPath string,
	runSecurity func(...string) (string, error),
	removeDirectory func(string) error,
) error {
	recovery, err := readIsolatedKeychainRecovery(recoveryPath)
	if err != nil {
		return errors.New("isolated Keychain recovery artifact is invalid")
	}
	state := isolatedKeychainState{
		setup: isolatedKeychainSetup{
			runSecurity:     runSecurity,
			removeDirectory: removeDirectory,
		},
		originalDefault:     recovery.OriginalDefault,
		originalSearch:      recovery.OriginalSearch,
		directory:           recovery.Directory,
		keychain:            recovery.Keychain,
		recoveryPath:        recoveryPath,
		keychainMayExist:    true,
		cleanupArmed:        true,
		hostMutationStarted: true,
	}
	return state.cleanup()
}

func recoverIsolatedTestKeychainFromRoot(
	recoveryRoot string,
	runSecurity func(...string) (string, error),
	removeDirectory func(string) error,
) error {
	canonicalRoot, err := canonicalIsolatedKeychainRecoveryRoot(recoveryRoot)
	if err != nil {
		return errors.New("isolated Keychain recovery root is unsafe")
	}
	rootDirectory, err := openPrivateRecoveryDirectory(canonicalRoot)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return errors.New("isolated Keychain recovery root is unsafe")
	}
	defer rootDirectory.Close()
	locatorContents, err := readPrivateRecoveryFileAt(rootDirectory, isolatedKeychainLocatorFilename)
	if err != nil {
		return errors.New("isolated Keychain recovery locator is invalid")
	}
	locator, err := decodeIsolatedKeychainRecoveryLocator(locatorContents, canonicalRoot)
	if err != nil {
		return errors.New("isolated Keychain recovery locator is invalid")
	}
	stateName := filepath.Base(filepath.Dir(locator.RecoveryPath))
	stateDirectory, err := openPrivateRecoveryDirectoryAt(rootDirectory, stateName)
	if err != nil {
		return errors.New("isolated Keychain recovery artifact is invalid")
	}
	defer stateDirectory.Close()
	artifactContents, err := readPrivateRecoveryFileAt(stateDirectory, isolatedKeychainRecoveryFilename)
	if err != nil {
		return errors.New("isolated Keychain recovery artifact is invalid")
	}
	recovery, err := decodeIsolatedKeychainRecovery(artifactContents, locator.RecoveryPath)
	if err != nil {
		return errors.New("isolated Keychain recovery artifact is invalid")
	}
	keychainMayExist := true
	keychainFile, err := openPrivateRecoveryFileAt(stateDirectory, filepath.Base(recovery.Keychain))
	if errors.Is(err, unix.ENOENT) {
		keychainMayExist = false
	} else if err != nil {
		return errors.New("isolated Keychain recovery artifact is invalid")
	} else {
		defer keychainFile.Close()
	}
	state := isolatedKeychainState{
		setup: isolatedKeychainSetup{
			runSecurity:     runSecurity,
			removeDirectory: removeDirectory,
		},
		originalDefault:     recovery.OriginalDefault,
		originalSearch:      recovery.OriginalSearch,
		directory:           recovery.Directory,
		keychain:            recovery.Keychain,
		recoveryPath:        locator.RecoveryPath,
		recoveryRoot:        canonicalRoot,
		locatorPath:         filepath.Join(canonicalRoot, isolatedKeychainLocatorFilename),
		keychainMayExist:    keychainMayExist,
		cleanupArmed:        true,
		hostMutationStarted: true,
	}
	if err := state.cleanup(); err != nil {
		return fmt.Errorf("recovery state retained at %s: recovery did not complete", state.locatorPath)
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
	paths := make([]string, 0)
	for _, line := range strings.Split(output, "\n") {
		path := strings.Trim(line, "\" \t\r")
		if path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}
