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
			err := configureIsolatedTestKeychain(isolatedKeychainSetup{
				recoveryRoot: recoveryRoot,
				runSecurity:  fake.run,
				chooseDirectory: func() (string, error) {
					fake.events = append(fake.events, "mkdir")
					return directory, nil
				},
				recordRecoveryPersisted: func() {
					fake.events = append(fake.events, "persist recovery")
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
				Version:         2,
				OriginalDefault: "/original/login.keychain-db",
				OriginalSearch:  []string{"/original/login.keychain-db", "/original/system.keychain"},
				Guidance:        isolatedKeychainRecoveryGuidance,
			}
			if !reflect.DeepEqual(recovery, wantRecovery) {
				t.Fatalf("recovery artifact = %#v, want %#v", recovery, wantRecovery)
			}
			locatorContents, locatorErr := os.ReadFile(filepath.Join(recoveryRoot, isolatedKeychainLocatorFilename))
			if locatorErr != nil {
				t.Fatalf("read recovery locator: %v", locatorErr)
			}
			locator, locatorErr := decodeIsolatedKeychainRecoveryLocator(locatorContents)
			wantLocator := isolatedKeychainRecoveryLocator{
				Version: 2, StateDirectory: filepath.Base(directory), Phase: isolatedKeychainPhaseRecovery,
			}
			if locatorErr != nil || !reflect.DeepEqual(locator, wantLocator) {
				t.Fatalf("recovery locator = (%#v, %v), want %#v", locator, locatorErr, wantLocator)
			}
			if strings.Contains(string(locatorContents), recoveryRoot) || strings.Contains(string(locatorContents), keychain) {
				t.Fatalf("recovery locator contains an absolute private path: %q", locatorContents)
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
			if eventIndex(fake.events, searchRestore) < 0 || eventIndex(fake.events, defaultRestore) < 0 {
				t.Fatalf("successful cleanup omitted host restoration: %q", fake.events)
			}
			if eventIndex(fake.events, "delete-keychain "+keychain) >= 0 {
				t.Fatalf("successful cleanup deleted the disposable Keychain by pathname: %q", fake.events)
			}
			if _, statErr := os.Lstat(directory); !os.IsNotExist(statErr) {
				t.Fatalf("successful restoration retained disposable directory: %v", statErr)
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
			err := configureIsolatedTestKeychain(isolatedKeychainSetup{
				recoveryRoot:    recoveryRoot,
				runSecurity:     fake.run,
				chooseDirectory: func() (string, error) { return directory, nil },
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
		chooseDirectory: func() (string, error) { return directory, nil },
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
	if err := recoverIsolatedTestKeychain(recoveryPath, fake.run); err != nil {
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
		Version:         2,
		OriginalDefault: "/original/login.keychain-db",
		OriginalSearch:  []string{},
		Guidance:        isolatedKeychainRecoveryGuidance,
	}); err != nil {
		t.Fatal(err)
	}

	if err := recoverIsolatedTestKeychain(recoveryPath, fake.run); err != nil {
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
		chooseDirectory: func() (string, error) { return directory, nil },
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
		chooseDirectory: func() (string, error) { return directory, nil },
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
	} {
		if !strings.Contains(string(contents), want+"\n") {
			t.Errorf("fresh-process recovery events %q omit %q", contents, want)
		}
	}
	if strings.Contains(string(contents), "delete-keychain ") {
		t.Fatalf("fresh-process recovery deleted the disposable Keychain by pathname: %q", contents)
	}
}

func TestNativeKeychainRecoveryEntrypointResumesAfterCreateBeforeModeNormalization(t *testing.T) {
	recoveryRoot := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
	directory := filepath.Join(recoveryRoot, "state-native-create-crash")
	keychain := filepath.Join(directory, isolatedKeychainFilename)
	setupFake := newFakeSecurityCommand()
	setupFake.keychainPath = keychain
	setupFake.keychainMode = 0o644
	crash := errors.New("simulate process crash after create-keychain")
	setupFake.afterCreate = func(string) error { return crash }
	if err := configureIsolatedTestKeychain(isolatedKeychainSetup{
		recoveryRoot:    recoveryRoot,
		runSecurity:     setupFake.run,
		chooseDirectory: func() (string, error) { return directory, nil },
		registerCleanup: func(func()) {},
		reportCleanup:   func(error) {},
		password:        "synthetic-password",
	}); err == nil {
		t.Fatal("setup succeeded despite injected post-create crash")
	}
	info, err := os.Stat(keychain)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("crash-point disposable Keychain mode = %#o, want actual system-created 0644", got)
	}

	output, events, err := runNativeRecoveryEntrypoint(t, recoveryRoot)
	if err != nil {
		t.Fatalf("fresh-process recovery from pre-normalization crash: %v; output=%q", err, output)
	}
	if _, err := os.Lstat(recoveryRoot); !os.IsNotExist(err) {
		t.Fatalf("fresh-process recovery retained root: %v", err)
	}
	for _, want := range []string{
		"list-keychains -d user -s /original/login.keychain-db /original/system.keychain",
		"default-keychain -d user -s /original/login.keychain-db",
	} {
		if !strings.Contains(string(events), want+"\n") {
			t.Errorf("fresh-process recovery events %q omit %q", events, want)
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
		Version:         2,
		OriginalDefault: privateDefault,
		OriginalSearch:  []string{privateSearch},
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

func TestIsolatedKeychainRecoveryResumesEveryCleanupCrashPoint(t *testing.T) {
	for _, crashPoint := range []string{"phase updated", "artifact removed", "state directory removed", "locator removed"} {
		t.Run(crashPoint, func(t *testing.T) {
			root := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
			directory := prepareFreshRecoveryState(t, root, "state-crash")
			fake := newFakeSecurityCommand()
			stopAfterPhase := errors.New("stop after durable phase update")
			err := recoverIsolatedTestKeychainFromRootWithHooks(root, fake.run, isolatedKeychainRecoveryHooks{
				afterPhaseUpdate: func() error {
					if _, statErr := os.Lstat(filepath.Join(directory, isolatedKeychainFilename)); !os.IsNotExist(statErr) {
						t.Fatalf("cleanup-only phase retained disposable Keychain: %v", statErr)
					}
					return stopAfterPhase
				},
			})
			if !errors.Is(err, stopAfterPhase) {
				t.Fatalf("first recovery error = %v, want phase-update interruption", err)
			}
			if eventIndex(fake.events, "list-keychains -d user -s /original/login.keychain-db /original/system.keychain") < 0 ||
				eventIndex(fake.events, "default-keychain -d user -s /original/login.keychain-db") < 0 {
				t.Fatalf("recovery-required phase omitted host restoration: %q", fake.events)
			}

			switch crashPoint {
			case "artifact removed":
				if err := os.Remove(filepath.Join(directory, isolatedKeychainRecoveryFilename)); err != nil {
					t.Fatal(err)
				}
			case "state directory removed":
				if err := os.Remove(filepath.Join(directory, isolatedKeychainRecoveryFilename)); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(directory); err != nil {
					t.Fatal(err)
				}
			case "locator removed":
				if err := os.Remove(filepath.Join(directory, isolatedKeychainRecoveryFilename)); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(directory); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(root, isolatedKeychainLocatorFilename)); err != nil {
					t.Fatal(err)
				}
			}

			fake.events = nil
			if err := recoverIsolatedTestKeychainFromRoot(root, fake.run); err != nil {
				t.Fatalf("resume after %s: %v", crashPoint, err)
			}
			if len(fake.events) != 0 {
				t.Fatalf("cleanup-only recovery repeated host calls: %q", fake.events)
			}
			if _, err := os.Lstat(root); !os.IsNotExist(err) {
				t.Fatalf("recovery retained root after %s: %v", crashPoint, err)
			}
		})
	}
}

func TestIsolatedKeychainRecoveryAncestorSwapCannotRedirectCleanup(t *testing.T) {
	base := canonicalTestTemporaryDirectory(t)
	ancestor := filepath.Join(base, "ancestor")
	root := filepath.Join(ancestor, "recovery-root")
	if err := os.Mkdir(ancestor, 0o700); err != nil {
		t.Fatal(err)
	}
	prepareFreshRecoveryState(t, root, "state-original")
	replacementSentinel := filepath.Join(root, "replacement-sentinel")
	oldAncestor := filepath.Join(base, "ancestor-opened")

	fake := newFakeSecurityCommand()
	err := recoverIsolatedTestKeychainFromRootWithHooks(root, fake.run, isolatedKeychainRecoveryHooks{
		afterDescriptorsOpened: func() error {
			if err := os.Rename(ancestor, oldAncestor); err != nil {
				return err
			}
			if err := os.MkdirAll(root, 0o700); err != nil {
				return err
			}
			return os.WriteFile(replacementSentinel, []byte("do not delete"), 0o600)
		},
	})
	if err != nil {
		t.Fatalf("descriptor-relative recovery after ancestor swap: %v", err)
	}
	if contents, err := os.ReadFile(replacementSentinel); err != nil || string(contents) != "do not delete" {
		t.Fatalf("replacement tree was modified: contents=%q err=%v", contents, err)
	}
	if _, err := os.Lstat(filepath.Join(oldAncestor, "recovery-root")); !os.IsNotExist(err) {
		t.Fatalf("opened recovery tree was not removed: %v", err)
	}
}

func TestNativeKeychainRecoveryEntrypointSanitizesCleanupErrors(t *testing.T) {
	root := filepath.Join(canonicalTestTemporaryDirectory(t), "private-recovery-root")
	directory := prepareFreshRecoveryState(t, root, "state-private")
	privateContents := "private-artifact-marker"
	if err := os.WriteFile(filepath.Join(directory, "unexpected-private-file"), []byte(privateContents), 0o600); err != nil {
		t.Fatal(err)
	}

	output, _, err := runNativeRecoveryEntrypoint(t, root)
	if err == nil {
		t.Fatal("fresh recovery unexpectedly removed a non-empty state directory")
	}
	if !strings.Contains(output, "isolated Keychain recovery did not complete") {
		t.Fatalf("fresh recovery returned an unstable cleanup error: %q", output)
	}
	for _, privateValue := range []string{root, directory, privateContents, isolatedKeychainRecoveryFilename} {
		if strings.Contains(output, privateValue) {
			t.Fatalf("fresh recovery error leaked private value %q: %q", privateValue, output)
		}
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
		chooseDirectory: func() (string, error) { return directory, nil },
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
		chooseDirectory: func() (string, error) { return directory, nil },
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
	if err := recoverIsolatedTestKeychainFromRoot(root, recoveryFake.run); err != nil {
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
	if err := recoverIsolatedTestKeychainFromRoot(recoveryRoot, runSecurity); err != nil {
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
			err := recoverIsolatedTestKeychainFromRoot(root, fake.run)
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
				chooseDirectory: func() (string, error) { return directory, nil },
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
			if err := recoverIsolatedTestKeychainFromRoot(root, recoveryFake.run); err == nil {
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
				chooseDirectory: func() (string, error) {
					madeDirectory = true
					return "", errors.New("must not create state")
				},
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

func TestIsolatedKeychainSetupNormalizesSecurityCreatedFileMode(t *testing.T) {
	recoveryRoot := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
	directory := filepath.Join(recoveryRoot, "state-native-mode")
	keychain := filepath.Join(directory, isolatedKeychainFilename)
	fake := newFakeSecurityCommand()
	fake.keychainPath = keychain
	fake.keychainMode = 0o644
	var cleanup func()
	var cleanupErrors []error

	err := configureIsolatedTestKeychain(isolatedKeychainSetup{
		recoveryRoot:    recoveryRoot,
		runSecurity:     fake.run,
		chooseDirectory: func() (string, error) { return directory, nil },
		registerCleanup: func(function func()) { cleanup = function },
		reportCleanup:   func(err error) { cleanupErrors = append(cleanupErrors, err) },
		password:        "synthetic-password",
	})
	if err != nil {
		t.Fatalf("configure isolated Keychain with native file mode: %v", err)
	}
	info, err := os.Stat(keychain)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("normalized disposable Keychain mode = %#o, want 0600", got)
	}
	if !reflect.DeepEqual(fake.keychainUseModes, []os.FileMode{0o600}) {
		t.Fatalf("disposable Keychain modes at first host use = %#o, want [0600]", fake.keychainUseModes)
	}

	cleanup()
	if len(cleanupErrors) != 0 {
		t.Fatalf("cleanup after native file mode: %v", cleanupErrors)
	}
	if _, err := os.Lstat(recoveryRoot); !os.IsNotExist(err) {
		t.Fatalf("cleanup retained recovery root: %v", err)
	}
	for _, want := range []string{
		"list-keychains -d user -s /original/login.keychain-db /original/system.keychain",
		"default-keychain -d user -s /original/login.keychain-db",
	} {
		if eventIndex(fake.events, want) < 0 {
			t.Fatalf("cleanup omitted host restoration %q; events=%q", want, fake.events)
		}
	}
}

func TestFreshRecoveryConvergesAfterNativeKeychainModeNormalization(t *testing.T) {
	recoveryRoot := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
	directory := filepath.Join(recoveryRoot, "state-native-recovery")
	keychain := filepath.Join(directory, isolatedKeychainFilename)
	setupFake := newFakeSecurityCommand()
	setupFake.keychainPath = keychain
	setupFake.keychainMode = 0o644
	if err := configureIsolatedTestKeychain(isolatedKeychainSetup{
		recoveryRoot:    recoveryRoot,
		runSecurity:     setupFake.run,
		chooseDirectory: func() (string, error) { return directory, nil },
		registerCleanup: func(func()) {},
		reportCleanup:   func(error) {},
		password:        "synthetic-password",
	}); err != nil {
		t.Fatal(err)
	}

	recoveryFake := newFakeSecurityCommand()
	if err := recoverIsolatedTestKeychainFromRoot(recoveryRoot, recoveryFake.run); err != nil {
		t.Fatalf("fresh recovery after native mode normalization: %v", err)
	}
	if _, err := os.Lstat(recoveryRoot); !os.IsNotExist(err) {
		t.Fatalf("fresh recovery retained root: %v", err)
	}
	for _, want := range []string{
		"list-keychains -d user -s /original/login.keychain-db /original/system.keychain",
		"default-keychain -d user -s /original/login.keychain-db",
	} {
		if eventIndex(recoveryFake.events, want) < 0 {
			t.Fatalf("fresh recovery omitted host restoration %q; events=%q", want, recoveryFake.events)
		}
	}
}

func TestDisposableKeychainMetadataValidationCategories(t *testing.T) {
	effectiveUID := uint32(os.Geteuid())
	valid := disposableKeychainMetadata{regular: true, mode: 0o600, owner: effectiveUID, links: 1}
	for name, testCase := range map[string]struct {
		metadata disposableKeychainMetadata
		want     error
	}{
		"directory":      {disposableKeychainMetadata{directory: true, mode: 0o700, owner: effectiveUID, links: 2}, errDisposableKeychainType},
		"foreign owner":  {disposableKeychainMetadata{regular: true, mode: 0o600, owner: effectiveUID + 1, links: 1}, errDisposableKeychainOwner},
		"multiple links": {disposableKeychainMetadata{regular: true, mode: 0o600, owner: effectiveUID, links: 2}, errDisposableKeychainLinks},
		"group access":   {disposableKeychainMetadata{regular: true, mode: 0o640, owner: effectiveUID, links: 1}, errDisposableKeychainMode},
		"other access":   {disposableKeychainMetadata{regular: true, mode: 0o604, owner: effectiveUID, links: 1}, errDisposableKeychainMode},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateDisposableKeychainMetadata(testCase.metadata, effectiveUID, false); !errors.Is(err, testCase.want) {
				t.Fatalf("validation error = %v, want category %v", err, testCase.want)
			}
		})
	}
	if err := validateDisposableKeychainMetadata(valid, effectiveUID, false); err != nil {
		t.Fatalf("private disposable Keychain rejected: %v", err)
	}
	nativeMode := valid
	nativeMode.mode = 0o644
	if err := validateDisposableKeychainMetadata(nativeMode, effectiveUID, true); err != nil {
		t.Fatalf("native security-created mode rejected before normalization: %v", err)
	}
	if err := validateDisposableKeychainMetadata(nativeMode, effectiveUID, false); !errors.Is(err, errDisposableKeychainMode) {
		t.Fatalf("native mode accepted after normalization boundary: %v", err)
	}
}

func TestFreshRecoveryRejectsUnsafeDisposableKeychainWithoutHostMutation(t *testing.T) {
	for name, makeUnsafe := range map[string]func(*testing.T, string){
		"symlink": func(t *testing.T, keychain string) {
			if err := os.Remove(keychain); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("do not delete"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, keychain); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(t *testing.T, keychain string) {
			if err := os.Remove(keychain); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(keychain, 0o700); err != nil {
				t.Fatal(err)
			}
		},
		"multiple links": func(t *testing.T, keychain string) {
			target := filepath.Join(t.TempDir(), "linked-keychain")
			if err := os.Link(keychain, target); err != nil {
				t.Fatal(err)
			}
		},
		"group access": func(t *testing.T, keychain string) {
			if err := os.Chmod(keychain, 0o640); err != nil {
				t.Fatal(err)
			}
		},
		"other access": func(t *testing.T, keychain string) {
			if err := os.Chmod(keychain, 0o604); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
			directory := prepareFreshRecoveryState(t, root, "state-unsafe-keychain")
			makeUnsafe(t, filepath.Join(directory, isolatedKeychainFilename))
			fake := newFakeSecurityCommand()
			if err := recoverIsolatedTestKeychainFromRoot(root, fake.run); err == nil {
				t.Fatal("fresh recovery accepted an unsafe disposable Keychain")
			}
			if len(fake.events) != 0 {
				t.Fatalf("unsafe disposable Keychain caused host mutation: %q", fake.events)
			}
		})
	}
}

func TestSetupRejectsUnsafeSecurityCreatedKeychainBeforeHostUse(t *testing.T) {
	for name, testCase := range map[string]struct {
		makeUnsafe func(*testing.T, string)
		want       error
	}{
		"symlink": {
			makeUnsafe: func(t *testing.T, keychain string) {
				if err := os.Remove(keychain); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, []byte("do not use"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, keychain); err != nil {
					t.Fatal(err)
				}
			},
			want: errDisposableKeychainType,
		},
		"directory": {
			makeUnsafe: func(t *testing.T, keychain string) {
				if err := os.Remove(keychain); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(keychain, 0o700); err != nil {
					t.Fatal(err)
				}
			},
			want: errDisposableKeychainType,
		},
		"multiple links": {
			makeUnsafe: func(t *testing.T, keychain string) {
				if err := os.Link(keychain, filepath.Join(t.TempDir(), "linked-keychain")); err != nil {
					t.Fatal(err)
				}
			},
			want: errDisposableKeychainLinks,
		},
		"unexpected mode": {
			makeUnsafe: func(t *testing.T, keychain string) {
				if err := os.Chmod(keychain, 0o640); err != nil {
					t.Fatal(err)
				}
			},
			want: errDisposableKeychainMode,
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
			directory := filepath.Join(root, "state-unsafe-create")
			keychain := filepath.Join(directory, isolatedKeychainFilename)
			fake := newFakeSecurityCommand()
			fake.keychainPath = keychain
			fake.afterCreate = func(path string) error {
				testCase.makeUnsafe(t, path)
				return nil
			}
			var cleanup func()
			err := configureIsolatedTestKeychain(isolatedKeychainSetup{
				recoveryRoot:    root,
				runSecurity:     fake.run,
				chooseDirectory: func() (string, error) { return directory, nil },
				registerCleanup: func(function func()) { cleanup = function },
				reportCleanup:   func(error) {},
				password:        "synthetic-password",
			})
			if !errors.Is(err, testCase.want) {
				t.Fatalf("unsafe security-created Keychain error = %v, want category %v", err, testCase.want)
			}
			if len(fake.keychainUseModes) != 0 {
				t.Fatalf("unsafe security-created Keychain was used with modes %#o", fake.keychainUseModes)
			}
			cleanup()
		})
	}
}

func TestDisposableKeychainLeafSwapBeforeModeNormalizationFailsClosed(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		name := "setup"
		if recovery {
			name = "recovery"
		}
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
			directory := filepath.Join(root, "state-normalization-swap")
			keychain := filepath.Join(directory, isolatedKeychainFilename)
			moved := filepath.Join(directory, "opened-keychain")
			swap := func() error {
				if err := os.Rename(keychain, moved); err != nil {
					return err
				}
				return os.WriteFile(keychain, []byte("unrelated replacement"), 0o644)
			}

			setupFake := newFakeSecurityCommand()
			setupFake.keychainPath = keychain
			setupFake.keychainMode = 0o644
			setup := isolatedKeychainSetup{
				recoveryRoot:    root,
				runSecurity:     setupFake.run,
				chooseDirectory: func() (string, error) { return directory, nil },
				registerCleanup: func(func()) {},
				reportCleanup:   func(error) {},
				password:        "synthetic-password",
			}
			if !recovery {
				setup.beforeKeychainModeNormalization = swap
				if err := configureIsolatedTestKeychain(setup); err == nil {
					t.Fatal("setup accepted a disposable Keychain leaf swap before mode normalization")
				}
				if len(setupFake.keychainUseModes) != 0 {
					t.Fatalf("setup used a swapped disposable Keychain: %#o", setupFake.keychainUseModes)
				}
			} else {
				crash := errors.New("simulate process crash after create-keychain")
				setupFake.afterCreate = func(string) error { return crash }
				if err := configureIsolatedTestKeychain(setup); err == nil {
					t.Fatal("setup succeeded despite injected post-create crash")
				}
				recoveryFake := newFakeSecurityCommand()
				if err := recoverIsolatedTestKeychainFromRootWithHooks(root, recoveryFake.run, isolatedKeychainRecoveryHooks{
					beforeKeychainModeNormalization: swap,
				}); err == nil {
					t.Fatal("recovery accepted a disposable Keychain leaf swap before mode normalization")
				}
				if len(recoveryFake.events) != 0 {
					t.Fatalf("recovery called host security after a pre-normalization leaf swap: %q", recoveryFake.events)
				}
			}

			for _, path := range []string{moved, keychain} {
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if got := info.Mode().Perm(); got != 0o644 {
					t.Fatalf("swapped leaf %q mode = %#o, want unchanged 0644", filepath.Base(path), got)
				}
			}
		})
	}
}

func TestDisposableKeychainDescriptorSwapCannotRedirectDeletion(t *testing.T) {
	directory := filepath.Join(canonicalTestTemporaryDirectory(t), "private-state")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, err := openPrivateRecoveryDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	keychain := filepath.Join(directory, isolatedKeychainFilename)
	if err := os.WriteFile(keychain, []byte("opened"), 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := openDisposableKeychainAt(parent, isolatedKeychainFilename)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	moved := filepath.Join(directory, "opened-keychain")
	if err := os.Rename(keychain, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keychain, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := unlinkOpenedDisposableKeychainAt(parent, isolatedKeychainFilename, opened); err == nil {
		t.Fatal("descriptor swap was accepted")
	}
	if contents, err := os.ReadFile(keychain); err != nil || string(contents) != "replacement" {
		t.Fatalf("replacement was modified: contents=%q err=%v", contents, err)
	}
}

func TestOpenedDisposableKeychainDeletionRequiresZeroLinks(t *testing.T) {
	for _, alreadyUnlinked := range []bool{false, true} {
		name := "successful unlink"
		if alreadyUnlinked {
			name = "already unlinked"
		}
		t.Run(name, func(t *testing.T) {
			directory := filepath.Join(canonicalTestTemporaryDirectory(t), "private-state")
			if err := os.Mkdir(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			parent, err := openPrivateRecoveryDirectory(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			keychain := filepath.Join(directory, isolatedKeychainFilename)
			if err := os.WriteFile(keychain, []byte("opened"), 0o600); err != nil {
				t.Fatal(err)
			}
			opened, err := openDisposableKeychainAt(parent, isolatedKeychainFilename)
			if err != nil {
				t.Fatal(err)
			}
			defer opened.Close()
			if alreadyUnlinked {
				if err := os.Remove(keychain); err != nil {
					t.Fatal(err)
				}
			}

			if err := unlinkOpenedDisposableKeychainAt(parent, isolatedKeychainFilename, opened); err != nil {
				t.Fatalf("delete opened disposable Keychain: %v", err)
			}
			info, err := opened.Stat()
			if err != nil {
				t.Fatal(err)
			}
			native := info.Sys().(*syscall.Stat_t)
			if native.Nlink != 0 {
				t.Fatalf("opened disposable Keychain link count = %d, want 0", native.Nlink)
			}
		})
	}
}

func TestOpenedRecoveryDirectoryDeletionRejectsPostOpenAbsence(t *testing.T) {
	base := canonicalTestTemporaryDirectory(t)
	directoryName := "private-state"
	directory := filepath.Join(base, directoryName)
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, err := openRecoveryDirectoryNoFollow(base, false)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	opened, err := openPrivateRecoveryDirectoryAt(parent, directoryName)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := os.Remove(directory); err != nil {
		t.Fatal(err)
	}

	if err := unlinkOpenedRecoveryDirectoryAt(parent, directoryName, opened); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("post-open directory absence error = %v, want ENOENT", err)
	}
}

func TestRecoveryRetainsRecoveryRequiredAfterValidatedKeychainRename(t *testing.T) {
	root := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
	directory := prepareFreshRecoveryState(t, root, "state-unlink-race")
	keychain := filepath.Join(directory, isolatedKeychainFilename)
	moved := filepath.Join(directory, "still-linked-keychain")
	fake := newFakeSecurityCommand()
	err := recoverIsolatedTestKeychainFromRootWithHooks(root, fake.run, isolatedKeychainRecoveryHooks{
		beforeKeychainUnlink: func() error { return os.Rename(keychain, moved) },
	})
	if err == nil {
		t.Fatal("recovery accepted a renamed but still-linked disposable Keychain")
	}
	if _, err := os.Stat(moved); err != nil {
		t.Fatalf("recovery removed the still-linked opened inode: %v", err)
	}
	locatorContents, err := os.ReadFile(filepath.Join(root, isolatedKeychainLocatorFilename))
	if err != nil {
		t.Fatal(err)
	}
	locator, err := decodeIsolatedKeychainRecoveryLocator(locatorContents)
	if err != nil {
		t.Fatal(err)
	}
	if locator.Phase != isolatedKeychainPhaseRecovery {
		t.Fatalf("rename-race locator phase = %q, want recovery-required", locator.Phase)
	}
}

func TestRecoveryRetainsCleanupLocatorAfterValidatedStateDirectoryRename(t *testing.T) {
	root := filepath.Join(canonicalTestTemporaryDirectory(t), "recovery-root")
	directory := prepareFreshRecoveryState(t, root, "state-unlink-race")
	moved := filepath.Join(root, "still-linked-state")
	fake := newFakeSecurityCommand()
	err := recoverIsolatedTestKeychainFromRootWithHooks(root, fake.run, isolatedKeychainRecoveryHooks{
		beforeStateDirectoryUnlink: func() error { return os.Rename(directory, moved) },
	})
	if err == nil || err.Error() != "isolated Keychain recovery did not complete" {
		t.Fatalf("state-directory rename recovery = %v", err)
	}
	if _, err := os.Stat(moved); err != nil {
		t.Fatalf("recovery removed the still-linked opened state directory: %v", err)
	}
	locatorContents, err := os.ReadFile(filepath.Join(root, isolatedKeychainLocatorFilename))
	if err != nil {
		t.Fatal(err)
	}
	locator, err := decodeIsolatedKeychainRecoveryLocator(locatorContents)
	if err != nil {
		t.Fatal(err)
	}
	if locator.Phase != isolatedKeychainPhaseCleanup {
		t.Fatalf("rename-race locator phase = %q, want cleanup-only", locator.Phase)
	}
}

func TestRecoveryRetainsCleanupLocatorAfterValidatedRootDirectoryRename(t *testing.T) {
	base := canonicalTestTemporaryDirectory(t)
	root := filepath.Join(base, "recovery-root")
	prepareFreshRecoveryState(t, root, "state-unlink-race")
	moved := filepath.Join(base, "still-linked-root")
	fake := newFakeSecurityCommand()
	err := recoverIsolatedTestKeychainFromRootWithHooks(root, fake.run, isolatedKeychainRecoveryHooks{
		beforeRootDirectoryUnlink: func() error { return os.Rename(root, moved) },
	})
	if err == nil || err.Error() != "isolated Keychain recovery did not complete" {
		t.Fatalf("root-directory rename recovery = %v", err)
	}
	if _, statErr := os.Stat(moved); statErr != nil {
		t.Fatalf("recovery removed the still-linked opened root directory: %v", statErr)
	}
	locatorContents, err := os.ReadFile(filepath.Join(moved, isolatedKeychainLocatorFilename))
	if err != nil {
		t.Fatal(err)
	}
	locator, err := decodeIsolatedKeychainRecoveryLocator(locatorContents)
	if err != nil {
		t.Fatal(err)
	}
	if locator.Phase != isolatedKeychainPhaseCleanup {
		t.Fatalf("rename-race locator phase = %q, want cleanup-only", locator.Phase)
	}
}

type fakeSecurityCommand struct {
	events               []string
	failures             map[string]error
	failuresAfter        map[string]error
	keychainPath         string
	keychainMode         os.FileMode
	keychainUseModes     []os.FileMode
	afterCreate          func(string) error
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
		mode := fake.keychainMode
		if mode == 0 {
			mode = 0o600
		}
		if err := os.WriteFile(fake.keychainPath, []byte("synthetic disposable Keychain"), mode); err != nil {
			return "", err
		}
		if err := os.Chmod(fake.keychainPath, mode); err != nil {
			return "", err
		}
		if fake.afterCreate != nil {
			if err := fake.afterCreate(fake.keychainPath); err != nil {
				return "", err
			}
		}
	}
	if command == "list-keychains -d user -s "+fake.keychainPath && fake.keychainPath != "" {
		info, err := os.Stat(fake.keychainPath)
		if err != nil {
			return "", err
		}
		fake.keychainUseModes = append(fake.keychainUseModes, info.Mode().Perm())
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
		chooseDirectory: func() (string, error) {
			return filepath.Join(recoveryRoot, fmt.Sprintf("state-%d-%d", os.Getpid(), time.Now().UnixNano())), nil
		},
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
	recoveryRoot                    string
	runSecurity                     func(...string) (string, error)
	chooseDirectory                 func() (string, error)
	recordRecoveryPersisted         func()
	beforeKeychainModeNormalization func() error
	registerCleanup                 func(func())
	reportCleanup                   func(error)
	password                        string
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
	rootParent          *os.File
	rootDirectory       *os.File
	stateDirectory      *os.File
	rootName            string
	stateName           string
	keychainMayExist    bool
	cleanupArmed        bool
	hostMutationStarted bool
}

const (
	isolatedKeychainRecoveryFilename = "native-auth-gate.recovery.json"
	isolatedKeychainLocatorFilename  = "active-recovery.json"
	isolatedKeychainFilename         = "native-auth-gate.keychain-db"
	isolatedKeychainRecoveryGuidance = "Restore the user Keychain search list and default from this file with /usr/bin/security, then delete the disposable Keychain and this directory only after both restorations succeed."
	isolatedKeychainPhaseRecovery    = "recovery-required"
	isolatedKeychainPhaseCleanup     = "cleanup-only"
)

type isolatedKeychainRecovery struct {
	Version         int      `json:"version"`
	OriginalDefault string   `json:"originalDefault"`
	OriginalSearch  []string `json:"originalSearch"`
	Guidance        string   `json:"guidance"`
}

type isolatedKeychainRecoveryLocator struct {
	Version        int    `json:"version"`
	StateDirectory string `json:"stateDirectory"`
	Phase          string `json:"phase"`
}

type isolatedKeychainRecoveryHooks struct {
	afterDescriptorsOpened          func() error
	beforeKeychainModeNormalization func() error
	beforeKeychainUnlink            func() error
	afterPhaseUpdate                func() error
	beforeStateDirectoryUnlink      func() error
	beforeRootDirectoryUnlink       func() error
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
	state.recoveryRoot, err = canonicalIsolatedKeychainRecoveryRoot(setup.recoveryRoot)
	if err != nil {
		return fmt.Errorf("prepare isolated Keychain recovery root %s: %w", setup.recoveryRoot, err)
	}
	state.rootName = filepath.Base(state.recoveryRoot)
	state.rootParent, err = openRecoveryDirectoryNoFollow(filepath.Dir(state.recoveryRoot), false)
	if err != nil {
		return fmt.Errorf("prepare isolated Keychain recovery root %s", state.recoveryRoot)
	}
	if err := unix.Mkdirat(int(state.rootParent.Fd()), state.rootName, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("prepare isolated Keychain recovery root %s", state.recoveryRoot)
	}
	if err := state.rootParent.Sync(); err != nil {
		return fmt.Errorf("prepare isolated Keychain recovery root %s", state.recoveryRoot)
	}
	state.rootDirectory, err = openPrivateRecoveryDirectoryAt(state.rootParent, state.rootName)
	if err != nil {
		return fmt.Errorf("prepare isolated Keychain recovery root %s", state.recoveryRoot)
	}
	state.locatorPath = filepath.Join(state.recoveryRoot, isolatedKeychainLocatorFilename)
	entries, err := state.rootDirectory.ReadDir(-1)
	if err != nil || len(entries) != 0 {
		return fmt.Errorf("stale or unsafe isolated Keychain recovery state at %s", state.locatorPath)
	}
	state.cleanupArmed = true
	state.directory, err = setup.chooseDirectory()
	if err != nil {
		return errors.New("create isolated Keychain directory")
	}
	state.stateName = filepath.Base(state.directory)
	if filepath.Dir(state.directory) != state.recoveryRoot || !validIsolatedKeychainStateName(state.stateName) {
		return errors.New("create isolated Keychain directory")
	}
	if err := unix.Mkdirat(int(state.rootDirectory.Fd()), state.stateName, 0o700); err != nil {
		return errors.New("create isolated Keychain directory")
	}
	if err := state.rootDirectory.Sync(); err != nil {
		return errors.New("create isolated Keychain directory")
	}
	state.stateDirectory, err = openPrivateRecoveryDirectoryAt(state.rootDirectory, state.stateName)
	if err != nil {
		return errors.New("create isolated Keychain directory")
	}
	state.keychain = filepath.Join(state.directory, isolatedKeychainFilename)
	state.recoveryPath = filepath.Join(state.directory, isolatedKeychainRecoveryFilename)
	if err := persistIsolatedKeychainRecoveryAt(state.stateDirectory, isolatedKeychainRecovery{
		Version:         2,
		OriginalDefault: state.originalDefault,
		OriginalSearch:  append([]string{}, state.originalSearch...),
		Guidance:        isolatedKeychainRecoveryGuidance,
	}); err != nil {
		return errors.New("persist isolated Keychain recovery state")
	}
	if setup.recordRecoveryPersisted != nil {
		setup.recordRecoveryPersisted()
	}
	if err := persistIsolatedKeychainRecoveryLocatorAt(state.rootDirectory, isolatedKeychainRecoveryLocator{
		Version:        2,
		StateDirectory: state.stateName,
		Phase:          isolatedKeychainPhaseRecovery,
	}); err != nil {
		return errors.New("persist isolated Keychain recovery locator")
	}
	locatorContents, err := readPrivateRecoveryFileAt(state.rootDirectory, isolatedKeychainLocatorFilename)
	locator, decodeErr := decodeIsolatedKeychainRecoveryLocator(locatorContents)
	if err != nil || decodeErr != nil || locator.StateDirectory != state.stateName || locator.Phase != isolatedKeychainPhaseRecovery {
		return errors.New("validate isolated Keychain recovery locator")
	}
	if _, err := readIsolatedKeychainRecoveryAt(state.stateDirectory); err != nil {
		return errors.New("validate isolated Keychain recovery state")
	}
	state.keychainMayExist = true
	state.hostMutationStarted = true
	if _, err := setup.runSecurity("create-keychain", "-p", setup.password, state.keychain); err != nil {
		return errors.New("configure isolated Keychain")
	}
	if err := normalizeDisposableKeychainAtWithHook(
		state.stateDirectory,
		isolatedKeychainFilename,
		setup.beforeKeychainModeNormalization,
	); err != nil {
		return fmt.Errorf("configure isolated Keychain: %w", err)
	}
	for _, command := range [][]string{
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
	defer state.closeDescriptors()
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
		keychainFile, err := openDisposableKeychainAt(state.stateDirectory, isolatedKeychainFilename)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return fmt.Errorf("recovery state retained at %s: %w", state.locatorPath, err)
		} else if err == nil {
			if err := unlinkOpenedDisposableKeychainAt(state.stateDirectory, isolatedKeychainFilename, keychainFile); err != nil {
				_ = keychainFile.Close()
				return fmt.Errorf("recovery state retained at %s: delete isolated Keychain after restoration", state.locatorPath)
			}
			_ = keychainFile.Close()
		}
	}
	if state.rootDirectory != nil && state.stateName != "" {
		if err := persistIsolatedKeychainRecoveryLocatorAt(state.rootDirectory, isolatedKeychainRecoveryLocator{
			Version: 2, StateDirectory: state.stateName, Phase: isolatedKeychainPhaseCleanup,
		}); err != nil {
			return fmt.Errorf("recovery state retained at %s: persist cleanup phase", state.locatorPath)
		}
	}
	return cleanupIsolatedKeychainLocalState(state.rootParent, state.rootDirectory, state.stateDirectory, state.rootName, state.stateName, isolatedKeychainRecoveryHooks{})
}

func (state *isolatedKeychainState) closeDescriptors() {
	for _, descriptor := range []*os.File{state.stateDirectory, state.rootDirectory, state.rootParent} {
		if descriptor != nil {
			_ = descriptor.Close()
		}
	}
}

func persistIsolatedKeychainRecovery(path string, recovery isolatedKeychainRecovery) error {
	parent, err := openPrivateRecoveryDirectory(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	return persistIsolatedKeychainRecoveryAt(parent, recovery)
}

func persistIsolatedKeychainRecoveryAt(parent *os.File, recovery isolatedKeychainRecovery) error {
	contents, err := json.Marshal(recovery)
	if err != nil {
		return err
	}
	return persistPrivateRecoveryFileAt(parent, isolatedKeychainRecoveryFilename, append(contents, '\n'))
}

func persistIsolatedKeychainRecoveryLocatorAt(parent *os.File, locator isolatedKeychainRecoveryLocator) error {
	contents, err := json.Marshal(locator)
	if err != nil {
		return err
	}
	return persistPrivateRecoveryFileAt(parent, isolatedKeychainLocatorFilename, append(contents, '\n'))
}

func persistPrivateRecoveryFileAt(parent *os.File, name string, contents []byte) (resultErr error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return errors.New("recovery path is unsafe")
	}
	temporary := name + ".tmp"
	if err := unlinkPrivateRecoveryFileIfPresent(parent, temporary); err != nil {
		return err
	}
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
	if err := unix.Renameat(int(parent.Fd()), temporary, int(parent.Fd()), name); err != nil {
		return err
	}
	return parent.Sync()
}

func readIsolatedKeychainRecovery(path string) (isolatedKeychainRecovery, error) {
	parent, err := openPrivateRecoveryDirectory(filepath.Dir(path))
	if err != nil {
		return isolatedKeychainRecovery{}, err
	}
	defer parent.Close()
	return readIsolatedKeychainRecoveryAt(parent)
}

func readIsolatedKeychainRecoveryAt(parent *os.File) (isolatedKeychainRecovery, error) {
	contents, err := readPrivateRecoveryFileAt(parent, isolatedKeychainRecoveryFilename)
	if err != nil {
		return isolatedKeychainRecovery{}, err
	}
	return decodeIsolatedKeychainRecovery(contents)
}

func decodeIsolatedKeychainRecovery(contents []byte) (isolatedKeychainRecovery, error) {
	var recovery isolatedKeychainRecovery
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&recovery); err != nil {
		return isolatedKeychainRecovery{}, errors.New("recovery artifact is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return isolatedKeychainRecovery{}, errors.New("recovery artifact has trailing data")
	}
	if recovery.Version != 2 || recovery.OriginalDefault == "" || recovery.OriginalSearch == nil ||
		recovery.Guidance != isolatedKeychainRecoveryGuidance {
		return isolatedKeychainRecovery{}, errors.New("recovery artifact is invalid")
	}
	return recovery, nil
}

func decodeIsolatedKeychainRecoveryLocator(contents []byte) (isolatedKeychainRecoveryLocator, error) {
	var locator isolatedKeychainRecoveryLocator
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&locator); err != nil {
		return isolatedKeychainRecoveryLocator{}, errors.New("recovery locator is invalid")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return isolatedKeychainRecoveryLocator{}, errors.New("recovery locator has trailing data")
	}
	if locator.Version != 2 || !validIsolatedKeychainStateName(locator.StateDirectory) ||
		(locator.Phase != isolatedKeychainPhaseRecovery && locator.Phase != isolatedKeychainPhaseCleanup) {
		return isolatedKeychainRecoveryLocator{}, errors.New("recovery locator is invalid")
	}
	return locator, nil
}

func validIsolatedKeychainStateName(name string) bool {
	if len(name) < len("state-")+1 || len(name) > 96 || !strings.HasPrefix(name, "state-") || filepath.Base(name) != name {
		return false
	}
	for _, character := range name[len("state-"):] {
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && character != '-' && character != '_' {
			return false
		}
	}
	return true
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

var (
	errDisposableKeychainType  = errors.New("disposable Keychain type is unsafe")
	errDisposableKeychainOwner = errors.New("disposable Keychain owner is unsafe")
	errDisposableKeychainLinks = errors.New("disposable Keychain link count is unsafe")
	errDisposableKeychainMode  = errors.New("disposable Keychain mode is unsafe")
)

func normalizeDisposableKeychainAt(parent *os.File, name string) error {
	return normalizeDisposableKeychainAtWithHook(parent, name, nil)
}

func normalizeDisposableKeychainAtWithHook(parent *os.File, name string, beforeModeNormalization func() error) error {
	file, err := openDisposableKeychainForNormalizationAt(parent, name)
	if err != nil {
		return err
	}
	defer file.Close()
	if beforeModeNormalization != nil {
		if err := beforeModeNormalization(); err != nil {
			return err
		}
	}
	if err := verifyDisposableKeychainDescriptorContinuityAt(parent, name, file, true); err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		return errDisposableKeychainMode
	}
	if err := file.Sync(); err != nil {
		return errors.New("sync disposable Keychain")
	}
	if err := verifyDisposableKeychainDescriptorContinuityAt(parent, name, file, false); err != nil {
		return err
	}
	if err := parent.Sync(); err != nil {
		return errors.New("sync disposable Keychain directory")
	}
	return nil
}

func openDisposableKeychainForNormalizationAt(parent *os.File, name string) (*os.File, error) {
	return openDisposableKeychainWithModeAt(parent, name, true)
}

func openDisposableKeychainAt(parent *os.File, name string) (*os.File, error) {
	return openDisposableKeychainWithModeAt(parent, name, false)
}

func openDisposableKeychainWithModeAt(parent *os.File, name string, allowNativeMode bool) (*os.File, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, errDisposableKeychainType
	}
	descriptor, err := unix.Openat(int(parent.Fd()), name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, errDisposableKeychainType
		}
		return nil, err
	}
	file := os.NewFile(uintptr(descriptor), "disposable Keychain")
	if file == nil {
		_ = unix.Close(descriptor)
		return nil, errors.New("open disposable Keychain")
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := validateDisposableKeychainInfo(info, allowNativeMode); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func canonicalIsolatedKeychainRecoveryRoot(root string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", errors.New("recovery root is not an absolute clean path")
	}
	return root, nil
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

func validateDisposableKeychainInfo(info os.FileInfo, allowNativeMode bool) error {
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("disposable Keychain metadata is unavailable")
	}
	return validateDisposableKeychainMetadata(disposableKeychainMetadata{
		directory: info.IsDir(),
		regular:   info.Mode().IsRegular(),
		mode:      info.Mode(),
		owner:     native.Uid,
		links:     uint64(native.Nlink),
	}, uint32(os.Geteuid()), allowNativeMode)
}

type disposableKeychainMetadata struct {
	directory bool
	regular   bool
	mode      os.FileMode
	owner     uint32
	links     uint64
}

func validateDisposableKeychainMetadata(metadata disposableKeychainMetadata, effectiveUID uint32, allowNativeMode bool) error {
	if !metadata.regular || metadata.directory {
		return errDisposableKeychainType
	}
	if metadata.owner != effectiveUID {
		return errDisposableKeychainOwner
	}
	if metadata.links != 1 {
		return errDisposableKeychainLinks
	}
	if metadata.mode&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return errDisposableKeychainMode
	}
	mode := metadata.mode.Perm()
	if mode != 0o600 && (!allowNativeMode || mode != 0o644) {
		return errDisposableKeychainMode
	}
	return nil
}

func recoverIsolatedTestKeychain(
	recoveryPath string,
	runSecurity func(...string) (string, error),
) error {
	directoryPath := filepath.Dir(recoveryPath)
	parent, err := openRecoveryDirectoryNoFollow(filepath.Dir(directoryPath), false)
	if err != nil {
		return errors.New("isolated Keychain recovery artifact is invalid")
	}
	defer parent.Close()
	directory, err := openPrivateRecoveryDirectoryAt(parent, filepath.Base(directoryPath))
	if err != nil {
		return errors.New("isolated Keychain recovery artifact is invalid")
	}
	defer directory.Close()
	recovery, err := readIsolatedKeychainRecoveryAt(directory)
	if err != nil {
		return errors.New("isolated Keychain recovery artifact is invalid")
	}
	if err := restoreIsolatedKeychainHost(recovery, runSecurity); err != nil {
		return errors.New("isolated Keychain recovery did not complete")
	}
	if err := unlinkDisposableKeychainIfPresent(directory, isolatedKeychainFilename); err != nil {
		return errors.New("isolated Keychain recovery did not complete")
	}
	if err := unlinkPrivateRecoveryFileIfPresent(directory, isolatedKeychainRecoveryFilename); err != nil {
		return errors.New("isolated Keychain recovery did not complete")
	}
	if err := unlinkOpenedRecoveryDirectoryAt(parent, filepath.Base(directoryPath), directory); err != nil {
		return errors.New("isolated Keychain recovery did not complete")
	}
	return nil
}

func recoverIsolatedTestKeychainFromRoot(
	recoveryRoot string,
	runSecurity func(...string) (string, error),
) error {
	return recoverIsolatedTestKeychainFromRootWithHooks(recoveryRoot, runSecurity, isolatedKeychainRecoveryHooks{})
}

func recoverIsolatedTestKeychainFromRootWithHooks(
	recoveryRoot string,
	runSecurity func(...string) (string, error),
	hooks isolatedKeychainRecoveryHooks,
) error {
	canonicalRoot, err := canonicalIsolatedKeychainRecoveryRoot(recoveryRoot)
	if err != nil {
		return errors.New("isolated Keychain recovery root is unsafe")
	}
	rootParent, err := openRecoveryDirectoryNoFollow(filepath.Dir(canonicalRoot), false)
	if err != nil {
		return errors.New("isolated Keychain recovery root is unsafe")
	}
	defer rootParent.Close()
	rootName := filepath.Base(canonicalRoot)
	rootDirectory, err := openPrivateRecoveryDirectoryAt(rootParent, rootName)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return errors.New("isolated Keychain recovery root is unsafe")
	}
	defer rootDirectory.Close()
	locatorFile, err := openPrivateRecoveryFileAt(rootDirectory, isolatedKeychainLocatorFilename)
	if errors.Is(err, unix.ENOENT) {
		entries, readErr := rootDirectory.ReadDir(-1)
		if readErr != nil || len(entries) != 0 {
			return errors.New("isolated Keychain recovery locator is invalid")
		}
		if err := unlinkOpenedRecoveryDirectoryAt(rootParent, rootName, rootDirectory); err != nil {
			return errors.New("isolated Keychain recovery did not complete")
		}
		return nil
	}
	if err != nil {
		return errors.New("isolated Keychain recovery locator is invalid")
	}
	locatorContents, err := io.ReadAll(io.LimitReader(locatorFile, 64*1024))
	_ = locatorFile.Close()
	if err != nil {
		return errors.New("isolated Keychain recovery locator is invalid")
	}
	locator, err := decodeIsolatedKeychainRecoveryLocator(locatorContents)
	if err != nil {
		return errors.New("isolated Keychain recovery locator is invalid")
	}
	stateDirectory, err := openPrivateRecoveryDirectoryAt(rootDirectory, locator.StateDirectory)
	if locator.Phase == isolatedKeychainPhaseCleanup && errors.Is(err, unix.ENOENT) {
		if err := unlinkRecoveryRootAfterLocatorAt(rootParent, rootDirectory, rootName, locator, hooks.beforeRootDirectoryUnlink); err != nil {
			return errors.New("isolated Keychain recovery did not complete")
		}
		return nil
	}
	if err != nil {
		return errors.New("isolated Keychain recovery artifact is invalid")
	}
	defer stateDirectory.Close()

	if locator.Phase == isolatedKeychainPhaseRecovery {
		artifactFile, artifactErr := openPrivateRecoveryFileAt(stateDirectory, isolatedKeychainRecoveryFilename)
		if artifactErr != nil {
			return errors.New("isolated Keychain recovery artifact is invalid")
		}
		defer artifactFile.Close()
		keychainFile, keychainErr := openDisposableKeychainAt(stateDirectory, isolatedKeychainFilename)
		if errors.Is(keychainErr, errDisposableKeychainMode) {
			if normalizeErr := normalizeDisposableKeychainAtWithHook(
				stateDirectory,
				isolatedKeychainFilename,
				hooks.beforeKeychainModeNormalization,
			); normalizeErr != nil {
				return errors.New("isolated Keychain recovery artifact is invalid")
			}
			keychainFile, keychainErr = openDisposableKeychainAt(stateDirectory, isolatedKeychainFilename)
		}
		if keychainErr != nil && !errors.Is(keychainErr, unix.ENOENT) {
			return errors.New("isolated Keychain recovery artifact is invalid")
		}
		if keychainFile != nil {
			defer keychainFile.Close()
		}
		if hooks.afterDescriptorsOpened != nil {
			if err := hooks.afterDescriptorsOpened(); err != nil {
				return err
			}
		}
		artifactContents, readErr := io.ReadAll(io.LimitReader(artifactFile, 64*1024))
		if readErr != nil {
			return errors.New("isolated Keychain recovery artifact is invalid")
		}
		recovery, decodeErr := decodeIsolatedKeychainRecovery(artifactContents)
		if decodeErr != nil {
			return errors.New("isolated Keychain recovery artifact is invalid")
		}
		if err := restoreIsolatedKeychainHost(recovery, runSecurity); err != nil {
			return errors.New("isolated Keychain recovery did not complete")
		}
		if keychainFile != nil {
			if err := unlinkOpenedDisposableKeychainAtWithHook(
				stateDirectory,
				isolatedKeychainFilename,
				keychainFile,
				hooks.beforeKeychainUnlink,
			); err != nil {
				return errors.New("isolated Keychain recovery did not complete")
			}
		}
		if err := persistIsolatedKeychainRecoveryLocatorAt(rootDirectory, isolatedKeychainRecoveryLocator{
			Version: 2, StateDirectory: locator.StateDirectory, Phase: isolatedKeychainPhaseCleanup,
		}); err != nil {
			return errors.New("isolated Keychain recovery did not complete")
		}
		if hooks.afterPhaseUpdate != nil {
			if err := hooks.afterPhaseUpdate(); err != nil {
				return err
			}
		}
	}
	if err := cleanupIsolatedKeychainLocalState(rootParent, rootDirectory, stateDirectory, rootName, locator.StateDirectory, hooks); err != nil {
		return errors.New("isolated Keychain recovery did not complete")
	}
	return nil
}

func restoreIsolatedKeychainHost(recovery isolatedKeychainRecovery, runSecurity func(...string) (string, error)) error {
	searchArguments := []string{"list-keychains", "-d", "user", "-s"}
	searchArguments = append(searchArguments, recovery.OriginalSearch...)
	_, searchErr := runSecurity(searchArguments...)
	_, defaultErr := runSecurity("default-keychain", "-d", "user", "-s", recovery.OriginalDefault)
	return errors.Join(cleanupError("restore Keychain search list", searchErr), cleanupError("restore default Keychain", defaultErr))
}

func cleanupIsolatedKeychainLocalState(rootParent, rootDirectory, stateDirectory *os.File, rootName, stateName string, hooks isolatedKeychainRecoveryHooks) error {
	if stateDirectory != nil {
		if err := unlinkPrivateRecoveryFileIfPresent(stateDirectory, isolatedKeychainRecoveryFilename); err != nil {
			return err
		}
		if err := unlinkOpenedRecoveryDirectoryAtWithHook(rootDirectory, stateName, stateDirectory, hooks.beforeStateDirectoryUnlink); err != nil {
			return err
		}
	}
	locator := isolatedKeychainRecoveryLocator{
		Version: 2, StateDirectory: stateName, Phase: isolatedKeychainPhaseCleanup,
	}
	return unlinkRecoveryRootAfterLocatorAt(rootParent, rootDirectory, rootName, locator, hooks.beforeRootDirectoryUnlink)
}

func unlinkRecoveryRootAfterLocatorAt(
	rootParent, rootDirectory *os.File,
	rootName string,
	locator isolatedKeychainRecoveryLocator,
	beforeUnlink func() error,
) error {
	if err := unlinkPrivateRecoveryFileIfPresent(rootDirectory, isolatedKeychainLocatorFilename); err != nil {
		return err
	}
	if err := unlinkOpenedRecoveryDirectoryAtWithHook(rootParent, rootName, rootDirectory, beforeUnlink); err != nil {
		return errors.Join(err, persistIsolatedKeychainRecoveryLocatorAt(rootDirectory, locator))
	}
	return nil
}

func unlinkPrivateRecoveryFileIfPresent(parent *os.File, name string) error {
	file, err := openPrivateRecoveryFileAt(parent, name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	return unlinkOpenedRecoveryFileAt(parent, name, file)
}

func unlinkDisposableKeychainIfPresent(parent *os.File, name string) error {
	file, err := openDisposableKeychainAt(parent, name)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer file.Close()
	return unlinkOpenedDisposableKeychainAt(parent, name, file)
}

func unlinkOpenedDisposableKeychainAt(parent *os.File, name string, opened *os.File) error {
	return unlinkOpenedDisposableKeychainAtWithHook(parent, name, opened, nil)
}

func unlinkOpenedDisposableKeychainAtWithHook(parent *os.File, name string, opened *os.File, beforeUnlink func() error) error {
	if err := verifyDisposableKeychainDescriptorContinuityAt(parent, name, opened, false); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if beforeUnlink != nil {
		if err := beforeUnlink(); err != nil {
			return err
		}
	}
	if err := unix.Unlinkat(int(parent.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err := requireOpenedDescriptorUnlinked(opened); err != nil {
		return err
	}
	return parent.Sync()
}

func unlinkOpenedRecoveryFileAt(parent *os.File, name string, opened *os.File) error {
	if err := verifyRecoveryDescriptorContinuityAt(parent, name, opened, false); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err := unix.Unlinkat(int(parent.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	if err := requireOpenedDescriptorUnlinked(opened); err != nil {
		return err
	}
	return parent.Sync()
}

func requireOpenedDescriptorUnlinked(opened *os.File) error {
	info, err := opened.Stat()
	if err != nil {
		return err
	}
	native, ok := info.Sys().(*syscall.Stat_t)
	if !ok || native.Nlink != 0 {
		return errors.New("opened recovery file physical removal is unproven")
	}
	return nil
}

func unlinkOpenedRecoveryDirectoryAt(parent *os.File, name string, opened *os.File) error {
	return unlinkOpenedRecoveryDirectoryAtWithHook(parent, name, opened, nil)
}

func unlinkOpenedRecoveryDirectoryAtWithHook(parent *os.File, name string, opened *os.File, beforeUnlink func() error) error {
	if err := verifyRecoveryDescriptorContinuityAt(parent, name, opened, true); err != nil {
		return err
	}
	if beforeUnlink != nil {
		if err := beforeUnlink(); err != nil {
			return err
		}
	}
	if err := unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return parent.Sync()
}

func verifyRecoveryDescriptorContinuityAt(parent *os.File, name string, opened *os.File, directory bool) error {
	openedInfo, err := opened.Stat()
	if err != nil {
		return err
	}
	var entry unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	openedNative, ok := openedInfo.Sys().(*syscall.Stat_t)
	if !ok || uint64(openedNative.Dev) != uint64(entry.Dev) || openedNative.Ino != entry.Ino {
		return errors.New("recovery descriptor continuity is invalid")
	}
	return validatePrivateRecoveryInfo(openedInfo, directory)
}

func verifyDisposableKeychainDescriptorContinuityAt(parent *os.File, name string, opened *os.File, allowNativeMode bool) error {
	openedInfo, err := opened.Stat()
	if err != nil {
		return err
	}
	var entry unix.Stat_t
	if err := unix.Fstatat(int(parent.Fd()), name, &entry, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	openedNative, ok := openedInfo.Sys().(*syscall.Stat_t)
	if !ok || uint64(openedNative.Dev) != uint64(entry.Dev) || openedNative.Ino != entry.Ino {
		return errors.New("disposable Keychain descriptor continuity is invalid")
	}
	return validateDisposableKeychainInfo(openedInfo, allowNativeMode)
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
