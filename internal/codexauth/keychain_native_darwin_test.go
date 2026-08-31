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

func useIsolatedTestKeychain(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/usr/bin/security"); err != nil {
		t.Fatal("system Keychain tool is unavailable")
	}
	originalDefault := securityOutput(t, "default-keychain", "-d", "user")
	originalSearch := parseSecurityKeychainList(securityOutput(t, "list-keychains", "-d", "user"))
	keychain := filepath.Join(t.TempDir(), "native-auth-gate.keychain-db")
	password := fmt.Sprintf("synthetic-%d-%d", os.Getpid(), time.Now().UnixNano())
	runSecurity(t, "create-keychain", "-p", password, keychain)
	runSecurity(t, "list-keychains", "-d", "user", "-s", keychain)
	runSecurity(t, "default-keychain", "-d", "user", "-s", keychain)
	runSecurity(t, "unlock-keychain", "-p", password, keychain)
	t.Cleanup(func() {
		arguments := []string{"list-keychains", "-d", "user", "-s"}
		arguments = append(arguments, originalSearch...)
		if err := runSecurityForCleanup(arguments...); err != nil {
			t.Error("restore Keychain search list")
		}
		if original := strings.Trim(originalDefault, "\"\n \t\r"); original != "" {
			if err := runSecurityForCleanup("default-keychain", "-d", "user", "-s", original); err != nil {
				t.Error("restore default Keychain")
			}
		}
		if err := runSecurityForCleanup("delete-keychain", keychain); err != nil {
			t.Error("delete isolated Keychain")
		}
	})
}

func securityOutput(t *testing.T, arguments ...string) string {
	t.Helper()
	output, err := exec.Command("/usr/bin/security", arguments...).CombinedOutput()
	if err != nil {
		t.Fatal("inspect Keychain configuration")
	}
	return string(output)
}

func runSecurity(t *testing.T, arguments ...string) {
	t.Helper()
	if err := exec.Command("/usr/bin/security", arguments...).Run(); err != nil {
		t.Fatal("configure isolated Keychain")
	}
}

func runSecurityForCleanup(arguments ...string) error {
	return exec.Command("/usr/bin/security", arguments...).Run()
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
