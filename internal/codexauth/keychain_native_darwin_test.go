//go:build darwin

package codexauth

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestNativeKeychainFrameworkLoads(t *testing.T) {
	if _, err := newNativeKeychainClient(); err != nil {
		t.Fatalf("load native Keychain client: %v", err)
	}
}

func TestNativeKeychainRoundTrip(t *testing.T) {
	if os.Getenv("ACS_RUN_NATIVE_KEYCHAIN_TEST") != "1" {
		t.Skip("set ACS_RUN_NATIVE_KEYCHAIN_TEST=1 to exercise a temporary Keychain item")
	}
	client, err := newNativeKeychainClient()
	if err != nil {
		t.Fatal(err)
	}
	service := fmt.Sprintf("%s.test.%d.%d", keychainService, os.Getpid(), time.Now().UnixNano())
	account := "round-trip"
	comment := `{"version":1,"kind":"test"}`
	secret := bytes.Repeat([]byte("s"), maximumAuthJSONSize+1024)
	t.Cleanup(func() {
		if err := client.Delete(service, account); err != nil && !errors.Is(err, errKeychainItemNotFound) {
			t.Errorf("clean temporary Keychain item: %v", err)
		}
	})

	if err := client.Add(service, account, comment, secret); err != nil {
		t.Fatal(err)
	}
	if err := client.Add(service, account, comment, secret); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("duplicate add error = %v", err)
	}
	attributes, err := client.Attributes(service, &account)
	if err != nil {
		t.Fatal(err)
	}
	wantAttributes := []keychainAttributes{{Account: account, Comment: comment}}
	if !reflect.DeepEqual(attributes, wantAttributes) {
		t.Fatalf("attributes = %#v, want %#v", attributes, wantAttributes)
	}
	gotSecret, err := client.Data(service, account)
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(gotSecret)
	if !reflect.DeepEqual(gotSecret, secret) {
		t.Fatal("Keychain changed the opaque payload")
	}
	updatedComment := `{"version":1,"kind":"updated-test"}`
	updatedSecret := bytes.Repeat([]byte("u"), maximumAuthJSONSize+2048)
	if err := client.Update(service, account, updatedComment, updatedSecret); err != nil {
		t.Fatal(err)
	}
	attributes, err = client.Attributes(service, &account)
	if err != nil {
		t.Fatal(err)
	}
	if want := []keychainAttributes{{Account: account, Comment: updatedComment}}; !reflect.DeepEqual(attributes, want) {
		t.Fatalf("updated attributes = %#v, want %#v", attributes, want)
	}
	gotUpdatedSecret, err := client.Data(service, account)
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(gotUpdatedSecret)
	if !reflect.DeepEqual(gotUpdatedSecret, updatedSecret) {
		t.Fatal("Keychain changed the updated opaque payload")
	}
	if err := client.Delete(service, account); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Data(service, account); !errors.Is(err, errKeychainItemNotFound) {
		t.Fatalf("data after delete error = %v", err)
	}
}
