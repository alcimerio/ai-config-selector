package profilerepo_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/alcimerio/ai-config-selector/internal/profileinspect"
	"golang.org/x/sys/unix"
)

func TestPassiveInspectionIgnoresLiveAndMalformedTransactionState(t *testing.T) {
	home := t.TempDir()
	directory := filepath.Join(home, ".acs", "profiles")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"example.json":                []byte(`{"version":2,"name":"example","target":"devin","categories":{}}`),
		".profile-transaction-plan":   []byte("malformed metadata"),
		".profile-transaction-future": []byte("unknown future metadata"),
		".profile-transaction-lock":   nil,
	}
	before := map[string]os.FileInfo{}
	for name, data := range files {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		before[name] = info
	}
	lock, err := os.OpenFile(filepath.Join(directory, ".profile-transaction-lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		list := (profileinspect.Store{Home: home}).List()
		show := (profileinspect.Store{Home: home}).Show("example")
		if len(list.Entries) != 1 || len(show.Entries) != 1 || show.Entries[0].Status != "valid" {
			t.Fatal("transaction state affected passive inspection")
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(files) {
		t.Fatal("inspection changed entries", err)
	}
	for name, want := range files {
		path := filepath.Join(directory, name)
		got, err := os.ReadFile(path)
		if err != nil || !reflect.DeepEqual(string(got), string(want)) {
			t.Fatal("inspection changed bytes", err)
		}
		info, err := os.Stat(path)
		if err != nil || !os.SameFile(before[name], info) || info.Mode() != before[name].Mode() || info.ModTime() != before[name].ModTime() {
			t.Fatal("inspection changed metadata", err)
		}
	}
}
