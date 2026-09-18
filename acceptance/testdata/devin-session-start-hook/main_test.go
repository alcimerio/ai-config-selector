package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func witnessFixture(t *testing.T) {
	t.Helper()
	oldInput, oldOutside, oldReceipt, oldExpected := inputPath, outsidePath, receipt, expectedInput
	t.Cleanup(func() { inputPath, outsidePath, receipt, expectedInput = oldInput, oldOutside, oldReceipt, oldExpected })
	dir := t.TempDir()
	inputPath, outsidePath, receipt, expectedInput = filepath.Join(dir, "input"), filepath.Join(dir, "outside"), filepath.Join(dir, "receipt.json"), "selected\n"
	home := filepath.Join(dir, "home")
	cfg := filepath.Join(home, ".config", "devin", "config.json")
	if err := os.MkdirAll(filepath.Dir(cfg), 0700); err != nil {
		t.Fatal(err)
	}
	for p, content := range map[string]string{inputPath: expectedInput, outsidePath: "outside", cfg: "protected"} {
		if err := os.WriteFile(p, []byte(content), 0400); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
}
func requireNoReceipt(t *testing.T) {
	t.Helper()
	if _, err := os.Lstat(receipt); !os.IsNotExist(err) {
		t.Fatalf("unexpected receipt or stat error: %v", err)
	}
}

const validEvent = `{"hook_event_name":"SessionStart","session_id":"s1"}`

func TestRunWitnessUsesOperationsAndAtomicReceipt(t *testing.T) {
	witnessFixture(t)
	if err := run(bytes.NewBufferString(validEvent), &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(receipt)
	if err != nil {
		t.Fatal(err)
	}
	var got hookReceipt
	if err = json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.Event != "SessionStart" || got.SessionID != "s1" || got.PID <= 0 || got.PPID <= 0 || got.InputSHA256 == "" || got.InputWriteError != "permission-denied" || got.OutsideWriteError != "permission-denied" || got.ConfigWriteError != "permission-denied" {
		t.Fatalf("incomplete receipt: %#v", got)
	}
	if err = run(bytes.NewBufferString(validEvent), &bytes.Buffer{}); err == nil {
		t.Fatal("repeated publication succeeded")
	}
	after, err := os.ReadFile(receipt)
	if err != nil || !bytes.Equal(data, after) {
		t.Fatal("repeated publication changed receipt", err)
	}
}
func TestRunWitnessRejectsInvalidEvents(t *testing.T) {
	cases := map[string]string{
		"wrong-event":       `{"hook_event_name":"BeforeTool","session_id":"s"}`,
		"duplicate-event":   `{"hook_event_name":"Wrong","hook_event_name":"SessionStart","session_id":"s"}`,
		"duplicate-session": `{"hook_event_name":"SessionStart","session_id":"a","session_id":"s"}`,
		"prompt":            `{"hook_event_name":"SessionStart","session_id":"s","prompt_id":"p"}`,
		"null-prompt":       `{"hook_event_name":"SessionStart","session_id":"s","prompt_id":null}`,
		"empty-prompt":      `{"hook_event_name":"SessionStart","session_id":"s","prompt_id":""}`,
		"missing-session":   `{"hook_event_name":"SessionStart"}`,
		"null-session":      `{"hook_event_name":"SessionStart","session_id":null}`,
		"empty-session":     `{"hook_event_name":"SessionStart","session_id":""}`,
		"malformed":         `{"hook_event_name":`,
		"trailing":          validEvent + `{}`,
	}
	for name, event := range cases {
		t.Run(name, func(t *testing.T) {
			witnessFixture(t)
			err := run(bytes.NewBufferString(event), &bytes.Buffer{})
			if err == nil || err.Error() != "invalid SessionStart event" {
				t.Fatalf("expected event rejection, got %v", err)
			}
			requireNoReceipt(t)
		})
	}
}
func TestRunWitnessRequiresExpectedInput(t *testing.T) {
	witnessFixture(t)
	expectedInput = ""
	err := run(bytes.NewBufferString(validEvent), &bytes.Buffer{})
	if err == nil || err.Error() != "expected selected input is required" {
		t.Fatalf("expected missing expectation error, got %v", err)
	}
	requireNoReceipt(t)
}
func TestRunWitnessRejectsWrongSelectedInput(t *testing.T) {
	witnessFixture(t)
	expectedInput = "different\n"
	err := run(bytes.NewBufferString(validEvent), &bytes.Buffer{})
	if err == nil || err.Error() != "selected input mismatch" {
		t.Fatalf("expected input mismatch, got %v", err)
	}
	requireNoReceipt(t)
}
func TestWitnessReadBounds(t *testing.T) {
	for _, reader := range []struct {
		name  string
		limit int64
		read  func(string) error
	}{
		{"input", 1 << 20, func(p string) error { _, e := readSelectedInput(p); return e }},
		{"executable", 512 << 20, func(p string) error { _, e := digestExecutable(p); return e }},
	} {
		t.Run(reader.name, func(t *testing.T) {
			dir := t.TempDir()
			regular := filepath.Join(dir, "regular")
			if e := os.WriteFile(regular, []byte("regular"), 0600); e != nil {
				t.Fatal(e)
			}
			if e := reader.read(regular); e != nil {
				t.Fatal("valid regular file refused", e)
			}
			link := filepath.Join(dir, "link")
			if e := os.Symlink(regular, link); e != nil {
				t.Fatal(e)
			}
			fifo := filepath.Join(dir, "fifo")
			if e := syscall.Mkfifo(fifo, 0600); e != nil {
				t.Fatal(e)
			}
			large := filepath.Join(dir, "large")
			f, e := os.Create(large)
			if e != nil {
				t.Fatal(e)
			}
			e = f.Truncate(reader.limit + 1)
			closeErr := f.Close()
			if e != nil || closeErr != nil {
				t.Fatal(e, closeErr)
			}
			for name, p := range map[string]string{"symlink": link, "fifo": fifo, "directory": dir, "oversize": large, "missing": filepath.Join(dir, "missing")} {
				t.Run(name, func(t *testing.T) {
					done := make(chan error, 1)
					go func() { done <- reader.read(p) }()
					select {
					case e := <-done:
						if e == nil {
							t.Fatal("invalid file accepted")
						}
					case <-time.After(time.Second):
						t.Fatal("reader did not reject within deadline")
					}
				})
			}
		})
	}
}
func TestWitnessHeldStdinBound(t *testing.T) {
	r, w := io.Pipe()
	defer r.Close()
	defer w.Close()
	go func() { _, _ = w.Write([]byte(validEvent)) }()
	start := time.Now()
	if _, err := readBounded(r, 1024, 10*time.Millisecond); err == nil || err.Error() != "hook input deadline exceeded" {
		t.Fatalf("held input not refused by deadline: %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("stdin deadline exceeded generous bound")
	}
}
