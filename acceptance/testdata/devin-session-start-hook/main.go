package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

var receipt, inputPath, outsidePath, expectedInput string

type hookEvent struct {
	Event     string `json:"hook_event_name"`
	SessionID string `json:"session_id"`
	PromptID  string `json:"prompt_id"`
}
type hookReceipt struct {
	Event             string `json:"event"`
	SessionID         string `json:"session_id"`
	SessionHome       string `json:"session_home"`
	Executable        string `json:"executable"`
	ExecutableSHA256  string `json:"executable_sha256"`
	InputSHA256       string `json:"input_sha256"`
	InputWriteError   string `json:"input_write_error"`
	OutsideWriteError string `json:"outside_write_error"`
	ConfigWriteError  string `json:"config_write_error"`
	PID               int    `json:"pid"`
	PPID              int    `json:"ppid"`
}

func main() {
	if err := run(os.Stdin, os.Stdout); err != nil {
		os.Exit(1)
	}
}
func run(in io.Reader, _ io.Writer) error {
	body, err := readBounded(in, 16<<10, time.Second)
	if err != nil {
		return err
	}
	event, err := decodeEvent(body)
	if err != nil {
		return errors.New("invalid SessionStart event")
	}
	if expectedInput == "" {
		return errors.New("expected selected input is required")
	}
	input, err := readSelectedInput(inputPath)
	if err != nil {
		return err
	}
	if expectedInput != "" && !bytes.Equal(input, []byte(expectedInput)) {
		return errors.New("selected input mismatch")
	}
	inputErr := probeWrite(inputPath)
	outsideErr := probeWrite(outsidePath)
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	configErr := probeWrite(filepath.Join(home, ".config", "devin", "config.json"))
	if inputErr != "permission-denied" || outsideErr != "permission-denied" || configErr != "permission-denied" {
		return errors.New("required write denial missing")
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executableHash, err := digestExecutable(executable)
	if err != nil {
		return err
	}
	h := sha256.Sum256(input)
	r := hookReceipt{Event: event.Event, SessionID: event.SessionID, SessionHome: home, Executable: executable, ExecutableSHA256: hex.EncodeToString(executableHash[:]), PID: os.Getpid(), PPID: os.Getppid(), InputSHA256: hex.EncodeToString(h[:]), InputWriteError: inputErr, OutsideWriteError: outsideErr, ConfigWriteError: configErr}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return publish(data)
}

func digestExecutable(path string) ([32]byte, error) {
	var zero [32]byte
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return zero, err
	}
	f := os.NewFile(uintptr(fd), "hook-executable")
	defer f.Close()
	initial, err := f.Stat()
	if err != nil || !initial.Mode().IsRegular() || initial.Size() > 512<<20 {
		return zero, errors.New("executable identity invalid")
	}
	h := sha256.New()
	if _, err = io.CopyN(h, f, initial.Size()); err != nil {
		return zero, err
	}
	final, err := f.Stat()
	if err != nil || !os.SameFile(initial, final) || final.Size() != initial.Size() {
		return zero, errors.New("executable changed")
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}
func readSelectedInput(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("selected input path missing")
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), "selected-input")
	defer f.Close()
	initial, e := f.Stat()
	if e != nil || !initial.Mode().IsRegular() || initial.Size() > 1<<20 {
		return nil, errors.New("selected input invalid")
	}
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || int64(len(b)) > initial.Size() || int64(len(b)) > 1<<20 {
		return nil, errors.New("selected input invalid")
	}
	final, e := f.Stat()
	if e != nil || !os.SameFile(initial, final) || final.Size() != initial.Size() {
		return nil, errors.New("selected input changed")
	}
	return b, nil
}

func decodeEvent(data []byte) (hookEvent, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return hookEvent{}, err
	}
	if tok != json.Delim('{') {
		return hookEvent{}, errors.New("event is not object")
	}
	values := map[string]json.RawMessage{}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return hookEvent{}, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return hookEvent{}, errors.New("event key is not string")
		}
		if _, exists := values[key]; exists {
			return hookEvent{}, errors.New("duplicate event key")
		}
		var raw json.RawMessage
		if err = dec.Decode(&raw); err != nil {
			return hookEvent{}, err
		}
		values[key] = raw
	}
	if _, err = dec.Token(); err != nil {
		return hookEvent{}, err
	}
	var extra any
	if err = dec.Decode(&extra); err != io.EOF {
		return hookEvent{}, errors.New("event trailing data")
	}
	var event hookEvent
	if raw, ok := values["hook_event_name"]; !ok || json.Unmarshal(raw, &event.Event) != nil {
		return hookEvent{}, errors.New("event name missing")
	}
	if raw, ok := values["session_id"]; !ok || json.Unmarshal(raw, &event.SessionID) != nil {
		return hookEvent{}, errors.New("session id missing")
	}
	if _, ok := values["prompt_id"]; ok {
		return hookEvent{}, errors.New("prompt id present")
	}
	if event.Event != "SessionStart" || event.SessionID == "" {
		return hookEvent{}, errors.New("invalid SessionStart event")
	}
	return event, nil
}
func probeWrite(path string) string {
	if path == "" {
		return "missing"
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0600)
	if e == nil {
		f.Close()
		return "unexpected-success"
	}
	if errors.Is(e, os.ErrPermission) {
		return "permission-denied"
	}
	return "other-error"
}
func publish(data []byte) error {
	if receipt == "" {
		return errors.New("receipt path missing")
	}
	dir := filepath.Dir(receipt)
	tmp, err := os.OpenFile(filepath.Join(dir, ".hook-receipt.tmp"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(tmp.Name())
		if err != nil {
			return err
		}
		return closeErr
	}
	if err = os.Link(tmp.Name(), receipt); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	return os.Remove(tmp.Name())
}
func readBounded(in io.Reader, limit int64, timeout time.Duration) ([]byte, error) {
	ch := make(chan struct {
		b []byte
		e error
	}, 1)
	go func() {
		b, e := io.ReadAll(io.LimitReader(in, limit+1))
		ch <- struct {
			b []byte
			e error
		}{b, e}
	}()
	select {
	case r := <-ch:
		if r.e != nil {
			return nil, r.e
		}
		if int64(len(r.b)) > limit {
			return nil, errors.New("hook input too large")
		}
		return r.b, nil
	case <-time.After(timeout):
		return nil, errors.New("hook input deadline exceeded")
	}
}
