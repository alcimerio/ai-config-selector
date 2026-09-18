// The fixture trampoline runs only inside the production ACS sandbox. It
// preserves all target arguments; it never substitutes print/ACP mode.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"time"
)

var target, memberDigest, endpoint, coordination string // fixed at build time
func write(path string, v any) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".phase-receipt-")
	if e != nil {
		return e
	}
	temporary := f.Name()
	defer os.Remove(temporary)
	if e = f.Chmod(0600); e != nil {
		_ = f.Close()
		return e
	}
	e = json.NewEncoder(f).Encode(v)
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	return os.Link(temporary, path) // atomic publication; existing destination refused
}

func member() error {
	f, e := os.Open(target)
	if e != nil {
		return e
	}
	defer f.Close()
	a, e := f.Stat()
	if e != nil || !a.Mode().IsRegular() || a.Size() > 512<<20 {
		return errors.New("member type/size")
	}
	h := sha256.New()
	if _, e = io.Copy(h, io.LimitReader(f, 512<<20+1)); e != nil {
		return e
	}
	z, e := f.Stat()
	if e != nil || !os.SameFile(a, z) || a.Size() != z.Size() || a.ModTime() != z.ModTime() || hex.EncodeToString(h.Sum(nil)) != memberDigest {
		return errors.New("member identity/digest")
	}
	return nil
}
func run() error {
	phase := ""
	for i, a := range [][]string{{"skills", "list", "--json"}, {"auth", "status"}, {"--respect-workspace-trust", "false"}} {
		if reflect.DeepEqual(os.Args[1:], a) {
			phase = []string{"skills", "auth", "attached"}[i]
		}
	}
	if phase == "" || !filepath.IsAbs(coordination) || endpoint == "" {
		return errors.New("unexpected target invocation")
	}
	if e := member(); e != nil {
		return e
	}
	if phase != "attached" && (os.Getenv("PROFILE_MCP_ARGUMENT") != "" || os.Getenv("PROFILE_MCP_SECRET") != "") {
		return errors.New("selected environment leaked to preflight")
	}
	if os.Getenv("ACS_NATIVE_MCP_ARGUMENT") != "" || os.Getenv("ACS_NATIVE_MCP_SECRET") != "" || os.Getenv("ACS_NATIVE_MCP_UNSELECTED") != "" {
		return errors.New("ambient source environment leaked")
	}
	ready := map[string]any{"PID": os.Getpid(), "Argv": os.Args[1:], "MemberSHA256": memberDigest, "SessionHome": os.Getenv("HOME")}
	if e := write(filepath.Join(coordination, phase+".ready"), ready); e != nil {
		return e
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		b, e := os.ReadFile(filepath.Join(coordination, phase+".release"))
		if e == nil {
			if string(b) != "release\n" {
				return errors.New("release contents")
			}
			break
		}
		if !os.IsNotExist(e) {
			return e
		}
		if time.Now().After(deadline) {
			return errors.New("phase release deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if e := member(); e != nil {
		return e
	}
	cmd := exec.Command(target, os.Args[1:]...)
	cmd.Env = os.Environ()
	for _, kv := range []string{"WINDSURF_API_SERVER_URL=" + endpoint, "CHISEL_MOCK_BACKEND_ADDR=" + endpoint} {
		key := kv[:len(kv)-len(endpoint)]
		var clean []string
		for _, old := range cmd.Env {
			if len(old) < len(key) || old[:len(key)] != key {
				clean = append(clean, old)
			}
		}
		cmd.Env = append(clean, kv)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if e := cmd.Start(); e != nil {
		return e
	}
	if e := write(filepath.Join(coordination, phase+".started"), map[string]any{"pid": cmd.Process.Pid, "parent": os.Getpid(), "argv": os.Args[1:]}); e != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return e
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	forced := false
	select {
	case err = <-done:
	case <-time.After(75 * time.Second):
		forced = true
		_ = cmd.Process.Kill()
		select {
		case err = <-done:
		case <-time.After(2 * time.Second):
			err = errors.New("child reap deadline")
		}
	}
	code := -1
	if cmd.ProcessState != nil {
		code = cmd.ProcessState.ExitCode()
	}
	if e := write(filepath.Join(coordination, phase+".done"), map[string]any{"pid": cmd.Process.Pid, "parent": os.Getpid(), "exitCode": code, "forced": forced}); e != nil {
		return e
	}
	if forced {
		return errors.New("forced target termination")
	}
	if err != nil {
		return err
	}
	return awaitInspection(filepath.Join(coordination, phase+".inspected"), 15*time.Second)
}
func awaitInspection(path string, limit time.Duration) error {
	deadline := time.Now().Add(limit)
	for {
		b, e := readInspection(path)
		if e == nil {
			if string(b) != "release\n" {
				return errors.New("inspection acknowledgement contents")
			}
			return nil
		}
		if !os.IsNotExist(e) {
			return errors.New("inspection acknowledgement read")
		}
		if time.Now().After(deadline) {
			return errors.New("inspection acknowledgement deadline")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "Devin fixture trampoline:", e)
		os.Exit(1)
	}
}

func readInspection(path string) ([]byte, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		if errors.Is(e, syscall.ENOENT) {
			return nil, os.ErrNotExist
		}
		return nil, errors.New("inspection acknowledgement open")
	}
	f := os.NewFile(uintptr(fd), "inspection")
	defer f.Close()
	a, e := f.Stat()
	if e != nil || !a.Mode().IsRegular() || a.Size() > int64(len("release\n")) {
		return nil, errors.New("inspection acknowledgement type or size")
	}
	b, e := io.ReadAll(io.LimitReader(f, int64(len("release\n")+1)))
	if e != nil || len(b) > len("release\n") {
		return nil, errors.New("inspection acknowledgement bound")
	}
	z, e := f.Stat()
	if e != nil || !os.SameFile(a, z) || a.Size() != z.Size() || a.Mode() != z.Mode() || !a.ModTime().Equal(z.ModTime()) {
		return nil, errors.New("inspection acknowledgement changed")
	}
	return b, nil
}
