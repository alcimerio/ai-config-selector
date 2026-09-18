package acceptance_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const devinSelectedSecret = "acs selected synthetic secret"

var errDevinTerminalEvidenceCap = errors.New("terminal evidence cap")

func devinRejectSecret(b []byte) error {
	if bytes.Contains(b, []byte(devinSelectedSecret)) {
		return errors.New("resolved selected secret serialized")
	}
	return nil
}

func devinShellLiteral(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }

// Scan the actual HOME through no-follow descriptors. The receipt contains only
// counts; filenames and file bytes never enter diagnostics. Symlinks are not
// followed: their literal target is checked separately, not claimed as scanned.
type devinSecrecyReceipt struct{ Files, Directories, Links, Bytes int }

func devinInspectState(root string) (devinSecrecyReceipt, error) {
	var result devinSecrecyReceipt
	fd, e := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return result, errors.New("state root unavailable")
	}
	f := os.NewFile(uintptr(fd), "state")
	defer f.Close()
	var walk func(*os.File, int) error
	walk = func(dir *os.File, depth int) error {
		result.Directories++
		if depth > 16 || result.Directories > 256 {
			return errors.New("state directory bound")
		}
		for {
			entries, e := dir.ReadDir(32)
			if e != nil && e != io.EOF {
				return errors.New("state directory read")
			}
			for _, entry := range entries {
				if devinRejectSecret([]byte(entry.Name())) != nil {
					return errors.New("secret in state name")
				}
				if entry.Type()&os.ModeSymlink != 0 {
					target := make([]byte, 4096)
					n, err := unix.Readlinkat(int(dir.Fd()), entry.Name(), target)
					if err != nil || n == len(target) {
						return errors.New("state link bound")
					}
					if err = devinRejectSecret(target[:n]); err != nil {
						return err
					}
					result.Links++
					if result.Links > 256 {
						return errors.New("state link count")
					}
					continue
				}
				flags := unix.O_RDONLY | unix.O_NONBLOCK | unix.O_NOFOLLOW | unix.O_CLOEXEC
				if entry.IsDir() {
					flags |= unix.O_DIRECTORY
				}
				childFD, err := unix.Openat(int(dir.Fd()), entry.Name(), flags, 0)
				if err != nil {
					return errors.New("state entry unavailable")
				}
				child := os.NewFile(uintptr(childFD), "state-entry")
				before, err := child.Stat()
				if err == nil && before.IsDir() {
					err = walk(child, depth+1)
				} else if err == nil {
					if !before.Mode().IsRegular() || before.Size() > 4<<20 {
						err = errors.New("state entry type or size")
					} else {
						result.Files++
						var b []byte
						b, err = io.ReadAll(io.LimitReader(child, 4<<20+1))
						result.Bytes += len(b)
						if err == nil && (len(b) > 4<<20 || result.Bytes > 32<<20 || result.Files > 1024) {
							err = errors.New("state byte or file bound")
						}
						if err == nil {
							err = devinRejectSecret(b)
						}
					}
				}
				after, statErr := child.Stat()
				closeErr := child.Close()
				if err != nil {
					return err
				}
				if statErr != nil || closeErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || (!before.IsDir() && (before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()))) {
					return errors.New("state entry changed")
				}
			}
			if e == io.EOF {
				return nil
			}
		}
	}
	e = walk(f, 0)
	return result, e
}

func devinInspectGenerated(home string, launchers ...string) error {
	for _, rel := range []string{".config/devin/config.json", ".config/devin/mcp_config.json", ".acs/mcp/recipes.json"} {
		p := filepath.Join(home, rel)
		st, e := os.Lstat(p)
		if e != nil || !st.Mode().IsRegular() || st.Size() == 0 {
			return errors.New("generated configuration absent")
		}
	}
	if e := devinGeneratedSemantics(home, launchers...); e != nil {
		return e
	}
	_, e := devinInspectState(home)
	return e
}

// Preserve only a sentinel-sized suffix so split terminal writes cannot evade
// the check; neither terminal contents nor the suffix become diagnostics.
type devinSecretStream struct{ tail []byte }

func (s *devinSecretStream) feed(b []byte) error {
	combined := append(append([]byte{}, s.tail...), b...)
	if err := devinRejectSecret(combined); err != nil {
		return err
	}
	n := len(devinSelectedSecret) - 1
	if len(combined) > n {
		combined = combined[len(combined)-n:]
	}
	s.tail = append(s.tail[:0], combined...)
	return nil
}

// devinTerminalEvidence drains terminal bytes while retaining only a bounded,
// sanitized diagnostic excerpt. Secret detection runs before appending each
// chunk, including across chunk boundaries.
type devinTerminalEvidence struct {
	mu              sync.Mutex
	secret          devinSecretStream
	sanitizedSecret devinSecretStream
	bytes           int
	chunks          int
	unsafe          bool
	text            []byte
}

func (e *devinTerminalEvidence) feed(b []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.secret.feed(b); err != nil {
		e.unsafe = true
		return err
	}
	clean := make([]byte, 0, len(b))
	for _, c := range b {
		if c >= 0x20 && c != 0x7f || c == '\n' || c == '\r' || c == '\t' {
			clean = append(clean, c)
		}
	}
	if err := e.sanitizedSecret.feed(clean); err != nil {
		e.unsafe = true
		return err
	}
	if len(b) > (1<<20)-e.bytes {
		e.bytes = 1 << 20
		e.unsafe = true
		return errDevinTerminalEvidenceCap
	}
	e.bytes += len(b)
	e.chunks++
	if len(clean) > (16<<10)-len(e.text) {
		clean = clean[:(16<<10)-len(e.text)]
	}
	e.text = append(e.text, clean...)
	return nil
}

func (e *devinTerminalEvidence) snapshot() (bytes, chunks int, unsafe bool, text string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.bytes, e.chunks, e.unsafe, string(e.text)
}

// drainDevinFailureTerminal consumes both the read result and every queued
// chunk. A read EOF/EIO can be queued before the reader's final bytes, so it
// is status, not permission to stop consuming. The caller supplies the
// platform-specific natural-read predicate.
func drainDevinFailureTerminal(chunks <-chan []byte, readDone <-chan error, evidence *devinTerminalEvidence, naturalRead func(error) bool) string {
	deadline := time.NewTimer(500 * time.Millisecond)
	defer deadline.Stop()
	readStatus := ""
	for chunks != nil {
		select {
		case chunk, ok := <-chunks:
			if !ok {
				if readStatus != "" {
					return readStatus
				}
				return "closed"
			}
			if e := evidence.feed(chunk); e != nil {
				if errors.Is(e, errDevinTerminalEvidenceCap) {
					return "terminal-cap"
				}
				return "secret-detected"
			}
		case e := <-readDone:
			if readStatus == "" {
				if naturalRead(e) {
					readStatus = "eof"
				} else {
					readStatus = "read-failed"
				}
			}
			readDone = nil
		case <-deadline.C:
			return "drain-timeout"
		}
	}
	return readStatus
}

func TestDevinTerminalEvidenceIsBoundedAndSecretSafe(t *testing.T) {
	var evidence devinTerminalEvidence
	if err := evidence.feed([]byte("prefix-acs selected ")); err != nil {
		t.Fatal(err)
	}
	if err := evidence.feed([]byte("synthetic secret-suffix")); err == nil {
		t.Fatal("split secret was accepted")
	}
	bytes, chunks, unsafe, _ := evidence.snapshot()
	if bytes != len("prefix-acs selected ") || chunks != 1 || !unsafe {
		t.Fatalf("evidence=%d bytes/%d chunks unsafe=%v", bytes, chunks, unsafe)
	}
}

func TestDevinTerminalEvidenceSuppressesSecretReconstructedBySanitizing(t *testing.T) {
	var evidence devinTerminalEvidence
	if err := evidence.feed([]byte("acs selected \x01synthetic secret")); err == nil {
		t.Fatal("sanitized secret was accepted")
	}
	_, _, unsafe, text := evidence.snapshot()
	if !unsafe || strings.Contains(text, devinSelectedSecret) {
		t.Fatalf("unsafe=%v text=%q", unsafe, text)
	}
}

func TestDevinTerminalEvidenceUsesSameSanitizedBytesInFormattedDiagnostic(t *testing.T) {
	var evidence devinTerminalEvidence
	if err := evidence.feed([]byte("acs selected\n")); err != nil {
		t.Fatal(err)
	}
	if err := evidence.feed([]byte("\tsynthetic\r secret")); err != nil {
		t.Fatal(err)
	}
	_, _, unsafe, text := evidence.snapshot()
	formatted := fmt.Sprintf("terminal=%q", text)
	if unsafe || strings.Contains(formatted, devinSelectedSecret) || !strings.Contains(formatted, `\n`) || !strings.Contains(formatted, `\t`) || !strings.Contains(formatted, `\r`) {
		t.Fatalf("unsafe=%v text=%q formatted=%q", unsafe, text, formatted)
	}
}

func TestDevinTerminalEvidenceCapsFailedDrain(t *testing.T) {
	chunks := make(chan []byte, 1)
	readDone := make(chan error, 1)
	chunks <- bytes.Repeat([]byte{'x'}, (1<<20)+1)
	close(chunks)
	var evidence devinTerminalEvidence
	if got := drainDevinFailureTerminal(chunks, readDone, &evidence, func(error) bool { return true }); got != "terminal-cap" {
		t.Fatalf("drain status=%q", got)
	}
	bytes, _, unsafe, _ := evidence.snapshot()
	if bytes != 1<<20 || !unsafe {
		t.Fatalf("bytes=%d unsafe=%v", bytes, unsafe)
	}
}

func TestDevinTerminalEvidenceSupportsConcurrentQueuedOutput(t *testing.T) {
	var evidence devinTerminalEvidence
	const writers = 8
	const writes = 64
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < writes; j++ {
				if err := evidence.feed([]byte("safe terminal progress")); err != nil {
					t.Errorf("feed: %v", err)
					return
				}
			}
		}()
	}
	for i := 0; i < 16; i++ {
		_, _, _, _ = evidence.snapshot()
	}
	wg.Wait()
	bytes, chunks, unsafe, _ := evidence.snapshot()
	if unsafe || chunks != writers*writes || bytes != chunks*len("safe terminal progress") {
		t.Fatalf("evidence=%d bytes/%d chunks unsafe=%v", bytes, chunks, unsafe)
	}
}

func TestDevinFailureDrainConsumesQueuedOutputAfterEOF(t *testing.T) {
	chunks := make(chan []byte, 3)
	readDone := make(chan error, 1)
	chunks <- []byte("prefix-acs selected ")
	readDone <- io.EOF
	chunks <- []byte("synthetic secret-suffix")
	close(chunks)
	var evidence devinTerminalEvidence
	if got := drainDevinFailureTerminal(chunks, readDone, &evidence, func(e error) bool { return errors.Is(e, io.EOF) }); got != "secret-detected" {
		t.Fatalf("drain status=%q", got)
	}
	bytes, chunksSeen, unsafe, _ := evidence.snapshot()
	if bytes != len("prefix-acs selected ") || chunksSeen != 1 || !unsafe {
		t.Fatalf("evidence=%d bytes/%d chunks unsafe=%v", bytes, chunksSeen, unsafe)
	}
}

func devinRequestMetadata(r *http.Request) error {
	for _, v := range []string{r.RequestURI, r.Host, r.URL.String()} {
		decoded, e := url.QueryUnescape(v)
		if e != nil {
			decoded = v
		}
		if devinRejectSecret([]byte(v)) != nil || devinRejectSecret([]byte(decoded)) != nil {
			return errors.New("resolved selected secret serialized")
		}
	}
	for k, values := range r.Header {
		if e := devinRejectSecret([]byte(k)); e != nil {
			return e
		}
		for _, v := range values {
			if e := devinRejectSecret([]byte(v)); e != nil {
				return e
			}
		}
	}
	return nil
}
func devinReadRegular(path string) ([]byte, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, errors.New("generated configuration open")
	}
	f := os.NewFile(uintptr(fd), "generated")
	defer f.Close()
	a, e := f.Stat()
	if e != nil || !a.Mode().IsRegular() || a.Size() > 1<<20 {
		return nil, errors.New("generated configuration shape")
	}
	b, e := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if e != nil || len(b) > 1<<20 {
		return nil, errors.New("generated configuration bound")
	}
	z, e := f.Stat()
	if e != nil || !os.SameFile(a, z) || a.Size() != z.Size() || a.Mode() != z.Mode() || !a.ModTime().Equal(z.ModTime()) {
		return nil, errors.New("generated configuration changed")
	}
	if e = devinRejectSecret(b); e != nil {
		return nil, e
	}
	return b, nil
}
func devinGeneratedSemantics(home string, launchers ...string) error {
	read := func(rel string, v any) error {
		b, e := devinReadRegular(filepath.Join(home, rel))
		if e != nil {
			return e
		}
		if json.Unmarshal(b, v) != nil {
			return errors.New("generated configuration JSON")
		}
		return nil
	}
	var user map[string]any
	if e := read(".config/devin/config.json", &user); e != nil {
		return e
	}
	expected := map[string]any{"read_config_from": map[string]any{"cursor": false, "windsurf": false, "claude": false, "opencode": false, "zed": false}}
	if !reflect.DeepEqual(user, expected) {
		return errors.New("generated import controls mismatch")
	}
	var cfg map[string]map[string]map[string]any
	if e := read(".config/devin/mcp_config.json", &cfg); e != nil {
		return e
	}
	servers := cfg["mcpServers"]
	server := servers["fixture"]
	command, ok := server["command"].(string)
	if len(launchers) > 0 {
		expected, e := filepath.EvalSymlinks(launchers[0])
		if e != nil || command != expected {
			return errors.New("generated launcher identity mismatch")
		}
	}

	if len(cfg) != 1 || len(servers) != 1 || len(server) != 4 || !ok || !filepath.IsAbs(command) || server["type"] != "stdio" || !reflect.DeepEqual(server["args"], []any{"--acs-mcp-launch", home, "fixture"}) || !reflect.DeepEqual(server["disabledTools"], []any{"acs_blocked_echo"}) {
		return errors.New("generated MCP projection mismatch")
	}
	var recipes []struct {
		ID       string                         `json:"id"`
		Home     string                         `json:"sessionHome"`
		Env      []string                       `json:"environmentNames"`
		Disabled []string                       `json:"disabledTools"`
		Args     []struct{ Kind, Value string } `json:"arguments"`
	}
	if e := read(".acs/mcp/recipes.json", &recipes); e != nil {
		return e
	}
	if len(recipes) != 1 {
		return errors.New("generated recipe count")
	}
	r := recipes[0]
	if r.ID != "fixture" || r.Home != home || !reflect.DeepEqual(r.Env, []string{"PROFILE_MCP_ARGUMENT", "PROFILE_MCP_SECRET"}) || !reflect.DeepEqual(r.Disabled, []string{"acs_blocked_echo"}) || len(r.Args) != 2 || r.Args[0].Kind != "environment" || r.Args[0].Value != "PROFILE_MCP_ARGUMENT" || r.Args[1].Kind != "path" || !filepath.IsAbs(r.Args[1].Value) {
		return errors.New("generated recipe references mismatch")
	}
	return nil
}

// Shapes independently recognized by the exact pinned CLI in case
// external-mcp-importers-4d_pzihx. That probe did not prove clean server launch.
func devinSeedProjectImports(workspace, command string) error {
	standard := func(name string) any {
		return map[string]any{"mcpServers": map[string]any{name: map[string]any{"command": command, "args": []string{}, "env": map[string]string{}}}}
	}
	fixtures := map[string]any{
		".cursor/mcp.json":   standard("acs-import-cursor"),
		".mcp.json":          standard("acs-import-claude"),
		"opencode.json":      map[string]any{"mcp": map[string]any{"acs-import-opencode": map[string]any{"type": "local", "command": []string{command}, "environment": map[string]string{}, "enabled": true}}},
		".zed/settings.json": map[string]any{"context_servers": map[string]any{"acs-import-zed": map[string]any{"command": command, "args": []string{}, "env": map[string]string{}}}},
	}
	for rel, v := range fixtures {
		b, e := json.Marshal(v)
		if e != nil {
			return e
		}
		p := filepath.Join(workspace, rel)
		if e = os.MkdirAll(filepath.Dir(p), 0700); e != nil {
			return e
		}
		f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(b)
		ce := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
	}
	return nil
}
