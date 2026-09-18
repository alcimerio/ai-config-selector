// Package main is a bounded synthetic MCP witness, never an account client.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

var forbiddenPath, evidenceBase string // fixed outside all grants at build time

func denied(e error) bool { return errors.Is(e, syscall.EACCES) || errors.Is(e, syscall.EPERM) }

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

func exclusive(path string, value any) error {
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	e = json.NewEncoder(f).Encode(value)
	c := f.Close()
	if e != nil {
		return e
	}
	return c
}
func journalRequest(r request) map[string]any {
	event := map[string]any{"event": "request", "method": r.Method, "params": r.Params}
	if len(r.ID) != 0 {
		event["id"] = json.RawMessage(r.ID)
	}
	return event
}
func run(in io.Reader, out io.Writer, journal io.Writer, effect string) error {
	scan := bufio.NewScanner(io.LimitReader(in, 256*1024+1))
	scan.Buffer(make([]byte, 4096), 32768)
	total, count := 0, 0
	initialized, ready, listed, called := false, false, false, false
	seen := map[string]bool{}
	record := func(value any) error { return json.NewEncoder(journal).Encode(value) }
	for scan.Scan() {
		line := scan.Bytes()
		total += len(line) + 1
		count++
		if total > 256*1024 || count > 16 {
			return errors.New("MCP input cap")
		}
		var r request
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		if e := dec.Decode(&r); e != nil {
			return e
		}
		var extra any
		if dec.Decode(&extra) != io.EOF {
			return errors.New("trailing JSON")
		}
		if r.JSONRPC != "2.0" {
			return errors.New("JSONRPC version")
		}
		if e := record(journalRequest(r)); e != nil {
			return e
		}
		if r.Method == "notifications/initialized" {
			if !initialized || ready || len(r.ID) != 0 {
				return errors.New("initialized ordering")
			}
			ready = true
			continue
		}
		if len(r.ID) == 0 || string(r.ID) == "null" || seen[string(r.ID)] {
			return errors.New("missing/duplicate ID")
		}
		seen[string(r.ID)] = true
		var result any
		switch r.Method {
		case "initialize":
			var p struct {
				ProtocolVersion string          `json:"protocolVersion"`
				Capabilities    json.RawMessage `json:"capabilities"`
				ClientInfo      json.RawMessage `json:"clientInfo"`
			}
			if json.Unmarshal(r.Params, &p) != nil || initialized || p.ProtocolVersion != "2025-11-25" {
				return errors.New("initialize contract")
			}
			initialized = true
			result = map[string]any{"protocolVersion": p.ProtocolVersion, "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "acs-native-witness", "version": "1"}}
		case "tools/list":
			if !ready || listed || called {
				return errors.New("listing ordering")
			}
			listed = true
			schema := map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}
			result = map[string]any{"tools": []any{map[string]any{"name": "acs_allowed_echo", "description": "Write synthetic test receipt", "inputSchema": schema}, map[string]any{"name": "acs_blocked_echo", "description": "Must be filtered by ACS", "inputSchema": schema}}}
		case "tools/call":
			var p struct {
				Name      string          `json:"name"`
				Arguments map[string]any  `json:"arguments"`
				Meta      json.RawMessage `json:"_meta"`
			}
			dec := json.NewDecoder(bytes.NewReader(r.Params))
			dec.DisallowUnknownFields()
			if dec.Decode(&p) != nil || !ready || !listed || called || p.Name != "acs_allowed_echo" || p.Arguments == nil || len(p.Arguments) != 0 {
				return errors.New("call contract")
			}
			called = true
			child := exec.Command(os.Args[0], "--descendant", effect+".descendant", os.Args[2])
			child.Stdin = nil
			child.Stdout = nil
			child.Stderr = nil
			if e := child.Start(); e != nil {
				return e
			}
			readyDeadline := time.Now().Add(time.Second)
			for {
				if _, e := os.Stat(effect + ".descendant"); e == nil {
					break
				}
				if time.Now().After(readyDeadline) {
					return errors.New("descendant readiness deadline")
				}
				time.Sleep(10 * time.Millisecond)
			}
			// The descendant intentionally outlives server EOF; production Session
			// cleanup must settle it. Its own receipt and heartbeat are independent.
			if e := record(map[string]any{"event": "descendant-started", "pid": child.Process.Pid}); e != nil {
				return e
			}

			if e := exclusive(effect, map[string]any{"tool": p.Name, "arguments": p.Arguments, "pid": os.Getpid(), "parent": os.Getppid(), "result": "ACS_MCP_TOOL_OK"}); e != nil {
				return e
			}
			result = map[string]any{"content": []any{map[string]any{"type": "text", "text": "ACS_MCP_TOOL_OK"}}, "isError": false}
		default:
			return errors.New("unexpected MCP method")
		}
		response := map[string]any{"jsonrpc": "2.0", "id": r.ID, "result": result}
		b, e := json.Marshal(response)
		if e != nil {
			return e
		}
		if len(b) > 32768 {
			return errors.New("output cap")
		}
		b = append(b, '\n')
		n, e := out.Write(b)
		if e != nil {
			return e
		}
		if n != len(b) {
			return io.ErrShortWrite
		}
		if e = record(map[string]any{"event": "response-complete", "method": r.Method, "id": r.ID, "result": result}); e != nil {
			return e
		}
	}
	if e := scan.Err(); e != nil {
		return e
	}
	if !called {
		return errors.New("EOF before tool effect")
	}
	return record(map[string]any{"event": "stdin-eof", "called": called})
}
func main() {
	if len(os.Args) == 4 && os.Args[1] == "--descendant" {
		receipt := os.Args[2]
		if os.Getenv("PROFILE_MCP_ARGUMENT") != "acs selected argument" || os.Getenv("PROFILE_MCP_SECRET") != "acs selected synthetic secret" || os.Getenv("ACS_NATIVE_MCP_UNSELECTED") != "" || os.Getenv("ACS_NATIVE_MCP_ARGUMENT") != "" || os.Getenv("ACS_NATIVE_MCP_SECRET") != "" {
			os.Exit(7)
		}
		b, e := os.ReadFile(os.Args[3])
		if e != nil || string(b) != "acs selected input\n" {
			os.Exit(7)
		}
		f, e := os.OpenFile(os.Args[3], os.O_WRONLY|os.O_APPEND, 0)
		if !denied(e) {
			if f != nil {
				_ = f.Close()
			}
			os.Exit(7)
		}
		if _, e = os.ReadFile(forbiddenPath); !denied(e) {
			os.Exit(7)
		}
		f, e = os.OpenFile(forbiddenPath+".descendant-effect", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if !denied(e) {
			if f != nil {
				_ = f.Close()
			}
			os.Exit(7)
		}
		if e := exclusive(receipt, map[string]any{"pid": os.Getpid(), "parent": os.Getppid(), "startedUnixNano": time.Now().UnixNano(), "inheritedEnvironment": true, "inputRead": true, "inputReadOnly": true, "outsideDenied": true}); e != nil {
			os.Exit(4)
		}
		deadline := time.Now().Add(45 * time.Second)
		for time.Now().Before(deadline) {
			if e := os.WriteFile(receipt+".heartbeat", []byte(fmt.Sprint(time.Now().UnixNano())), 0600); e != nil {
				os.Exit(5)
			}
			time.Sleep(100 * time.Millisecond)
		}
		os.Exit(6) // watchdog expiry is failure, not successful cleanup
	}
	if len(os.Args) != 3 || os.Args[1] != "acs selected argument" || !filepath.IsAbs(os.Args[2]) {
		fmt.Fprintln(os.Stderr, "selected argv mismatch")
		os.Exit(2)
	}
	if os.Getenv("PROFILE_MCP_ARGUMENT") != "acs selected argument" || os.Getenv("PROFILE_MCP_SECRET") != "acs selected synthetic secret" || os.Getenv("ACS_NATIVE_MCP_ARGUMENT") != "" || os.Getenv("ACS_NATIVE_MCP_SECRET") != "" || os.Getenv("ACS_NATIVE_MCP_UNSELECTED") != "" {
		fmt.Fprintln(os.Stderr, "selected environment mismatch")
		os.Exit(2)
	}
	input, e := os.Open(os.Args[2])
	if e != nil {
		os.Exit(2)
	}
	b, e := io.ReadAll(io.LimitReader(input, 1025))
	_ = input.Close()
	if e != nil || string(b) != "acs selected input\n" {
		fmt.Fprintln(os.Stderr, "selected input mismatch")
		os.Exit(2)
	}
	base := evidenceBase
	if !filepath.IsAbs(base) {
		os.Exit(2)
	}
	writable, e := os.OpenFile(os.Args[2], os.O_WRONLY|os.O_APPEND, 0)
	if !denied(e) {
		if writable != nil {
			_ = writable.Close()
		}
		fmt.Fprintln(os.Stderr, "read-only input writable")
		os.Exit(2)
	}
	if forbiddenPath == "" {
		os.Exit(2)
	}
	if _, e = os.ReadFile(forbiddenPath); !denied(e) {
		fmt.Fprintln(os.Stderr, "outside read allowed")
		os.Exit(2)
	}
	outside, e := os.OpenFile(forbiddenPath+".effect", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if !denied(e) {
		if outside != nil {
			_ = outside.Close()
		}
		fmt.Fprintln(os.Stderr, "outside write allowed")
		os.Exit(2)
	}
	if e = exclusive(base+".selection", map[string]any{"inputReadOnly": true, "outsideReadDenied": true, "outsideWriteDenied": true, "argvMatched": true, "inputMatched": true, "selectedEnvironmentMatched": true, "ambientEnvironmentAbsent": true, "pid": os.Getpid(), "parent": os.Getppid()}); e != nil {
		os.Exit(2)
	}
	timer := time.AfterFunc(45*time.Second, func() { fmt.Fprintln(os.Stderr, "MCP witness deadline"); os.Exit(3) })
	defer timer.Stop()
	journal, e := os.OpenFile(base+".journal", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		os.Exit(2)
	}
	e = run(os.Stdin, os.Stdout, journal, base+".effect")
	closeErr := journal.Close()
	if e == nil {
		e = closeErr
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
