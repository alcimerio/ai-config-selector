package codexauthresource_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

const nativeResponsesBodyLimit = 2 << 20

func decodeNativeResponsesBody(body io.Reader, encoding string) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(body, nativeResponsesBodyLimit+1))
	if err != nil {
		return "", errors.New("cannot read Responses request body")
	}
	if len(raw) > nativeResponsesBodyLimit {
		return "", errors.New("Responses request body exceeds fixture limit")
	}
	var decoded io.Reader = bytes.NewReader(raw)
	switch encoding {
	case "":
	case "zstd":
		decoder, err := zstd.NewReader(decoded)
		if err != nil {
			return "", errors.New("cannot initialize Responses zstd decoder")
		}
		defer decoder.Close()
		decoded = decoder
	default:
		return "", fmt.Errorf("unsupported Responses request encoding %q", encoding)
	}
	contents, err := io.ReadAll(io.LimitReader(decoded, nativeResponsesBodyLimit+1))
	if err != nil {
		return "", errors.New("cannot decode Responses request body")
	}
	if len(contents) > nativeResponsesBodyLimit {
		return "", errors.New("decoded Responses request body exceeds fixture limit")
	}
	if !json.Valid(contents) {
		return "", errors.New("decoded Responses request body is not JSON")
	}
	return string(contents), nil
}

func nativeFunctionCallOutput(body, callID string) (string, error) {
	var request struct {
		Input []struct {
			Type   string `json:"type"`
			CallID string `json:"call_id"`
			Output string `json:"output"`
		} `json:"input"`
	}
	if err := json.Unmarshal([]byte(body), &request); err != nil {
		return "", errors.New("invalid Responses request JSON")
	}
	var matched string
	for _, item := range request.Input {
		if item.Type != "function_call_output" || item.CallID != callID {
			continue
		}
		if matched != "" || item.Output == "" {
			return "", errors.New("ambiguous or empty function output")
		}
		matched = item.Output
	}
	if matched == "" {
		return "", errors.New("matching function output is absent")
	}
	return matched, nil
}

func TestNativeFunctionCallOutputIgnoresEchoedCommandHistory(t *testing.T) {
	body := `{"input":[` +
		`{"type":"function_call","call_id":"acs-call-1","arguments":"outside-read-bad outside-write-bad"},` +
		`{"type":"function_call_output","call_id":"other","output":"wrong"},` +
		`{"type":"function_call_output","call_id":"acs-call-1","output":"Process exited with code 0\\nOutput:\\ncodex-native-tool-output private-ok outside-read-denied outside-write-denied descendant-pid:4242"}` +
		`]}`
	output, err := nativeFunctionCallOutput(body, "acs-call-1")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Process exited with code 0", "outside-read-denied", "outside-write-denied", "descendant-pid:4242"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("matching function output omitted %q", expected)
		}
	}
	if strings.Contains(output, "outside-read-bad") || strings.Contains(output, "outside-write-bad") {
		t.Fatal("function output extractor included echoed command history")
	}
}

func TestNativeFunctionCallOutputRejectsMissingEmptyAndDuplicateMatches(t *testing.T) {
	for _, body := range []string{
		`{"input":[]}`,
		`{"input":[{"type":"function_call_output","call_id":"acs-call-1","output":""}]}`,
		`{"input":[{"type":"function_call_output","call_id":"acs-call-1","output":"one"},{"type":"function_call_output","call_id":"acs-call-1","output":"two"}]}`,
		`not-json`,
	} {
		if _, err := nativeFunctionCallOutput(body, "acs-call-1"); err == nil {
			t.Fatalf("accepted invalid matching output in %q", body)
		}
	}
}

func TestDecodeNativeResponsesBodyAcceptsRawAndZstdJSON(t *testing.T) {
	body := []byte(`{"input":[{"type":"function_call_output","call_id":"acs-call-1","output":"fixture"}]}`)
	encoder, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatal(err)
	}
	compressed := encoder.EncodeAll(body, nil)
	encoder.Close()
	for _, test := range []struct {
		name, encoding string
		body           []byte
	}{
		{name: "raw JSON", body: body},
		{name: "zstd JSON", encoding: "zstd", body: compressed},
	} {
		t.Run(test.name, func(t *testing.T) {
			decoded, err := decodeNativeResponsesBody(bytes.NewReader(test.body), test.encoding)
			if err != nil {
				t.Fatal(err)
			}
			if decoded != string(body) {
				t.Fatalf("decoded body = %q", decoded)
			}
			if output, err := nativeFunctionCallOutput(decoded, "acs-call-1"); err != nil || output != "fixture" {
				t.Fatalf("decoded function output = (%q, %v)", output, err)
			}
		})
	}
}

func TestDecodeNativeResponsesBodyRejectsUnsupportedCorruptAndOversizedBodies(t *testing.T) {
	for _, test := range []struct {
		name, encoding string
		body           []byte
	}{
		{name: "unsupported encoding", encoding: "gzip", body: []byte(`{}`)},
		{name: "corrupt zstd", encoding: "zstd", body: []byte(`not-zstd`)},
		{name: "invalid JSON", body: []byte(`not-json`)},
		{name: "oversized raw body", body: bytes.Repeat([]byte(" "), nativeResponsesBodyLimit+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeNativeResponsesBody(bytes.NewReader(test.body), test.encoding); err == nil {
				t.Fatal("accepted invalid Responses request body")
			}
		})
	}
}
