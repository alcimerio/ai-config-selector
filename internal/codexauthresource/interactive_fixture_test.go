package codexauthresource_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

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
