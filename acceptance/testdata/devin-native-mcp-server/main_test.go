package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRunJournalOmitsNotificationIDAndKeepsRequestID(t *testing.T) {
	input := strings.NewReader(`{"jsonrpc":"2.0","id":"req-1","method":"initialize","params":{"protocolVersion":"2025-11-25"}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
`)
	var journal bytes.Buffer
	if err := run(input, &bytes.Buffer{}, &journal, t.TempDir()+"/effect"); err == nil || err.Error() != "EOF before tool effect" {
		t.Fatalf("incomplete witness exchange error = %v, want EOF before tool effect", err)
	}
	decoder := json.NewDecoder(&journal)
	var requestEvent, responseEvent, notificationEvent map[string]json.RawMessage
	if err := decoder.Decode(&requestEvent); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&responseEvent); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&notificationEvent); err != nil {
		t.Fatal(err)
	}
	if string(requestEvent["id"]) != `"req-1"` {
		t.Fatalf("request ID changed: %s", requestEvent["id"])
	}
	if string(responseEvent["event"]) != `"response-complete"` || string(responseEvent["id"]) != `"req-1"` {
		t.Fatalf("request response journal mismatch: %s", responseEvent)
	}
	if string(notificationEvent["method"]) != `"notifications/initialized"` {
		t.Fatalf("notification journal event missing: %s", notificationEvent)
	}
	if _, ok := notificationEvent["id"]; ok {
		t.Fatalf("notification ID appeared in journal: %s", notificationEvent["id"])
	}
}

func TestRunRejectsExplicitNullNotificationID(t *testing.T) {
	input := strings.NewReader(`{"jsonrpc":"2.0","id":"req-1","method":"initialize","params":{"protocolVersion":"2025-11-25"}}
{"jsonrpc":"2.0","id":null,"method":"notifications/initialized","params":{}}
`)
	var journal bytes.Buffer
	if err := run(input, &bytes.Buffer{}, &journal, t.TempDir()+"/effect"); err == nil || err.Error() != "initialized ordering" {
		t.Fatalf("explicit null notification error = %v, want initialized ordering", err)
	}
	decoder := json.NewDecoder(&journal)
	var requestEvent map[string]json.RawMessage
	if err := decoder.Decode(&requestEvent); err != nil {
		t.Fatal(err)
	}
	var response map[string]json.RawMessage
	if err := decoder.Decode(&response); err != nil {
		t.Fatal(err)
	}
	var event map[string]json.RawMessage
	if err := decoder.Decode(&event); err != nil {
		t.Fatal(err)
	}
	if string(event["id"]) != "null" {
		t.Fatalf("explicit null ID was not preserved for rejection evidence: %s", event["id"])
	}
}

func TestJournalRequestPreservesNumericID(t *testing.T) {
	data, err := json.Marshal(journalRequest(request{JSONRPC: "2.0", ID: json.RawMessage(`7`), Method: "tools/list"}))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["id"]) != "7" {
		t.Fatalf("numeric request ID changed: %s", data)
	}
}

func TestJournalRequestOmitsAbsentNotificationID(t *testing.T) {
	data, err := json.Marshal(journalRequest(request{JSONRPC: "2.0", Method: "notifications/initialized"}))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["id"]; ok {
		t.Fatalf("absent notification ID serialized: %s", data)
	}
}

func TestJournalRequestPreservesPresentRequestID(t *testing.T) {
	data, err := json.Marshal(journalRequest(request{JSONRPC: "2.0", ID: json.RawMessage(`"req-1"`), Method: "initialize"}))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if string(fields["id"]) != `"req-1"` {
		t.Fatalf("request ID changed: %s", data)
	}
}
