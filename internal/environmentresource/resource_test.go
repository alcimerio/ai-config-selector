package environmentresource

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func validIntent() Intent {
	return Intent{ID: "token", Destination: "TOOL_TOKEN", Scope: "attached-process-tree", SourceKind: "secret-reference", Provider: "host-environment", Reference: "PRIVATE_SOURCE", Required: true, Classification: "secret"}
}

func TestResolveValidatesBeforeLookupAndRedactsFormatting(t *testing.T) {
	for name, mutate := range map[string]func(*Intent){
		"scope":    func(value *Intent) { value.Scope = "all-processes" },
		"provider": func(value *Intent) { value.Provider = "future" },
		"reserved": func(value *Intent) { value.Destination = "PATH" },
	} {
		t.Run(name, func(t *testing.T) {
			intent := validIntent()
			mutate(&intent)
			lookups := 0
			if _, err := Resolve([]Intent{intent}, func(string) (string, bool) { lookups++; return "secret", true }); !errors.Is(err, ErrInvalidValue) || lookups != 0 {
				t.Fatalf("invalid intent result err=%v lookups=%d", err, lookups)
			}
		})
	}
	lease, err := Resolve([]Intent{validIntent()}, func(string) (string, bool) { return "private-sentinel", true })
	if err != nil {
		t.Fatal(err)
	}
	for _, formatted := range []string{fmt.Sprintf("%v", lease), fmt.Sprintf("%+v", lease), fmt.Sprintf("%#v", lease)} {
		if strings.Contains(formatted, "private-sentinel") || strings.Contains(formatted, "112 114 105 118 97 116 101") {
			t.Fatalf("resource formatting exposed bytes: %s", formatted)
		}
	}
	lease.Release()
	if err := lease.WriteFrame(&bytes.Buffer{}); !errors.Is(err, ErrReleased) {
		t.Fatalf("released frame error = %v", err)
	}
}

func TestResolveAndFrameDistinguishMissingFromPresentEmpty(t *testing.T) {
	optional := Intent{ID: "mode", Destination: "TOOL_MODE", Scope: "attached-process-tree", SourceKind: "host-environment", SourceName: "SOURCE_MODE", Classification: "non-secret"}
	lease, err := Resolve([]Intent{optional}, func(string) (string, bool) { return "", false })
	if err != nil || !lease.Empty() {
		t.Fatalf("optional missing = (%v,%v)", lease, err)
	}
	lease.Release()
	optional.Required = true
	if _, err := Resolve([]Intent{optional}, func(string) (string, bool) { return "", false }); !errors.Is(err, ErrMissingValue) {
		t.Fatalf("required missing error = %v", err)
	}
	lease, err = Resolve([]Intent{optional}, func(name string) (string, bool) { return "", name == "SOURCE_MODE" })
	if err != nil || lease.Empty() {
		t.Fatalf("present empty = (%v,%v)", lease, err)
	}
	var frame bytes.Buffer
	if err := lease.WriteFrame(&frame); err != nil {
		t.Fatal(err)
	}
	projection, err := ReadFrame(&frame, []string{"HOME=/private/session/home"})
	if err != nil || !reflect.DeepEqual(projection, []string{"TOOL_MODE="}) {
		t.Fatalf("projection=%q err=%v", projection, err)
	}
}

func TestResolveEnforcesExactCanonicalLookupAndValueBounds(t *testing.T) {
	makeNonSecret := func(id, destination, source string) Intent {
		return Intent{ID: id, Destination: destination, Scope: "attached-process-tree", SourceKind: "host-environment", SourceName: source, Required: true, Classification: "non-secret"}
	}
	lookups := []string{}
	lease, err := Resolve([]Intent{makeNonSecret("z", "VALUE_Z", "SOURCE_Z"), makeNonSecret("a", "VALUE_A", "SOURCE_A")}, func(name string) (string, bool) {
		lookups = append(lookups, name)
		return name, true
	})
	if err != nil || !reflect.DeepEqual(lookups, []string{"SOURCE_A", "SOURCE_Z"}) {
		t.Fatalf("canonical exact lookups=%q err=%v", lookups, err)
	}
	lease.Release()
	lease.Release()
	if _, err := Resolve([]Intent{makeNonSecret("nul", "VALUE_NUL", "SOURCE_NUL")}, func(string) (string, bool) { return "bad\x00value", true }); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("NUL value error = %v", err)
	}
	if _, err := Resolve([]Intent{makeNonSecret("large", "VALUE_LARGE", "SOURCE_LARGE")}, func(string) (string, bool) { return strings.Repeat("x", 32*1024+1), true }); !errors.Is(err, ErrValueTooLarge) {
		t.Fatalf("per-value limit error = %v", err)
	}
	intents := []Intent{}
	for index := 0; index < 5; index++ {
		intents = append(intents, makeNonSecret(fmt.Sprintf("value-%d", index), fmt.Sprintf("VALUE_%d", index), fmt.Sprintf("SOURCE_%d", index)))
	}
	if _, err := Resolve(intents, func(string) (string, bool) { return strings.Repeat("x", 32*1024), true }); !errors.Is(err, ErrValueTooLarge) {
		t.Fatalf("aggregate limit error = %v", err)
	}
}

func TestReadFrameRejectsTruncationReservationAndIntrinsicCollision(t *testing.T) {
	optional := Intent{ID: "mode", Destination: "TOOL_MODE", Scope: "attached-process-tree", SourceKind: "host-environment", SourceName: "SOURCE_MODE", Required: true, Classification: "non-secret"}
	lease, err := Resolve([]Intent{optional}, func(string) (string, bool) { return "value", true })
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if err := lease.WriteFrame(&encoded); err != nil {
		t.Fatal(err)
	}
	data := encoded.Bytes()
	if _, err := ReadFrame(bytes.NewReader(data[:len(data)-1]), nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("truncated frame error = %v", err)
	}
	corrupt := append([]byte(nil), data...)
	corrupt[0] ^= 0xff
	if _, err := ReadFrame(bytes.NewReader(corrupt), nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("invalid magic error = %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader(data), []string{"TOOL_MODE=intrinsic"}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("intrinsic collision error = %v", err)
	}
	var reserved bytes.Buffer
	reserved.WriteString(frameMagic)
	_ = binary.Write(&reserved, binary.BigEndian, uint16(1))
	_ = binary.Write(&reserved, binary.BigEndian, uint16(len("PATH")))
	_ = binary.Write(&reserved, binary.BigEndian, uint32(len("value")))
	reserved.WriteString("PATH")
	reserved.WriteString("value")
	if _, err := ReadFrame(&reserved, nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("reserved destination error = %v", err)
	}
}
