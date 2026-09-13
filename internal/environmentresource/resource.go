// Package environmentresource owns resolved environment values between the
// pre-Session provider lookup and the contained target's Start boundary.
package environmentresource

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/alcimerio/ai-config-selector/internal/environmentintent"
)

const frameMagic = "ACSENV01"

var (
	ErrMissingValue  = errors.New("selected environment value is unavailable")
	ErrInvalidValue  = errors.New("selected environment value is invalid")
	ErrValueTooLarge = errors.New("selected environment values are too large")
	ErrReleased      = errors.New("selected environment resource is released")
)

type Intent struct {
	ID, Destination, Scope, SourceKind, SourceName, Provider, Reference, Classification string
	Required                                                                            bool
}

type Lookup func(string) (string, bool)

type entry struct {
	destination string
	value       []byte
}

// Lease contains no logical provider names or references after resolution.
// Release clears the owned value buffers and is idempotent.
type Lease struct {
	mutex    sync.Mutex
	entries  []entry
	released bool
}

func Resolve(intents []Intent, lookup Lookup) (*Lease, error) {
	if lookup == nil {
		return nil, ErrInvalidValue
	}
	selection := environmentintent.Selection{Entries: make([]environmentintent.Entry, 0, len(intents))}
	for _, intent := range intents {
		selection.Entries = append(selection.Entries, environmentintent.Entry{
			ID: intent.ID, Destination: intent.Destination, Scope: intent.Scope,
			Source:   environmentintent.Source{Kind: intent.SourceKind, Name: intent.SourceName, Provider: intent.Provider, Reference: intent.Reference},
			Required: intent.Required, Classification: intent.Classification,
		})
	}
	canonical, err := environmentintent.Canonical(selection)
	if err != nil {
		return nil, ErrInvalidValue
	}
	lease := &Lease{entries: make([]entry, 0, len(intents))}
	total := 0
	for _, intent := range canonical.Entries {
		name := intent.Source.Name
		if intent.Source.Kind == environmentintent.SourceSecretReference {
			name = intent.Source.Reference
		}
		value, present := lookup(name)
		if !present {
			if intent.Required || intent.Source.Kind == environmentintent.SourceSecretReference {
				lease.Release()
				return nil, ErrMissingValue
			}
			continue
		}
		if strings.IndexByte(value, 0) >= 0 {
			lease.Release()
			return nil, ErrInvalidValue
		}
		if len(value) > environmentintent.MaximumValueBytes || total > environmentintent.MaximumAggregateBytes-len(value) {
			lease.Release()
			return nil, ErrValueTooLarge
		}
		total += len(value)
		lease.entries = append(lease.entries, entry{destination: intent.Destination, value: []byte(value)})
	}
	return lease, nil
}

// Format prevents fmt diagnostics, including %#v, from traversing the owned
// byte buffers. Logical selection details belong to the sanitized authority
// plan; this resource reports only lifecycle state.
func (lease *Lease) Format(state fmt.State, verb rune) {
	status := "active"
	count := 0
	if lease == nil {
		status = "nil"
	} else {
		lease.mutex.Lock()
		count = len(lease.entries)
		if lease.released {
			status = "released"
		}
		lease.mutex.Unlock()
	}
	_, _ = fmt.Fprintf(state, "environment-resource(%s,count=%d)", status, count)
}

func (lease *Lease) Empty() bool {
	if lease == nil {
		return true
	}
	lease.mutex.Lock()
	defer lease.mutex.Unlock()
	return !lease.released && len(lease.entries) == 0
}

func (lease *Lease) WriteFrame(writer io.Writer) error {
	if lease == nil {
		return ErrInvalidValue
	}
	lease.mutex.Lock()
	defer lease.mutex.Unlock()
	if lease.released {
		return ErrReleased
	}
	if _, err := io.WriteString(writer, frameMagic); err != nil {
		return err
	}
	if err := binary.Write(writer, binary.BigEndian, uint16(len(lease.entries))); err != nil {
		return err
	}
	for _, entry := range lease.entries {
		if err := binary.Write(writer, binary.BigEndian, uint16(len(entry.destination))); err != nil {
			return err
		}
		if err := binary.Write(writer, binary.BigEndian, uint32(len(entry.value))); err != nil {
			return err
		}
		if _, err := io.WriteString(writer, entry.destination); err != nil {
			return err
		}
		if _, err := writer.Write(entry.value); err != nil {
			return err
		}
	}
	return nil
}

func ReadFrame(reader io.Reader, intrinsic []string) ([]string, error) {
	magic := make([]byte, len(frameMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != frameMagic {
		return nil, ErrInvalidValue
	}
	var count uint16
	if err := binary.Read(reader, binary.BigEndian, &count); err != nil || int(count) > environmentintent.MaximumEntries {
		return nil, ErrInvalidValue
	}
	seen := make(map[string]bool, len(intrinsic)+int(count))
	for _, item := range intrinsic {
		name, _, ok := strings.Cut(item, "=")
		if !ok || !environmentintent.ValidName(name) {
			return nil, ErrInvalidValue
		}
		seen[name] = true
	}
	selected := make([]string, 0, int(count))
	total := 0
	for index := 0; index < int(count); index++ {
		var nameLength uint16
		var valueLength uint32
		if binary.Read(reader, binary.BigEndian, &nameLength) != nil || binary.Read(reader, binary.BigEndian, &valueLength) != nil || nameLength == 0 || nameLength > 128 || valueLength > environmentintent.MaximumValueBytes {
			return nil, ErrInvalidValue
		}
		if total > environmentintent.MaximumAggregateBytes-int(valueLength) {
			return nil, ErrValueTooLarge
		}
		nameBytes := make([]byte, int(nameLength))
		value := make([]byte, int(valueLength))
		if _, err := io.ReadFull(reader, nameBytes); err != nil {
			return nil, ErrInvalidValue
		}
		if _, err := io.ReadFull(reader, value); err != nil {
			return nil, ErrInvalidValue
		}
		name := string(nameBytes)
		if !environmentintent.ValidName(name) || environmentintent.ReservedDestination(name) || seen[name] || strings.IndexByte(string(value), 0) >= 0 {
			clear(value)
			return nil, ErrInvalidValue
		}
		seen[name] = true
		total += len(value)
		selected = append(selected, name+"="+string(value))
		clear(value)
	}
	return selected, nil
}

func (lease *Lease) Release() {
	if lease == nil {
		return
	}
	lease.mutex.Lock()
	defer lease.mutex.Unlock()
	if lease.released {
		return
	}
	for index := range lease.entries {
		clear(lease.entries[index].value)
		lease.entries[index].value = nil
	}
	lease.entries = nil
	lease.released = true
}
