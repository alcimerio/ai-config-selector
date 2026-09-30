// Package strictjson provides lexical JSON checks only. Callers own schema
// admission, decoder number handling, byte limits, and public error categories.
package strictjson

import (
	"encoding/json"
	"errors"
	"io"
)

var (
	ErrSyntax       = errors.New("invalid JSON syntax")
	ErrDuplicateKey = errors.New("duplicate JSON object key")
	ErrLimit        = errors.New("JSON limit exceeded")
	ErrRejectedKey  = errors.New("JSON object key rejected")
)

// Limits describe one caller's lexical budget. MaxDepth counts nested values
// below the root, which is depth zero. Other zero limits mean unbounded.
// Tokens count values and object keys, excluding closing delimiters.
// String lengths are measured in decoded UTF-8 bytes.
type Limits struct {
	MaxDepth       int
	MaxTokens      int
	MaxMembers     int
	MaxArray       int
	MaxStringBytes int
}

// Scan accepts exactly one complete JSON value and rejects duplicate decoded
// object keys. The caller configures decoder.UseNumber when required. An
// optional rejectKey applies a caller-owned field-name rule at every object.
// Unicode validation is separate so callers can retain their error precedence.
func Scan(decoder *json.Decoder, limits Limits, rejectKey func(string) bool) error {
	scanner := scanner{decoder: decoder, limits: limits, rejectKey: rejectKey}
	if err := scanner.value(0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrSyntax
	}
	return nil
}

type scanner struct {
	decoder   *json.Decoder
	limits    Limits
	rejectKey func(string) bool
	tokens    int
}

func exceeds(value, maximum int) bool { return maximum > 0 && value > maximum }

func (s *scanner) value(depth int) error {
	if depth > s.limits.MaxDepth {
		return ErrLimit
	}
	token, err := s.decoder.Token()
	if err != nil {
		return ErrSyntax
	}
	s.tokens++
	if exceeds(s.tokens, s.limits.MaxTokens) {
		return ErrLimit
	}
	if value, ok := token.(string); ok && exceeds(len(value), s.limits.MaxStringBytes) {
		return ErrLimit
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	count := 0
	switch delim {
	case '{':
		seen := map[string]bool{}
		for s.decoder.More() {
			key, err := s.decoder.Token()
			if err != nil {
				return ErrSyntax
			}
			name, ok := key.(string)
			if !ok {
				return ErrSyntax
			}
			s.tokens++
			count++
			if exceeds(s.tokens, s.limits.MaxTokens) || exceeds(len(name), s.limits.MaxStringBytes) || exceeds(count, s.limits.MaxMembers) {
				return ErrLimit
			}
			if seen[name] {
				return ErrDuplicateKey
			}
			if s.rejectKey != nil && s.rejectKey(name) {
				return ErrRejectedKey
			}
			seen[name] = true
			if err := s.value(depth + 1); err != nil {
				return err
			}
		}
	case '[':
		for s.decoder.More() {
			count++
			if exceeds(count, s.limits.MaxArray) {
				return ErrLimit
			}
			if err := s.value(depth + 1); err != nil {
				return err
			}
		}
	default:
		return ErrSyntax
	}
	if _, err := s.decoder.Token(); err != nil {
		return ErrSyntax
	}
	return nil
}
