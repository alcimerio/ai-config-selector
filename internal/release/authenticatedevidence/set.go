package authenticatedevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const maximumEvidenceSetSize = 2*maximumEvidenceSize + 4096

// SetExpectations binds the two required authenticated reference records to
// the exact candidate bytes and source under release review.
type SetExpectations struct {
	DarwinArm64 Expectations
	LinuxAMD64  Expectations
}

type evidenceSet struct {
	SchemaVersion int             `json:"schema_version"`
	DarwinArm64   json.RawMessage `json:"darwin_arm64"`
	LinuxAMD64    json.RawMessage `json:"linux_amd64"`
}

// ValidateSet requires exactly one complete record for each authenticated
// reference target. It does not echo untrusted evidence content.
func ValidateSet(input io.Reader, expected SetExpectations) error {
	contents, err := io.ReadAll(io.LimitReader(input, maximumEvidenceSetSize+1))
	if err != nil || len(contents) > maximumEvidenceSetSize {
		return errors.New("authenticated evidence set contains trailing or oversized content")
	}
	if !utf8.Valid(contents) {
		return errors.New("authenticated evidence set is malformed")
	}
	if err := rejectDuplicateFields(contents); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var set evidenceSet
	if err := decoder.Decode(&set); err != nil {
		return errors.New("authenticated evidence set contains an unsupported field or malformed value")
	}
	if err := ensureJSONEnds(decoder); err != nil {
		return errors.New("authenticated evidence set contains trailing or oversized content")
	}
	if set.SchemaVersion != currentSchemaVersion || len(set.DarwinArm64) == 0 || len(set.LinuxAMD64) == 0 {
		return errors.New("authenticated evidence set is incomplete or malformed")
	}
	if err := Validate(bytes.NewReader(set.DarwinArm64), expected.DarwinArm64); err != nil {
		return errors.New("authenticated evidence set has invalid darwin/arm64 evidence: " + err.Error())
	}
	if err := Validate(bytes.NewReader(set.LinuxAMD64), expected.LinuxAMD64); err != nil {
		return errors.New("authenticated evidence set has invalid linux/amd64 evidence: " + err.Error())
	}
	return nil
}
