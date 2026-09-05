// Package profilerepo persists bounded opaque documents, without a Profile codec.
// Constructors and Read are passive. Only Apply and Recover acquire ownership.
package profilerepo

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const MaxDocumentBytes = 1 << 20

var (
	ErrConflict = errors.New("Profile revision or destination conflict")
	ErrBusy     = errors.New("Profile repository is busy")
	ErrUnsafe   = errors.New("unsafe Profile repository state")
	namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// Revision is an opaque name-bound exact-content condition, not a generation.
// The zero value is invalid. Present empty bytes differ from absence.
type Revision struct {
	digest [32]byte
	valid  bool
}
type Snapshot struct {
	Exists   bool
	Bytes    []byte
	Revision Revision
}

func revision(name string, present bool, data []byte) Revision {
	h := sha256.New()
	h.Write([]byte("acs-profile-content-v1\x00"))
	h.Write([]byte(name))
	h.Write([]byte{0})
	if present {
		h.Write([]byte{1})
		h.Write(data)
	} else {
		h.Write([]byte{0})
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return Revision{sum, true}
}

// State describes the requested operation independently of cleanup errors.
type State string

const (
	NotCommitted State = "not_committed"
	Committed    State = "committed"
	Unknown      State = "unknown"
)

type Outcome struct {
	State            State
	RecoveryRequired bool
}

// OutcomeError preserves the truthful outcome through legacy Store signatures.
type OutcomeError struct {
	Outcome Outcome
	Err     error
}

func (e *OutcomeError) Error() string {
	return fmt.Sprintf("Profile transaction %s: %v", e.Outcome.State, e.Err)
}
func (e *OutcomeError) Unwrap() error { return e.Err }

// Request is sealed to the five supported single-transaction shapes.
// Bytes are supplied canonical by the caller; nil means an empty document.
type Request interface{ change() change }
type CreateRequest struct {
	Name     string
	Expected Revision
	Bytes    []byte
}
type ReplaceRequest struct {
	Name     string
	Expected Revision
	Bytes    []byte
}
type CloneRequest struct {
	Source, Destination                 string
	ExpectedSource, ExpectedDestination Revision
	Bytes                               []byte
}
type RenameRequest struct {
	Source, Destination                 string
	ExpectedSource, ExpectedDestination Revision
	Bytes                               []byte
}
type DeleteRequest struct {
	Name     string
	Expected Revision
}
type change struct {
	op, source, destination             string
	sourceRevision, destinationRevision Revision
	data                                []byte
}

func (r CreateRequest) change() change {
	return change{op: "create", destination: r.Name, destinationRevision: r.Expected, data: r.Bytes}
}
func (r ReplaceRequest) change() change {
	return change{op: "replace", source: r.Name, sourceRevision: r.Expected, data: r.Bytes}
}
func (r CloneRequest) change() change {
	return change{op: "clone", source: r.Source, destination: r.Destination, sourceRevision: r.ExpectedSource, destinationRevision: r.ExpectedDestination, data: r.Bytes}
}
func (r RenameRequest) change() change {
	return change{op: "rename", source: r.Source, destination: r.Destination, sourceRevision: r.ExpectedSource, destinationRevision: r.ExpectedDestination, data: r.Bytes}
}
func (r DeleteRequest) change() change {
	return change{op: "delete", source: r.Name, sourceRevision: r.Expected}
}
func (c change) validate() error {
	if len(c.data) > MaxDocumentBytes {
		return fmt.Errorf("document exceeds %d bytes", MaxDocumentBytes)
	}
	if c.source != "" && (!namePattern.MatchString(c.source) || !c.sourceRevision.valid) {
		return ErrConflict
	}
	if c.destination != "" && (!namePattern.MatchString(c.destination) || c.destinationRevision != revision(c.destination, false, nil)) {
		return ErrConflict
	}
	if c.source != "" && c.sourceRevision == revision(c.source, false, nil) {
		return ErrConflict
	}
	if c.source != "" && c.destination != "" && strings.EqualFold(c.source, c.destination) {
		return ErrConflict
	}
	switch c.op {
	case "create":
		if c.destination == "" {
			return ErrConflict
		}
	case "replace", "delete":
		if c.source == "" {
			return ErrConflict
		}
	case "clone", "rename":
		if c.source == "" || c.destination == "" {
			return ErrConflict
		}
	default:
		return ErrConflict
	}
	return nil
}

type Repository struct {
	acsHome string
	// Per-instance test seams never read environment variables in production.
	hook  func(string) error
	write func(*os.File, []byte) (int, error)
}

func New(acsHome string) *Repository { return &Repository{acsHome: acsHome} }
func (r *Repository) step(point string, action func() error) error {
	if r.hook != nil {
		if err := r.hook(point + ".before"); err != nil {
			return err
		}
	}
	if err := action(); err != nil {
		return err
	}
	if r.hook != nil {
		return r.hook(point + ".after")
	}
	return nil
}
func (r *Repository) Read(ctx context.Context, name string) (snapshot Snapshot, err error) {
	if err = ctx.Err(); err != nil {
		return
	}
	if !namePattern.MatchString(name) {
		return snapshot, ErrConflict
	}
	d, err := r.open(false)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{Revision: revision(name, false, nil)}, nil
	}
	if err != nil {
		return snapshot, err
	}
	defer func() { err = errors.Join(err, d.close()) }()
	object, err := d.read(name+".json", MaxDocumentBytes, 2)
	if err != nil {
		return snapshot, err
	}
	if object != nil && object.links > 1 {
		// A passive read can recognize the one deliberate staging link; arbitrary
		// multiply linked public documents are not safe repository entries.
		stage, e := d.read("stage", MaxDocumentBytes, 2)
		if e != nil {
			return snapshot, e
		}
		decision, e := d.read("decision", maxMetadataBytes, 3)
		if e != nil {
			return snapshot, e
		}
		if stage == nil || decision == nil || !identical(stage, object) {
			return snapshot, ErrUnsafe
		}
		p, e := decodePlan(decision.data)
		if e != nil {
			return snapshot, e
		}
		target := p.Destination
		if p.Operation == "replace" {
			target = p.Source
		}
		if target != name || p.Stage == nil || !object.matches(*p.Stage) {
			return snapshot, ErrUnsafe
		}
	}
	return Snapshot{Exists: object != nil, Bytes: object.bytes(), Revision: revision(name, object != nil, object.bytes())}, ctx.Err()
}
func (r *Repository) Apply(ctx context.Context, request Request) (out Outcome, err error) {
	out.State = NotCommitted
	if err = ctx.Err(); err != nil {
		return
	}
	if request == nil {
		return out, ErrConflict
	}
	c := request.change()
	if err = c.validate(); err != nil {
		return
	}
	c.data = append([]byte(nil), c.data...)
	d, err := r.open(true)
	if err != nil {
		return out, err
	}
	defer func() { err = errors.Join(err, d.close()) }()
	if err = d.lock(); err != nil {
		return
	}
	defer func() { err = errors.Join(err, d.release()) }()
	// Recovery belongs to the old operation. Failure never implies this request committed.
	previous, recoveryErr := d.recover(ctx)
	if recoveryErr != nil {
		out.RecoveryRequired = previous.RecoveryRequired
		return out, fmt.Errorf("recover preceding transaction: %w", recoveryErr)
	}
	if err = ctx.Err(); err != nil {
		return
	}
	p, err := d.prepare(ctx, c)
	if err != nil {
		cleanup, cleanupErr := d.recover(context.Background())
		out.RecoveryRequired = cleanup.RecoveryRequired
		return out, errors.Join(err, cleanupErr)
	}
	if err = ctx.Err(); err != nil {
		cleanup, cleanupErr := d.recover(context.Background())
		out.RecoveryRequired = cleanup.RecoveryRequired
		return out, errors.Join(err, cleanupErr)
	}
	// From this point a commit decision can exist; errors require explicit recovery.
	out = Outcome{State: Unknown, RecoveryRequired: true}
	if err = d.link("plan", "decision", "decision.publish"); err != nil {
		return
	}
	if err = d.sync("decision.sync"); err != nil {
		return
	}
	return d.finish(p)
}
func (r *Repository) Recover(ctx context.Context) (out Outcome, err error) {
	out.State = NotCommitted
	if err = ctx.Err(); err != nil {
		return
	}
	// Empty explicit recovery does not bootstrap a missing repository. Apply
	// bootstraps only when it owns an actual mutation request.
	existing, probeErr := r.open(false)
	if errors.Is(probeErr, os.ErrNotExist) {
		return out, nil
	}
	if probeErr != nil {
		return out, probeErr
	}
	if closeErr := existing.close(); closeErr != nil {
		return out, closeErr
	}
	d, err := r.open(true)
	if err != nil {
		return out, err
	}
	defer func() { err = errors.Join(err, d.close()) }()
	if err = d.lock(); err != nil {
		return
	}
	defer func() { err = errors.Join(err, d.release()) }()
	return d.recover(ctx)
}

// AbsentRevision returns the explicit absent condition for a valid name without
// reading storage. It never matches a present empty document.
func AbsentRevision(name string) (Revision, error) {
	if !namePattern.MatchString(name) {
		return Revision{}, ErrConflict
	}
	return revision(name, false, nil), nil
}
