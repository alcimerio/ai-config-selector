package profilerepo

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// All filenames are derived locally. Journal bytes contain only validated names,
// exact object identities and content hashes, never paths or codec instructions.
type plan struct {
	Version     int
	ID          string
	Operation   string
	Source      string
	Destination string
	Before      *identity
	Stage       *identity
}

func validIdentity(id *identity) bool {
	if id == nil || id.Inode == 0 || id.Size < 0 || id.Size > MaxDocumentBytes || len(id.Hash) != 64 {
		return false
	}
	b, e := hex.DecodeString(id.Hash)
	return e == nil && hex.EncodeToString(b) == id.Hash
}
func decodePlan(data []byte) (*plan, error) {
	var p plan
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return nil, ErrUnsafe
	}
	// Canonical internal metadata rejects duplicate keys, trailing values, missing
	// fields, alternate number/string spellings and unknown fields without replay.
	canonical, err := json.Marshal(p)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, ErrUnsafe
	}
	id, e := hex.DecodeString(p.ID)
	if e != nil || len(id) != 16 || hex.EncodeToString(id) != p.ID || p.Version != 1 {
		return nil, ErrUnsafe
	}
	if p.Source != "" && (!namePattern.MatchString(p.Source) || !validIdentity(p.Before)) {
		return nil, ErrUnsafe
	}
	if p.Destination != "" && !namePattern.MatchString(p.Destination) {
		return nil, ErrUnsafe
	}
	if p.Source != "" && strings.EqualFold(p.Source, p.Destination) {
		return nil, ErrUnsafe
	}
	if p.Operation != "delete" && !validIdentity(p.Stage) {
		return nil, ErrUnsafe
	}
	switch p.Operation {
	case "create":
		if p.Source != "" || p.Destination == "" || p.Before != nil {
			return nil, ErrUnsafe
		}
	case "replace":
		if p.Source == "" || p.Destination != "" {
			return nil, ErrUnsafe
		}
	case "delete":
		if p.Source == "" || p.Destination != "" || p.Stage != nil {
			return nil, ErrUnsafe
		}
	case "clone", "rename":
		if p.Source == "" || p.Destination == "" {
			return nil, ErrUnsafe
		}
	default:
		return nil, ErrUnsafe
	}
	return &p, nil
}
func (d *directory) prepare(ctx context.Context, c change) (*plan, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	p := &plan{Version: 1, ID: hex.EncodeToString(random[:]), Operation: c.op, Source: c.source, Destination: c.destination}
	if c.source != "" {
		before, err := d.read(c.source+".json", MaxDocumentBytes, 1)
		if err != nil {
			return nil, err
		}
		if before == nil || revision(c.source, true, before.data) != c.sourceRevision {
			return nil, ErrConflict
		}
		p.Before = &before.identity
	}
	if c.destination != "" {
		target, err := d.read(c.destination+".json", MaxDocumentBytes, 1)
		if err != nil {
			return nil, errors.Join(ErrConflict, err)
		}
		if target != nil {
			return nil, ErrConflict
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.op != "delete" {
		if err := d.writeNew("stage", c.data); err != nil {
			return nil, err
		}
		staged, err := d.read("stage", MaxDocumentBytes, 1)
		if err != nil {
			return nil, err
		}
		if staged == nil {
			return nil, ErrUnsafe
		}
		if !bytes.Equal(staged.data, c.data) {
			return nil, ErrUnsafe
		}
		p.Stage = &staged.identity
		if err = d.sync("stage.directory-sync"); err != nil {
			return nil, err
		}
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if err = d.writeNew("pending", encoded); err != nil {
		return nil, err
	}
	if err = d.rename("pending", "plan", "plan.publish"); err != nil {
		return nil, err
	}
	if err = d.sync("plan.directory-sync"); err != nil {
		return nil, err
	}
	// Detect outside interference observed during preparation before deciding.
	if err = d.checkBefore(p); err != nil {
		return nil, err
	}
	return p, nil
}
func (d *directory) checkBefore(p *plan) error {
	if p.Source != "" {
		o, e := d.read(p.Source+".json", MaxDocumentBytes, 1)
		if e != nil {
			return e
		}
		if o == nil || !o.matches(*p.Before) {
			return ErrConflict
		}
	}
	if p.Destination != "" {
		o, e := d.read(p.Destination+".json", MaxDocumentBytes, 1)
		if e != nil {
			return errors.Join(ErrConflict, e)
		}
		if o != nil {
			return ErrConflict
		}
	}
	return nil
}
func (d *directory) recover(ctx context.Context) (out Outcome, err error) {
	out = Outcome{State: Unknown, RecoveryRequired: true}
	if err = ctx.Err(); err != nil {
		return
	}
	artifacts, err := d.artifacts()
	if err != nil {
		return out, err
	}
	if len(artifacts) == 0 {
		out.State = NotCommitted
		out.RecoveryRequired = false
		return out, nil
	}
	record := artifacts["complete"]
	if record == nil {
		record = artifacts["decision"]
	}
	if record == nil {
		record = artifacts["plan"]
	}
	decided := artifacts["decision"] != nil || artifacts["complete"] != nil
	if decided {
		out.State = Unknown
	}
	var p *plan
	if record != nil {
		p, err = decodePlan(record.data)
		if err != nil {
			return out, err
		}
		count := uint64(0)
		for _, n := range []string{"plan", "decision", "complete"} {
			if o := artifacts[n]; o != nil {
				count++
				if !identical(o, record) {
					return out, ErrUnsafe
				}
			}
		}
		if record.links != count || artifacts["pending"] != nil {
			return out, ErrUnsafe
		}
	}
	if artifacts["complete"] != nil {
		// Terminal cleanup is independent of staging already legitimately removed.
		// Recovery may observe a terminal link published just before interruption.
		// Synchronize that evidence before deleting any of its supporting links.
		if err = d.sync("complete.recovery-sync"); err != nil {
			return out, err
		}
		out.State = Committed
		err = d.cleanup(p, artifacts, true)
		out.RecoveryRequired = err != nil
		return
	}
	if !decided && record == nil && artifacts["pending"] != nil {
		pending := artifacts["pending"].data
		if json.Valid(pending) {
			// Even a preparation record from a future version is preserved.
			p, err = decodePlan(pending)
			if err != nil {
				return out, err
			}
		} else {
			if !preparationPrefix(pending) {
				return out, ErrUnsafe
			}
		}
	}
	if !decided {
		out.State = NotCommitted
		// Fixed private partial preparation files are recognizable even before a
		// complete plan exists. No public name was authorized to change.
		if artifacts["swap"] != nil {
			return out, ErrUnsafe
		}
		for n, o := range artifacts {
			if o.links != 1 {
				return out, ErrUnsafe
			}
			if n == "stage" && p != nil && (p.Stage == nil || !o.matches(*p.Stage)) {
				return out, ErrUnsafe
			}
		}
		err = d.cleanup(p, artifacts, false)
		out.RecoveryRequired = err != nil
		return
	}
	if artifacts["plan"] == nil || p == nil {
		return out, ErrUnsafe
	}
	return d.finish(p)
}
func (d *directory) finish(p *plan) (out Outcome, err error) {
	out = Outcome{State: Unknown, RecoveryRequired: true}
	artifacts, err := d.artifacts()
	if err != nil {
		return out, err
	}
	// Verify immutable decision, not only caller-held memory.
	record := artifacts["decision"]
	if record == nil || !identical(record, artifacts["plan"]) || record.links != 2 || artifacts["complete"] != nil || artifacts["pending"] != nil {
		return out, ErrUnsafe
	}
	encoded, _ := json.Marshal(p)
	if !bytes.Equal(record.data, encoded) {
		return out, ErrUnsafe
	}
	targetName := p.Destination
	if p.Operation == "replace" {
		targetName = p.Source
	}
	var target *object
	if targetName != "" {
		target, err = d.read(targetName+".json", MaxDocumentBytes, 2)
		if err != nil {
			return out, err
		}
	}
	if p.Stage != nil {
		stage := artifacts["stage"]
		if stage == nil || !stage.matches(*p.Stage) {
			return out, ErrUnsafe
		}
		links := uint64(1)
		if swap := artifacts["swap"]; swap != nil {
			if p.Operation != "replace" || !identical(swap, stage) {
				return out, ErrUnsafe
			}
			links++
		}
		if target != nil && target.matches(*p.Stage) {
			links++
		}
		if stage.links != links || links > 2 {
			return out, ErrUnsafe
		}
	} else if artifacts["stage"] != nil || artifacts["swap"] != nil {
		return out, ErrUnsafe
	}
	switch p.Operation {
	case "create", "clone", "rename":
		if target == nil {
			// Clone source freshness is checked until publication. Rename additionally
			// checks its source before removing it, including after a crash.
			if p.Source != "" {
				source, e := d.read(p.Source+".json", MaxDocumentBytes, 1)
				if e != nil {
					return out, e
				}
				if source == nil || !source.matches(*p.Before) {
					return out, ErrConflict
				}
			}
			if err = d.link("stage", p.Destination+".json", "publish.link"); err != nil {
				return
			}
		} else if !target.matches(*p.Stage) {
			return out, ErrConflict
		}
		if err = d.sync("publish.sync"); err != nil {
			return
		}
	case "replace":
		if target == nil {
			return out, ErrConflict
		}
		if !target.matches(*p.Stage) {
			if !target.matches(*p.Before) || target.links != 1 {
				return out, ErrConflict
			}
			if artifacts["swap"] == nil {
				if err = d.link("stage", "swap", "replace.link"); err != nil {
					return
				}
			}
			// Recheck after preparing the link; advisory exclusion covers cooperating writers.
			current, e := d.read(p.Source+".json", MaxDocumentBytes, 1)
			if e != nil {
				return out, e
			}
			if current == nil || !current.matches(*p.Before) {
				return out, ErrConflict
			}
			if err = d.rename("swap", p.Source+".json", "publish.replace"); err != nil {
				return
			}
		}
		if err = d.sync("publish.sync"); err != nil {
			return
		}
	}
	if p.Operation == "delete" || p.Operation == "rename" {
		source, e := d.read(p.Source+".json", MaxDocumentBytes, 1)
		if e != nil {
			return out, e
		}
		if source != nil {
			if !source.matches(*p.Before) {
				return out, ErrConflict
			}
			if err = d.remove(p.Source+".json", "publish.delete"); err != nil {
				return
			}
		}
		if err = d.sync("delete.sync"); err != nil {
			return
		}
	}
	if err = d.link("plan", "complete", "complete.publish"); err != nil {
		return
	}
	if err = d.sync("complete.sync"); err != nil {
		return
	}
	out.State = Committed
	artifacts, err = d.artifacts()
	if err != nil {
		return out, err
	}
	err = d.cleanup(p, artifacts, true)
	out.RecoveryRequired = err != nil
	return
}
func (d *directory) cleanup(p *plan, artifacts map[string]*object, committed bool) error {
	// No terminal state produced by this engine retains a swap or pending leaf.
	if committed {
		if artifacts["swap"] != nil || artifacts["pending"] != nil {
			return ErrUnsafe
		}
		if stage := artifacts["stage"]; stage != nil {
			if p == nil || p.Stage == nil || !stage.matches(*p.Stage) {
				return ErrUnsafe
			}
			targetName := p.Destination
			if p.Operation == "replace" {
				targetName = p.Source
			}
			target, err := d.read(targetName+".json", MaxDocumentBytes, 2)
			if err != nil {
				return err
			}
			links := uint64(1)
			if target != nil && target.matches(*p.Stage) {
				links++
			} else if target != nil && target.links != 1 {
				return ErrUnsafe
			}
			if stage.links != links {
				return ErrUnsafe
			}
		}
	}
	// Validate all remaining artifacts before removing any. Never touch public names.
	for n, o := range artifacts {
		switch n {
		case "stage", "swap":
			if committed {
				if p == nil || p.Stage == nil || !o.matches(*p.Stage) {
					return ErrUnsafe
				}
			} else if o.links != 1 {
				return ErrUnsafe
			}
		case "pending":
			if committed || o.links != 1 {
				return ErrUnsafe
			}
		}
	}
	// complete is last: every interrupted terminal cleanup retains a valid receipt
	// which requires no deleted staging blob or plan link to finish cleanup.
	for _, n := range []string{"pending", "swap", "stage", "decision", "plan", "complete"} {
		if artifacts[n] == nil {
			continue
		}
		current, err := d.read(n, func() int {
			if n == "stage" || n == "swap" {
				return MaxDocumentBytes
			}
			return maxMetadataBytes
		}(), 3)
		if err != nil {
			return err
		}
		if current == nil || !identical(current, artifacts[n]) || (n == "stage" && current.links != artifacts[n].links) {
			return ErrUnsafe
		}
		if err = d.remove(n, "cleanup."+n); err != nil {
			return err
		}
		if err = d.sync("cleanup." + n + ".sync"); err != nil {
			return err
		}
	}
	return nil
}
