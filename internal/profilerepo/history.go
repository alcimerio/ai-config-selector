package profilerepo

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	HistorySchemaVersion = 1
	MaxHistoryEvents     = 256
	MaxHistoryBytes      = 32 << 20
	DefaultHistoryKeep   = 100
)

var (
	lineagePattern = regexpMust(`^ln_[0-9a-f]{32}$`)
	eventPattern   = regexpMust(`^ev_[0-9a-f]{32}$`)
	ErrNotFound    = errors.New("Profile history entry not found")
	ErrQuota       = errors.New("Profile history quota exceeded")
)

// tinyPattern keeps the accepted private identifier grammar local without
// permitting callers to turn an identifier into a path.
type tinyPattern string

func regexpMust(s string) tinyPattern { return tinyPattern(s) }
func (p tinyPattern) MatchString(s string) bool {
	prefix := "ln_"
	if strings.HasPrefix(string(p), "^ev_") {
		prefix = "ev_"
	}
	if len(s) != 35 || !strings.HasPrefix(s, prefix) {
		return false
	}
	_, err := hex.DecodeString(s[3:])
	return err == nil && strings.ToLower(s) == s
}

type HistorySelector struct{ Name, Lineage string }

type HistoryEvent struct {
	SchemaVersion int            `json:"schemaVersion"`
	LineageID     string         `json:"lineageId"`
	EventID       string         `json:"eventId"`
	Operation     string         `json:"operation"`
	CreatedAt     string         `json:"createdAt"`
	Profile       HistoryProfile `json:"profile"`
	Pinned        bool           `json:"pinned"`
	Retained      bool           `json:"retained"`
}

type HistoryProfile struct {
	Name     string `json:"name"`
	State    string `json:"state"`
	Revision string `json:"revision"`
}

type HistoryResult struct {
	SchemaVersion int            `json:"schemaVersion"`
	LineageID     string         `json:"lineageId"`
	Events        []HistoryEvent `json:"events"`
}

type historyRecord struct {
	Version          int    `json:"version"`
	LineageID        string `json:"lineageId"`
	EventID          string `json:"eventId"`
	Sequence         int    `json:"sequence"`
	ParentDigest     string `json:"parentDigest"`
	Operation        string `json:"operation"`
	CreatedAt        string `json:"createdAt"`
	PreName          string `json:"preName"`
	PostName         string `json:"postName"`
	PreRevision      string `json:"preRevision"`
	PostRevision     string `json:"postRevision"`
	SnapshotName     string `json:"snapshotName"`
	SnapshotRevision string `json:"snapshotRevision"`
	SnapshotDigest   string `json:"snapshotDigest"`
	Tombstone        bool   `json:"tombstone"`
	SourceLineage    string `json:"sourceLineage,omitempty"`
}

type historyTxn struct {
	Version                    int `json:"version"`
	PlanID, LineageID, EventID string
	Record                     historyRecord
	SnapshotDigest             string
	Adoption                   *historyRecord `json:"Adoption,omitempty"`
	AdoptionDigest             string         `json:"AdoptionDigest,omitempty"`
	Prune                      []string       `json:"Prune,omitempty"`
	PruneDigest                string         `json:"PruneDigest,omitempty"`
}

type historyNameBinding struct {
	Version   int    `json:"version"`
	Name      string `json:"name"`
	LineageID string `json:"lineageId"`
}

type historyLineage struct {
	id      string
	records []historyRecord
	pins    map[string]bool
}

func randomHistoryID(prefix string) (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

func digestHex(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func revisionText(name string, present bool, data []byte) string {
	r := revision(name, present, data)
	return "pr_" + hex.EncodeToString(r.digest[:])
}

func openHistoryRoot(d *directory, mutate bool) (*os.File, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	if mutate {
		if err := d.r.step("history.mkdir", func() error {
			err := unix.Mkdirat(int(d.file.Fd()), "history", 0700)
			if errors.Is(err, unix.EEXIST) {
				return nil
			}
			return err
		}); err != nil {
			return nil, err
		}
		if err := d.r.step("history.parent-sync", d.file.Sync); err != nil {
			return nil, err
		}
	}
	var named unix.Stat_t
	if err := unix.Fstatat(int(d.file.Fd()), "history", &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	fd, err := unix.Openat(int(d.file.Fd()), "history", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "Profile history")
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0700 {
		return nil, errors.Join(ErrUnsafe, err, f.Close())
	}
	if !sameStat(&named, &st) {
		return nil, errors.Join(ErrUnsafe, f.Close())
	}
	return f, nil
}

func historyWriteNew(dir *os.File, name string, data []byte, limit int) (err error) {
	if len(data) > limit {
		return ErrUnsafe
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { err = errors.Join(err, f.Close()) }()
	if n, e := f.Write(data); e != nil || n != len(data) {
		return errors.Join(e, io.ErrShortWrite)
	}
	if err = f.Sync(); err != nil {
		return err
	}
	return nil
}

func historyRead(dir *os.File, name string, limit int) ([]byte, error) {
	var before unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, err
	}
	if !privateRegular(&before, 1) || before.Size < 0 || before.Size > int64(limit) {
		return nil, ErrUnsafe
	}
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil || len(data) > limit || int64(len(data)) != before.Size {
		return nil, errors.Join(ErrUnsafe, err)
	}
	var after unix.Stat_t
	if err = unix.Fstat(fd, &after); err != nil || !sameStat(&before, &after) || before.Size != after.Size || before.Mode != after.Mode || before.Nlink != after.Nlink {
		return nil, errors.Join(ErrUnsafe, err)
	}
	return data, nil
}

func openLineage(root *os.File, id string, create bool) (*os.File, error) {
	if !lineagePattern.MatchString(id) {
		return nil, ErrUnsafe
	}
	if create {
		if err := unix.Mkdirat(int(root.Fd()), id, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
			return nil, err
		}
		if err := root.Sync(); err != nil {
			return nil, err
		}
	}
	fd, err := unix.Openat(int(root.Fd()), id, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), id)
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Mode&07777 != 0700 {
		return nil, errors.Join(ErrUnsafe, err, f.Close())
	}
	return f, nil
}

func decodeStrict(data []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return ErrUnsafe
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, data) {
		return ErrUnsafe
	}
	return nil
}

func readLineage(root *os.File, id string) (historyLineage, error) {
	l := historyLineage{id: id, pins: map[string]bool{}}
	dir, err := openLineage(root, id, false)
	if err != nil {
		return l, err
	}
	defer dir.Close()
	names, err := dir.Readdirnames(maxEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return l, err
	}
	if len(names) > maxEntries {
		return l, ErrUnsafe
	}
	for _, name := range names {
		if name == "pins.json" {
			data, e := historyRead(dir, name, maxMetadataBytes)
			if e != nil {
				return l, e
			}
			var pins struct {
				Version int      `json:"version"`
				Events  []string `json:"events"`
			}
			if e = decodeStrict(data, &pins); e != nil || pins.Version != 1 || len(pins.Events) > MaxHistoryEvents {
				return l, ErrUnsafe
			}
			for _, event := range pins.Events {
				if !eventPattern.MatchString(event) {
					return l, ErrUnsafe
				}
				l.pins[event] = true
			}
			continue
		}
		if strings.HasSuffix(name, ".snapshot") {
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			return l, ErrUnsafe
		}
		idPart := strings.TrimSuffix(name, ".json")
		if !eventPattern.MatchString(idPart) {
			return l, ErrUnsafe
		}
		data, e := historyRead(dir, name, maxMetadataBytes)
		if e != nil {
			return l, e
		}
		var record historyRecord
		if e = decodeStrict(data, &record); e != nil || record.Version != 1 || record.LineageID != id || record.EventID != idPart || record.Sequence < 1 || !eventPattern.MatchString(record.EventID) || !namePattern.MatchString(record.SnapshotName) || len(record.SnapshotDigest) != 64 || len(record.ParentDigest) > 64 {
			return l, ErrUnsafe
		}
		l.records = append(l.records, record)
	}
	sort.Slice(l.records, func(i, j int) bool { return l.records[i].Sequence < l.records[j].Sequence })
	if len(l.records) > MaxHistoryEvents {
		return l, ErrQuota
	}
	seen := map[int]bool{}
	for _, r := range l.records {
		if seen[r.Sequence] {
			return l, ErrUnsafe
		}
		seen[r.Sequence] = true
		snapshot, e := historyRead(dir, r.EventID+".snapshot", MaxDocumentBytes)
		if e != nil || digestHex(snapshot) != r.SnapshotDigest || revisionText(r.SnapshotName, true, snapshot) != r.SnapshotRevision {
			return l, errors.Join(ErrUnsafe, e)
		}
		if !r.Tombstone && (r.SnapshotName != r.PostName || r.SnapshotRevision != r.PostRevision) {
			return l, ErrUnsafe
		}
	}
	return l, nil
}

func listLineageIDs(root *os.File) ([]string, error) {
	fd, err := unix.Openat(int(root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), "history scan")
	names, e := f.Readdirnames(maxEntries + 1)
	ce := f.Close()
	if e != nil && !errors.Is(e, io.EOF) {
		return nil, errors.Join(e, ce)
	}
	if ce != nil {
		return nil, ce
	}
	if len(names) > maxEntries {
		return nil, ErrUnsafe
	}
	ids := []string{}
	for _, n := range names {
		if lineagePattern.MatchString(n) {
			ids = append(ids, n)
		} else if strings.HasPrefix(n, "txn_") {
			continue
		} else if strings.HasPrefix(n, "name_") && strings.HasSuffix(n, ".json") {
			continue
		} else {
			return nil, ErrUnsafe
		}
	}
	sort.Strings(ids)
	return ids, nil
}

func resolveLineage(root *os.File, selector HistorySelector) (historyLineage, error) {
	if (selector.Name == "") == (selector.Lineage == "") {
		return historyLineage{}, ErrConflict
	}
	if selector.Lineage != "" {
		if !lineagePattern.MatchString(selector.Lineage) {
			return historyLineage{}, ErrConflict
		}
		return readLineage(root, selector.Lineage)
	}
	if !namePattern.MatchString(selector.Name) {
		return historyLineage{}, ErrConflict
	}
	data, err := historyRead(root, historyNameLeaf(selector.Name), maxMetadataBytes)
	if errors.Is(err, unix.ENOENT) {
		return historyLineage{}, ErrNotFound
	}
	if err != nil {
		return historyLineage{}, err
	}
	var binding historyNameBinding
	if err = decodeStrict(data, &binding); err != nil || binding.Version != 1 || binding.Name != selector.Name || !lineagePattern.MatchString(binding.LineageID) {
		return historyLineage{}, ErrUnsafe
	}
	l, err := readLineage(root, binding.LineageID)
	if err != nil {
		return historyLineage{}, err
	}
	if len(l.records) == 0 {
		return historyLineage{}, ErrUnsafe
	}
	head := l.records[len(l.records)-1]
	if head.Tombstone || head.PostName != selector.Name {
		return historyLineage{}, ErrUnsafe
	}
	return l, nil
}

func historyNameLeaf(name string) string {
	sum := sha256.Sum256([]byte("acs-profile-history-name-v1\x00" + name))
	return "name_" + hex.EncodeToString(sum[:]) + ".json"
}

func (r *Repository) History(ctx context.Context, selector HistorySelector, limit int) (HistoryResult, error) {
	result := HistoryResult{SchemaVersion: 1, Events: []HistoryEvent{}}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if limit < 1 || limit > DefaultHistoryKeep {
		return result, ErrConflict
	}
	d, err := r.open(false)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	defer d.close()
	root, err := openHistoryRoot(d, false)
	if errors.Is(err, os.ErrNotExist) {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	defer root.Close()
	l, err := resolveLineage(root, selector)
	if errors.Is(err, ErrNotFound) && selector.Name != "" {
		return result, nil
	}
	if err != nil {
		return result, err
	}
	result.LineageID = l.id
	start := len(l.records) - limit
	if start < 0 {
		start = 0
	}
	for i := len(l.records) - 1; i >= start; i-- {
		rec := l.records[i]
		state := "live"
		if rec.Tombstone {
			state = "deleted"
		}
		result.Events = append(result.Events, HistoryEvent{1, l.id, rec.EventID, rec.Operation, rec.CreatedAt, HistoryProfile{rec.PostName, state, rec.PostRevision}, l.pins[rec.EventID], true})
	}
	return result, nil
}

func (d *directory) historyPrepare(c change, p *plan) (result error) {
	root, err := openHistoryRoot(d, true)
	if err != nil {
		return err
	}
	defer root.Close()
	var source historyLineage
	if c.source != "" {
		source, err = resolveLineage(root, HistorySelector{Name: c.source})
		if errors.Is(err, ErrNotFound) {
			source = historyLineage{}
		} else if err != nil {
			return err
		}
	}
	lineage := source.id
	if c.op == "create" || c.op == "clone" || lineage == "" {
		lineage, err = randomHistoryID("ln_")
		if err != nil {
			return err
		}
	}
	if c.lineage != "" {
		if !lineagePattern.MatchString(c.lineage) {
			return ErrConflict
		}
		if source.id != "" && source.id != c.lineage {
			return ErrConflict
		}
		lineage = c.lineage
	}
	if c.op == "clone" {
		c.sourceLineage = source.id
		if c.sourceLineage == "" {
			c.sourceLineage, err = randomHistoryID("ln_")
			if err != nil {
				return err
			}
		}
	}
	event, err := randomHistoryID("ev_")
	if err != nil {
		return err
	}
	seq := 1
	parent := ""
	if len(source.records) > 0 {
		prev := source.records[len(source.records)-1]
		seq = prev.Sequence + 1
		b, _ := json.Marshal(prev)
		parent = digestHex(b)
	}
	preName, postName := c.source, c.destination
	if c.op == "replace" {
		postName = c.source
	}
	if c.op == "delete" {
		postName = c.source
	}
	if preName == "" {
		preName = postName
	}
	before := []byte(nil)
	if p.Before != nil {
		beforeObj, e := d.read(c.source+".json", MaxDocumentBytes, 1)
		if e != nil || beforeObj == nil {
			return errors.Join(ErrConflict, e)
		}
		before = beforeObj.bytes()
	}
	snapshot := append([]byte(nil), c.data...)
	snapshotName := postName
	if c.op == "delete" {
		snapshot = append([]byte(nil), before...)
		snapshotName = preName
	}
	if !namePattern.MatchString(snapshotName) {
		return ErrUnsafe
	}
	txn := historyTxn{Version: 1, PlanID: p.ID, LineageID: lineage, EventID: event}
	if len(source.records) == 0 && p.Before != nil {
		adoptionID, e := randomHistoryID("ev_")
		if e != nil {
			return e
		}
		adoptionLineage := lineage
		if c.op == "clone" {
			adoptionLineage = c.sourceLineage
		}
		adoption := historyRecord{Version: 1, LineageID: adoptionLineage, EventID: adoptionID, Sequence: 1, Operation: "adoption", CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), PreName: preName, PostName: preName, PreRevision: revisionText(preName, true, before), PostRevision: revisionText(preName, true, before), SnapshotName: preName, SnapshotRevision: revisionText(preName, true, before), SnapshotDigest: digestHex(before)}
		txn.Adoption, txn.AdoptionDigest = &adoption, adoption.SnapshotDigest
		adoptionBytes, _ := json.Marshal(adoption)
		if c.op != "clone" {
			parent, seq = digestHex(adoptionBytes), 2
		}
	}
	txn.Record = historyRecord{Version: 1, LineageID: lineage, EventID: event, Sequence: seq, ParentDigest: parent, Operation: c.historyOperation(), CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), PreName: preName, PostName: postName, PreRevision: revisionText(preName, p.Before != nil, before), PostRevision: revisionText(postName, c.op != "delete", c.data), SnapshotName: snapshotName, SnapshotRevision: revisionText(snapshotName, true, snapshot), SnapshotDigest: digestHex(snapshot), Tombstone: c.op == "delete", SourceLineage: c.sourceLineage}
	txn.SnapshotDigest = txn.Record.SnapshotDigest
	retained := historyLineage{id: lineage, pins: source.pins}
	if source.id == lineage {
		retained.records = append(retained.records, source.records...)
	}
	if txn.Adoption != nil && txn.Adoption.LineageID == lineage {
		retained.records = append(retained.records, *txn.Adoption)
	}
	retained.records = append(retained.records, txn.Record)
	txn.Prune = pruneCandidates(retained, DefaultHistoryKeep)
	if len(txn.Prune) > 0 {
		b, _ := json.Marshal(struct {
			Lineage string
			Keep    int
			IDs     []string
		}{lineage, DefaultHistoryKeep, txn.Prune})
		txn.PruneDigest = "hg_" + digestHex(b)
	}
	encoded, _ := json.Marshal(txn)
	p.HistoryDigest = digestHex(encoded)
	logical, e := historyLogicalBytes(root, lineage)
	if e != nil {
		return e
	}
	extra := int64(len(snapshot))
	count := len(retained.records) - len(txn.Prune)
	if txn.Adoption != nil && txn.Adoption.LineageID == lineage {
		extra += int64(len(before))
	}
	prunedBytes, e := historyCandidateBytes(root, lineage, txn.Prune)
	if e != nil {
		return e
	}
	if count > MaxHistoryEvents || logical+extra-prunedBytes > MaxHistoryBytes {
		return ErrQuota
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, d.historyAbort(p.ID))
		}
	}()
	if err = d.r.step("history.snapshot.prepare", func() error { return historyWriteNew(root, "txn_"+p.ID+".snapshot", snapshot, MaxDocumentBytes) }); err != nil {
		return err
	}
	if txn.Adoption != nil {
		if err = d.r.step("history.adoption.prepare", func() error { return historyWriteNew(root, "txn_"+p.ID+".adoption", before, MaxDocumentBytes) }); err != nil {
			return err
		}
	}
	if err = d.r.step("history.transaction.prepare", func() error { return historyWriteNew(root, "txn_"+p.ID+".json", encoded, maxMetadataBytes) }); err != nil {
		return err
	}
	return d.r.step("history.transaction.directory-sync", root.Sync)
}

func historyLogicalBytes(root *os.File, lineage string) (int64, error) {
	if lineage == "" {
		return 0, nil
	}
	l, e := readLineage(root, lineage)
	if errors.Is(e, unix.ENOENT) {
		return 0, nil
	}
	if e != nil {
		return 0, e
	}
	var n int64
	d, e := openLineage(root, lineage, false)
	if e != nil {
		return 0, e
	}
	defer d.Close()
	for _, r := range l.records {
		var st unix.Stat_t
		if e := unix.Fstatat(int(d.Fd()), r.EventID+".snapshot", &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
			return 0, e
		}
		if !privateRegular(&st, 1) || st.Size < 0 || st.Size > MaxDocumentBytes {
			return 0, ErrUnsafe
		}
		n += st.Size
	}
	return n, nil
}

func historyCandidateBytes(root *os.File, lineage string, ids []string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	dir, e := openLineage(root, lineage, false)
	if e != nil {
		return 0, e
	}
	defer dir.Close()
	var total int64
	for _, id := range ids {
		var st unix.Stat_t
		if e = unix.Fstatat(int(dir.Fd()), id+".snapshot", &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
			return 0, e
		}
		if !privateRegular(&st, 1) || st.Size < 0 || st.Size > MaxDocumentBytes {
			return 0, ErrUnsafe
		}
		total += st.Size
	}
	return total, nil
}

func (c change) historyOperation() string {
	if c.historyOp != "" {
		return c.historyOp
	}
	return c.op
}

func (d *directory) historyValidate(p *plan) error {
	if p == nil || p.Version != 2 || len(p.HistoryDigest) != 64 {
		return ErrUnsafe
	}
	root, err := openHistoryRoot(d, false)
	if err != nil {
		return err
	}
	defer root.Close()
	data, err := historyRead(root, "txn_"+p.ID+".json", maxMetadataBytes)
	if err != nil {
		return err
	}
	if digestHex(data) != p.HistoryDigest {
		return ErrUnsafe
	}
	var txn historyTxn
	if err = decodeStrict(data, &txn); err != nil {
		return err
	}
	snapshot, err := historyRead(root, "txn_"+p.ID+".snapshot", MaxDocumentBytes)
	if err != nil {
		return err
	}
	if err = validateHistoryTransaction(p, txn, snapshot); err != nil {
		return err
	}
	return nil
}

func validateHistoryTransaction(p *plan, txn historyTxn, snapshot []byte) error {
	if txn.Version != 1 || txn.PlanID != p.ID || txn.LineageID != txn.Record.LineageID || txn.EventID != txn.Record.EventID || !lineagePattern.MatchString(txn.LineageID) || !eventPattern.MatchString(txn.EventID) || digestHex(snapshot) != txn.SnapshotDigest || txn.Record.SnapshotDigest != txn.SnapshotDigest {
		return ErrUnsafe
	}
	rec := txn.Record
	if rec.Version != 1 || rec.Sequence < 1 || rec.PreName == "" || rec.PostName == "" || rec.CreatedAt == "" {
		return ErrUnsafe
	}
	pre, post := p.Source, p.Destination
	if p.Operation == "replace" || p.Operation == "delete" {
		post = p.Source
	}
	if pre == "" {
		pre = post
	}
	if rec.PreName != pre || rec.PostName != post {
		return ErrUnsafe
	}
	wantDigest := ""
	wantName := post
	if p.Operation == "delete" {
		if p.Before == nil || !rec.Tombstone {
			return ErrUnsafe
		}
		wantDigest = p.Before.Hash
		wantName = pre
		if rec.PostRevision != revisionText(post, false, nil) {
			return ErrUnsafe
		}
	} else {
		if p.Stage == nil || rec.Tombstone {
			return ErrUnsafe
		}
		wantDigest = p.Stage.Hash
		if rec.PostRevision != revisionText(post, true, snapshot) {
			return ErrUnsafe
		}
	}
	if rec.SnapshotName != wantName || rec.SnapshotDigest != wantDigest || rec.SnapshotRevision != revisionText(wantName, true, snapshot) {
		return ErrUnsafe
	}
	if p.Operation == "clone" {
		if rec.SourceLineage == "" || !lineagePattern.MatchString(rec.SourceLineage) {
			return ErrUnsafe
		}
	} else if rec.SourceLineage != "" {
		return ErrUnsafe
	}
	if txn.Adoption != nil {
		a := txn.Adoption
		wantAdoptionLineage := txn.LineageID
		if p.Operation == "clone" {
			wantAdoptionLineage = rec.SourceLineage
		}
		if a.LineageID != wantAdoptionLineage || a.EventID == rec.EventID || a.Sequence != 1 || a.Operation != "adoption" || a.PostName != pre || a.Tombstone || txn.AdoptionDigest != a.SnapshotDigest {
			return ErrUnsafe
		}
		if p.Operation != "clone" && rec.Sequence != 2 {
			return ErrUnsafe
		}
	}
	for _, id := range txn.Prune {
		if !eventPattern.MatchString(id) {
			return ErrUnsafe
		}
	}
	if len(txn.Prune) > 0 {
		b, _ := json.Marshal(struct {
			Lineage string
			Keep    int
			IDs     []string
		}{txn.LineageID, DefaultHistoryKeep, txn.Prune})
		if txn.PruneDigest != "hg_"+digestHex(b) {
			return ErrUnsafe
		}
	} else if txn.PruneDigest != "" {
		return ErrUnsafe
	}
	return nil
}

func (d *directory) historyCommit(p *plan) error {
	planID := p.ID
	root, err := openHistoryRoot(d, false)
	if err != nil {
		return err
	}
	defer root.Close()
	data, err := historyRead(root, "txn_"+planID+".json", maxMetadataBytes)
	if err != nil {
		return err
	}
	if digestHex(data) != p.HistoryDigest {
		return ErrUnsafe
	}
	var txn historyTxn
	if err = decodeStrict(data, &txn); err != nil || txn.Version != 1 || txn.PlanID != planID || !lineagePattern.MatchString(txn.LineageID) || !eventPattern.MatchString(txn.EventID) {
		return ErrUnsafe
	}
	snapshot, err := historyRead(root, "txn_"+planID+".snapshot", MaxDocumentBytes)
	if err != nil || digestHex(snapshot) != txn.SnapshotDigest {
		return errors.Join(ErrUnsafe, err)
	}
	dir, err := openLineage(root, txn.LineageID, true)
	if err != nil {
		return err
	}
	defer dir.Close()
	if txn.Adoption != nil {
		if !lineagePattern.MatchString(txn.Adoption.LineageID) || !eventPattern.MatchString(txn.Adoption.EventID) || txn.Adoption.Sequence != 1 || txn.Adoption.Operation != "adoption" {
			return ErrUnsafe
		}
		adopted, e := historyRead(root, "txn_"+planID+".adoption", MaxDocumentBytes)
		if e != nil || digestHex(adopted) != txn.AdoptionDigest || txn.Adoption.SnapshotDigest != txn.AdoptionDigest {
			return errors.Join(ErrUnsafe, e)
		}
		adoptionDir := dir
		if txn.Adoption.LineageID != txn.LineageID {
			adoptionDir, e = openLineage(root, txn.Adoption.LineageID, true)
			if e != nil {
				return e
			}
			defer adoptionDir.Close()
		}
		if e = publishHistoryRecord(d, adoptionDir, *txn.Adoption, adopted); e != nil {
			return e
		}
	}
	if err = publishHistoryRecord(d, dir, txn.Record, snapshot); err != nil {
		return err
	}
	e := error(nil)
	if txn.Record.PreName != "" && (txn.Record.Tombstone || txn.Record.PreName != txn.Record.PostName) {
		if e = unix.Unlinkat(int(root.Fd()), historyNameLeaf(txn.Record.PreName), 0); e != nil && !errors.Is(e, unix.ENOENT) {
			return e
		}
		if e = root.Sync(); e != nil {
			return e
		}
	}
	if !txn.Record.Tombstone {
		binding, _ := json.Marshal(historyNameBinding{1, txn.Record.PostName, txn.LineageID})
		leaf := historyNameLeaf(txn.Record.PostName)
		existing, e := historyRead(root, leaf, maxMetadataBytes)
		if e == nil && !bytes.Equal(existing, binding) {
			return ErrConflict
		}
		if errors.Is(e, unix.ENOENT) {
			if e = historyWriteNew(root, leaf, binding, maxMetadataBytes); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		if e = root.Sync(); e != nil {
			return e
		}
	}
	if txn.Adoption != nil && txn.Adoption.LineageID != txn.LineageID {
		binding, _ := json.Marshal(historyNameBinding{1, txn.Adoption.PostName, txn.Adoption.LineageID})
		leaf := historyNameLeaf(txn.Adoption.PostName)
		existing, e := historyRead(root, leaf, maxMetadataBytes)
		if e == nil && !bytes.Equal(existing, binding) {
			return ErrConflict
		}
		if errors.Is(e, unix.ENOENT) {
			if e = historyWriteNew(root, leaf, binding, maxMetadataBytes); e != nil {
				return e
			}
		} else if e != nil {
			return e
		}
		if e = root.Sync(); e != nil {
			return e
		}
	}
	if len(txn.Prune) > 0 {
		if e = commitBoundPrune(dir, txn.PruneDigest, txn.Prune); e != nil {
			return e
		}
	}
	// Keep the transaction witnesses until the repository complete receipt is
	// durable. A retry can then validate the same snapshot/event pair.
	return nil
}

func commitBoundPrune(dir *os.File, digest string, ids []string) error {
	if pending, e := readPruneJournal(dir); e == nil {
		if pending.Digest != digest || !slices.Equal(pending.Events, ids) {
			return ErrUnsafe
		}
		return completePrune(dir, ids)
	} else if !errors.Is(e, unix.ENOENT) {
		return e
	}
	encoded, _ := json.Marshal(pruneJournal{1, digest, ids})
	if e := historyWriteNew(dir, "prune.json", encoded, maxMetadataBytes); e != nil {
		return e
	}
	if e := dir.Sync(); e != nil {
		return e
	}
	return completePrune(dir, ids)
}

func publishHistoryRecord(d *directory, dir *os.File, record historyRecord, snapshot []byte) error {
	snapshotLeaf := record.EventID + ".snapshot"
	existingSnapshot, err := historyRead(dir, snapshotLeaf, MaxDocumentBytes)
	if errors.Is(err, unix.ENOENT) {
		if err = d.r.step("history.event-snapshot.publish", func() error { return historyWriteNew(dir, snapshotLeaf, snapshot, MaxDocumentBytes) }); err != nil {
			return err
		}
	} else if err != nil || !bytes.Equal(existingSnapshot, snapshot) {
		return errors.Join(ErrUnsafe, err)
	}
	if err = d.r.step("history.event-snapshot.directory-sync", dir.Sync); err != nil {
		return err
	}
	encoded, _ := json.Marshal(record)
	existingRecord, err := historyRead(dir, record.EventID+".json", maxMetadataBytes)
	if errors.Is(err, unix.ENOENT) {
		if err = d.r.step("history.event.publish", func() error { return historyWriteNew(dir, record.EventID+".json", encoded, maxMetadataBytes) }); err != nil {
			return err
		}
	} else if err != nil || !bytes.Equal(existingRecord, encoded) {
		return errors.Join(ErrUnsafe, err)
	}
	return d.r.step("history.event.directory-sync", dir.Sync)
}

func (d *directory) historyAbort(planID string) error {
	root, err := openHistoryRoot(d, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	for _, name := range []string{"txn_" + planID + ".json", "txn_" + planID + ".snapshot", "txn_" + planID + ".adoption"} {
		if e := unix.Unlinkat(int(root.Fd()), name, 0); e != nil && !errors.Is(e, unix.ENOENT) {
			return e
		}
	}
	return root.Sync()
}

func (d *directory) historyAbortOrphans(keep string) error {
	root, err := openHistoryRoot(d, false)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	fd, err := unix.Openat(int(root.Fd()), ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	scan := os.NewFile(uintptr(fd), "history transaction scan")
	names, e := scan.Readdirnames(maxEntries + 1)
	closeErr := scan.Close()
	if e != nil && !errors.Is(e, io.EOF) {
		return errors.Join(e, closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if len(names) > maxEntries {
		return ErrUnsafe
	}
	targets := []string{}
	for _, name := range names {
		if !strings.HasPrefix(name, "txn_") {
			continue
		}
		suffix := ""
		for _, candidate := range []string{".json", ".snapshot", ".adoption"} {
			if strings.HasSuffix(name, candidate) {
				suffix = candidate
				break
			}
		}
		id := strings.TrimSuffix(strings.TrimPrefix(name, "txn_"), suffix)
		if suffix == "" || len(id) != 32 {
			return ErrUnsafe
		}
		if _, e := hex.DecodeString(id); e != nil || strings.ToLower(id) != id {
			return ErrUnsafe
		}
		if id == keep {
			continue
		}
		if _, e = historyRead(root, name, func() int {
			if suffix == ".json" {
				return maxMetadataBytes
			}
			return MaxDocumentBytes
		}()); e != nil {
			return e
		}
		targets = append(targets, name)
	}
	sort.Strings(targets)
	for _, name := range targets {
		if e = d.r.step("history.orphan.remove", func() error {
			e := unix.Unlinkat(int(root.Fd()), name, 0)
			if errors.Is(e, unix.ENOENT) {
				return nil
			}
			return e
		}); e != nil {
			return e
		}
		if e = d.r.step("history.orphan.directory-sync", root.Sync); e != nil {
			return e
		}
	}
	return nil
}

func (r *Repository) HistorySnapshot(ctx context.Context, selector HistorySelector, event string) (historyRecord, []byte, error) {
	if err := ctx.Err(); err != nil {
		return historyRecord{}, nil, err
	}
	if !eventPattern.MatchString(event) {
		return historyRecord{}, nil, ErrConflict
	}
	d, err := r.open(false)
	if err != nil {
		return historyRecord{}, nil, err
	}
	defer d.close()
	root, err := openHistoryRoot(d, false)
	if err != nil {
		return historyRecord{}, nil, err
	}
	defer root.Close()
	l, err := resolveLineage(root, selector)
	if err != nil {
		return historyRecord{}, nil, err
	}
	for _, rec := range l.records {
		if rec.EventID == event {
			d, e := openLineage(root, l.id, false)
			if e != nil {
				return rec, nil, e
			}
			defer d.Close()
			b, e := historyRead(d, event+".snapshot", MaxDocumentBytes)
			if e != nil || digestHex(b) != rec.SnapshotDigest {
				return rec, nil, errors.Join(ErrUnsafe, e)
			}
			return rec, b, nil
		}
	}
	return historyRecord{}, nil, ErrNotFound
}

func (r *Repository) SetHistoryPin(ctx context.Context, lineage, event string, pin bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	d, err := r.open(true)
	if err != nil {
		return err
	}
	defer d.close()
	if err = d.lock(); err != nil {
		return err
	}
	defer d.release()
	if _, err = d.recover(ctx); err != nil {
		return err
	}
	root, err := openHistoryRoot(d, false)
	if err != nil {
		return err
	}
	defer root.Close()
	l, err := resolveLineage(root, HistorySelector{Lineage: lineage})
	if err != nil {
		return err
	}
	found := false
	for _, v := range l.records {
		found = found || v.EventID == event
	}
	if !found {
		return ErrNotFound
	}
	if pin {
		l.pins[event] = true
	} else {
		delete(l.pins, event)
	}
	events := make([]string, 0, len(l.pins))
	for id := range l.pins {
		events = append(events, id)
	}
	sort.Strings(events)
	encoded, _ := json.Marshal(struct {
		Version int      `json:"version"`
		Events  []string `json:"events"`
	}{1, events})
	dir, err := openLineage(root, lineage, false)
	if err != nil {
		return err
	}
	defer dir.Close()
	_ = unix.Unlinkat(int(dir.Fd()), "pins.next", 0)
	if err = historyWriteNew(dir, "pins.next", encoded, maxMetadataBytes); err != nil {
		return err
	}
	if err = unix.Renameat(int(dir.Fd()), "pins.next", int(dir.Fd()), "pins.json"); err != nil {
		return err
	}
	return dir.Sync()
}

type PrunePreview struct {
	SchemaVersion  int    `json:"schemaVersion"`
	LineageID      string `json:"lineageId"`
	Keep           int    `json:"keep"`
	CandidateCount int    `json:"candidateCount"`
	Digest         string `json:"digest"`
}

type RestoreSnapshot struct {
	LineageID string
	EventID   string
	Name      string
	Bytes     []byte
}

func (r *Repository) RestoreSnapshot(ctx context.Context, selector HistorySelector, event string) (RestoreSnapshot, error) {
	record, data, err := r.HistorySnapshot(ctx, selector, event)
	if err != nil {
		return RestoreSnapshot{}, err
	}
	return RestoreSnapshot{LineageID: record.LineageID, EventID: record.EventID, Name: record.SnapshotName, Bytes: data}, nil
}

func (r *Repository) PreviewPrune(ctx context.Context, lineage string, keep int) (PrunePreview, error) {
	p := PrunePreview{SchemaVersion: 1, LineageID: lineage, Keep: keep}
	if keep < 1 || keep > 100 {
		return p, ErrConflict
	}
	d, e := r.open(false)
	if e != nil {
		return p, e
	}
	defer d.close()
	root, e := openHistoryRoot(d, false)
	if e != nil {
		return p, e
	}
	defer root.Close()
	return previewPruneRoot(root, lineage, keep)
}

func previewPruneRoot(root *os.File, lineage string, keep int) (PrunePreview, error) {
	p := PrunePreview{SchemaVersion: 1, LineageID: lineage, Keep: keep}
	l, e := resolveLineage(root, HistorySelector{Lineage: lineage})
	if e != nil {
		return p, e
	}
	ids := pruneCandidates(l, keep)
	p.CandidateCount = len(ids)
	b, _ := json.Marshal(struct {
		Lineage string
		Keep    int
		IDs     []string
	}{lineage, keep, ids})
	p.Digest = "hg_" + digestHex(b)
	return p, nil
}

func pruneCandidates(l historyLineage, keep int) []string {
	ids := []string{}
	ordinary := 0
	for i := len(l.records) - 1; i >= 0; i-- {
		rec := l.records[i]
		// Keep pins, the current head, and the immediate recoverable predecessor.
		if l.pins[rec.EventID] || i == len(l.records)-2 {
			continue
		}
		ordinary++
		if ordinary > keep {
			ids = append(ids, rec.EventID)
		}
	}
	sort.Strings(ids)
	return ids
}

// Prune rechecks the exact passive preview under the repository mutation lock.
// Each independently complete snapshot is removed record-first only after the
// candidate set is durably journaled by its digest; an interrupted pass is safe
// to repeat because missing candidates are treated as already collected.
func (r *Repository) Prune(ctx context.Context, lineage string, keep int, expected string) (PrunePreview, error) {
	preview := PrunePreview{SchemaVersion: 1, LineageID: lineage, Keep: keep}
	if keep < 1 || keep > 100 || expected == "" {
		return preview, ErrConflict
	}
	d, err := r.open(true)
	if err != nil {
		return preview, err
	}
	defer d.close()
	if err = d.lock(); err != nil {
		return preview, err
	}
	defer d.release()
	if _, err = d.recover(ctx); err != nil {
		return preview, err
	}
	root, err := openHistoryRoot(d, false)
	if err != nil {
		return preview, err
	}
	defer root.Close()
	dir, err := openLineage(root, lineage, false)
	if err != nil {
		return preview, err
	}
	defer dir.Close()
	if pending, e := readPruneJournal(dir); e == nil {
		if e = completePrune(dir, pending.Events); e != nil {
			return preview, e
		}
		if pending.Digest == expected {
			return PrunePreview{1, lineage, keep, len(pending.Events), expected}, nil
		}
	} else if !errors.Is(e, unix.ENOENT) {
		return preview, e
	}
	current, err := previewPruneRoot(root, lineage, keep)
	if err != nil || current.Digest != expected {
		return current, errors.Join(ErrConflict, err)
	}
	l, err := resolveLineage(root, HistorySelector{Lineage: lineage})
	if err != nil {
		return current, err
	}
	ids := pruneCandidates(l, keep)
	journal, _ := json.Marshal(struct {
		Version int      `json:"version"`
		Digest  string   `json:"digest"`
		Events  []string `json:"events"`
	}{1, expected, ids})
	_ = unix.Unlinkat(int(dir.Fd()), "prune.json", 0)
	if err = historyWriteNew(dir, "prune.json", journal, maxMetadataBytes); err != nil {
		return current, err
	}
	if err = dir.Sync(); err != nil {
		return current, err
	}
	if err = completePrune(dir, ids); err != nil {
		return current, err
	}
	return current, nil
}

type pruneJournal struct {
	Version int      `json:"version"`
	Digest  string   `json:"digest"`
	Events  []string `json:"events"`
}

func readPruneJournal(dir *os.File) (pruneJournal, error) {
	data, e := historyRead(dir, "prune.json", maxMetadataBytes)
	if e != nil {
		return pruneJournal{}, e
	}
	var p pruneJournal
	if e = decodeStrict(data, &p); e != nil || p.Version != 1 || len(p.Events) > MaxHistoryEvents {
		return p, ErrUnsafe
	}
	for _, id := range p.Events {
		if !eventPattern.MatchString(id) {
			return p, ErrUnsafe
		}
	}
	return p, nil
}
func completePrune(dir *os.File, ids []string) error {
	for _, id := range ids {
		for _, suffix := range []string{".json", ".snapshot"} {
			if e := unix.Unlinkat(int(dir.Fd()), id+suffix, 0); e != nil && !errors.Is(e, unix.ENOENT) {
				return e
			}
			if e := dir.Sync(); e != nil {
				return e
			}
		}
	}
	if e := unix.Unlinkat(int(dir.Fd()), "prune.json", 0); e != nil && !errors.Is(e, unix.ENOENT) {
		return e
	}
	return dir.Sync()
}

func (d *directory) historyRecoverMaintenance(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	root, err := openHistoryRoot(d, false)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	ids, err := listLineageIDs(root)
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err = ctx.Err(); err != nil {
			return err
		}
		dir, e := openLineage(root, id, false)
		if e != nil {
			continue
		}
		lineageFailed := false
		if next, e := historyRead(dir, "pins.next", maxMetadataBytes); e == nil {
			var pins struct {
				Version int      `json:"version"`
				Events  []string `json:"events"`
			}
			if e = decodeStrict(next, &pins); e != nil || pins.Version != 1 || len(pins.Events) > MaxHistoryEvents {
				lineageFailed = true
			}
			for _, event := range pins.Events {
				if !eventPattern.MatchString(event) {
					lineageFailed = true
				}
			}
			if !lineageFailed {
				if e = unix.Renameat(int(dir.Fd()), "pins.next", int(dir.Fd()), "pins.json"); e != nil {
					lineageFailed = true
				}
				if !lineageFailed {
					if e = dir.Sync(); e != nil {
						lineageFailed = true
					}
				}
			}
		} else if !errors.Is(e, unix.ENOENT) {
			lineageFailed = true
		}
		if !lineageFailed {
			if pending, e := readPruneJournal(dir); e == nil {
				if e = completePrune(dir, pending.Events); e != nil {
					lineageFailed = true
				}
			} else if !errors.Is(e, unix.ENOENT) {
				lineageFailed = true
			}
		}
		_ = dir.Close()
	}
	return nil
}
