package sessionops

import (
	"container/heap"
	"os"
	"sort"
	"strings"
)

const (
	scanBatchSize       = 256
	MaxListPageSize     = 512
	maintenancePageSize = 256
)

// recordPage bounds retained names and later record reads, not filename
// enumeration. Directory offsets are not stable cross-process cursors, so each
// page streams all names and selects the next lexical IDs without trusting order.
func (store Store) recordPage(after string, limit int) ([]string, bool, error) {
	return selectIDPage(after, limit, store.storage.records.walkEntries)
}

func selectIDPage(after string, limit int, walk func(func(os.DirEntry) error) error) ([]string, bool, error) {
	ids := &maxIDs{}
	selected := make(map[string]bool, limit+1)
	err := walk(func(entry os.DirEntry) error {
		id := recordEntryID(entry)
		if id == "" || id <= after || selected[id] {
			return nil
		}
		if ids.Len() < limit+1 {
			heap.Push(ids, id)
			selected[id] = true
		} else if id < (*ids)[0] {
			delete(selected, (*ids)[0])
			(*ids)[0] = id
			selected[id] = true
			heap.Fix(ids, 0)
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	sort.Strings(*ids)
	more := ids.Len() > limit
	if more {
		*ids = (*ids)[:limit]
	}
	return []string(*ids), more, nil
}

func recordEntryID(entry os.DirEntry) string {
	if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
		return ""
	}
	id := strings.TrimSuffix(entry.Name(), ".json")
	if !ValidID(id) {
		return ""
	}
	return id
}

type maxIDs []string

func (ids maxIDs) Len() int           { return len(ids) }
func (ids maxIDs) Less(i, j int) bool { return ids[i] > ids[j] }
func (ids maxIDs) Swap(i, j int)      { ids[i], ids[j] = ids[j], ids[i] }
func (ids *maxIDs) Push(value any)    { *ids = append(*ids, value.(string)) }
func (ids *maxIDs) Pop() any {
	last := len(*ids) - 1
	value := (*ids)[last]
	*ids = (*ids)[:last]
	return value
}
