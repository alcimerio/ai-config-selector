package exclusionintent

import (
	"fmt"
	"strings"
)

// AdvisoryKind classifies a non-fatal redundancy between two exclusion entries.
type AdvisoryKind string

const (
	// AdvisoryNested reports an entry already covered by a directory entry.
	AdvisoryNested AdvisoryKind = "nested"
	// AdvisoryCaseDuplicate reports entries whose paths differ only by letter
	// case. macOS APFS volumes are case-insensitive by default, so both name the
	// same host path.
	AdvisoryCaseDuplicate AdvisoryKind = "case-duplicate"
)

// Advisory is a warning about a valid selection. Advisories never make a
// selection invalid: existing Profiles that contain them keep loading and
// enforcing exactly as stored. Messages name entry IDs only so local-absolute
// paths stay redacted wherever the warning is shown.
type Advisory struct {
	Kind AdvisoryKind
	// ID is the redundant entry; Covering is the entry that already covers it.
	ID       string
	Covering string
}

func (advisory Advisory) String() string {
	switch advisory.Kind {
	case AdvisoryNested:
		return fmt.Sprintf("exclusion %q is redundant: directory exclusion %q already covers its path", advisory.ID, advisory.Covering)
	case AdvisoryCaseDuplicate:
		return fmt.Sprintf("exclusions %q and %q differ only by letter case and name the same path on case-insensitive macOS volumes", advisory.Covering, advisory.ID)
	default:
		return fmt.Sprintf("exclusion %q overlaps %q", advisory.ID, advisory.Covering)
	}
}

// Advisories reports redundant entries in a selection: entries nested under a
// directory entry with the same reference kind, and entries that differ only by
// letter case. Comparison is case-insensitive because APFS is. Entries with
// different reference kinds are not compared because that would require
// resolving the workspace. An invalid selection has no advisories; Canonical
// reports its error instead.
func Advisories(selection Selection) []Advisory {
	canonical, err := Canonical(selection)
	if err != nil {
		return nil
	}
	var result []Advisory
	entries := canonical.Entries
	for i := range entries {
		for j := range entries {
			if i == j || entries[i].Reference.Kind != entries[j].Reference.Kind {
				continue
			}
			covering, candidate := entries[i], entries[j]
			coveringPath, candidatePath := foldPath(covering.Reference.Path), foldPath(candidate.Reference.Path)
			switch {
			case coveringPath == candidatePath:
				// Report each case-only pair once, in ID order.
				if i < j {
					result = append(result, Advisory{Kind: AdvisoryCaseDuplicate, ID: candidate.ID, Covering: covering.ID})
				}
			case covering.Type == TypeDirectory && strings.HasPrefix(candidatePath, strings.TrimSuffix(coveringPath, "/")+"/"):
				result = append(result, Advisory{Kind: AdvisoryNested, ID: candidate.ID, Covering: covering.ID})
			}
		}
	}
	return result
}

// foldPath approximates APFS case-insensitive comparison for canonical paths.
func foldPath(path string) string { return strings.ToLower(path) }
