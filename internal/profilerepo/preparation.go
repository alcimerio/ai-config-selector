package profilerepo

import "strings"

// preparationPrefix recognizes prefixes of the canonical current plan language,
// not arbitrary JSON following a magic header. It is bounded by metadata size,
// five alternatives, fixed field order and individually bounded scalar tokens.
// EOF inside a valid token is abortable; impossible bytes remain evidence.
func preparationPrefix(data []byte) bool {
	if len(data) > maxMetadataBytes {
		return false
	}
	for _, op := range []string{"create", "replace", "clone", "rename", "delete"} {
		p := prefixParser{data: data}
		p.literal(`{"Version":1,"ID":"`)
		p.hex(32)
		p.literal(`","Operation":"` + op + `","Source":"`)
		source := ""
		if op != "create" {
			source = p.name()
		}
		p.literal(`","Destination":"`)
		destination := ""
		if op == "create" || op == "clone" || op == "rename" {
			destination = p.name()
		}
		// Once both spellings are closed (or destination has no room to extend),
		// an alias cannot be extended into any valid two-name plan.
		if source != "" && destination != "" && strings.EqualFold(source, destination) && (!p.partial || len(destination) == 64) {
			p.invalid = true
		}
		p.literal(`","Before":`)
		if op == "create" {
			p.literal("null")
		} else {
			p.identity()
		}
		p.literal(`,"Stage":`)
		if op == "delete" {
			p.literal("null")
		} else {
			p.identity()
		}
		p.literal("}")
		if !p.invalid && (p.partial || p.pos == len(data)) {
			return true
		}
	}
	return false
}

type prefixParser struct {
	data             []byte
	pos              int
	partial, invalid bool
}

func (p *prefixParser) literal(value string) {
	if p.partial || p.invalid {
		return
	}
	for i := 0; i < len(value); i++ {
		if p.pos == len(p.data) {
			p.partial = true
			return
		}
		if p.data[p.pos] != value[i] {
			p.invalid = true
			return
		}
		p.pos++
	}
}
func (p *prefixParser) hex(length int) {
	if p.partial || p.invalid {
		return
	}
	for i := 0; i < length; i++ {
		if p.pos == len(p.data) {
			p.partial = true
			return
		}
		b := p.data[p.pos]
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			p.invalid = true
			return
		}
		p.pos++
	}
}
func (p *prefixParser) name() string {
	if p.partial || p.invalid {
		return ""
	}
	start := p.pos
	for p.pos < len(p.data) && p.data[p.pos] != '"' {
		b := p.data[p.pos]
		alnum := b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
		if p.pos-start >= 64 || !alnum && (p.pos == start || b != '.' && b != '_' && b != '-') {
			p.invalid = true
			return ""
		}
		p.pos++
	}
	if p.pos == len(p.data) {
		p.partial = true
	} else if p.pos == start {
		p.invalid = true
	}
	return string(p.data[start:p.pos])
}
func (p *prefixParser) number(max uint64, positive bool) {
	if p.partial || p.invalid {
		return
	}
	start := p.pos
	var value uint64
	for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
		digit := uint64(p.data[p.pos] - '0')
		if p.pos > start && p.data[start] == '0' || value > max/10 || value == max/10 && digit > max%10 {
			p.invalid = true
			return
		}
		value = value*10 + digit
		p.pos++
	}
	if p.pos == start {
		if p.pos == len(p.data) {
			p.partial = true
		} else {
			p.invalid = true
		}
		return
	}
	if positive && value == 0 {
		p.invalid = true
		return
	}
	if p.pos == len(p.data) {
		p.partial = true
	}
}
func (p *prefixParser) identity() {
	p.literal(`{"Device":`)
	p.number(^uint64(0), false)
	p.literal(`,"Inode":`)
	p.number(^uint64(0), true)
	p.literal(`,"Size":`)
	p.number(MaxDocumentBytes, false)
	p.literal(`,"Hash":"`)
	p.hex(64)
	p.literal(`"}`)
}
