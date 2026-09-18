package codexauthresource_test

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const nativeAgentRoleName = "acs-reviewer"
const nativeAgentRoleDescription = "Synthetic assessment reviewer"
const nativeAgentRoleDefinition = "name = \"acs-reviewer\"\ndescription = \"Synthetic assessment reviewer\"\ndeveloper_instructions = \"Return ACS_AGENT_OK only.\"\n"

// Decode bounded JSON with duplicate-member rejection. Catalog identity must
// come from a real spawn schema, never an echoed message or developer text.
func nativeAgentCatalogJSON(body string) (map[string]any, error) {
	if len(body) > 2<<20 {
		return nil, errors.New("agent catalog request cap")
	}
	d := json.NewDecoder(strings.NewReader(body))
	d.UseNumber()
	nodes := 0
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		nodes++
		if depth > 32 || nodes > 32768 {
			return nil, errors.New("agent catalog structure cap")
		}
		v, e := d.Token()
		if e != nil {
			return nil, e
		}
		switch v {
		case json.Delim('{'):
			m := map[string]any{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return nil, e
				}
				key, ok := k.(string)
				if !ok {
					return nil, errors.New("nonstring JSON key")
				}
				if _, ok = m[key]; ok {
					return nil, errors.New("duplicate JSON key")
				}
				x, e := read(depth + 1)
				if e != nil {
					return nil, e
				}
				m[key] = x
			}
			v, e = d.Token()
			if e != nil || v != json.Delim('}') {
				return nil, errors.New("object end")
			}
			return m, nil
		case json.Delim('['):
			var a []any
			for d.More() {
				x, e := read(depth + 1)
				if e != nil {
					return nil, e
				}
				a = append(a, x)
			}
			v, e = d.Token()
			if e != nil || v != json.Delim(']') {
				return nil, errors.New("array end")
			}
			return a, nil
		default:
			return v, nil
		}
	}
	v, e := read(0)
	if e != nil {
		return nil, e
	}
	if _, e = d.Token(); e != io.EOF {
		return nil, errors.New("trailing JSON")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("request object required")
	}
	return m, nil
}
func assertNativeAgentCatalog(body string, present bool) error {
	request, e := nativeAgentCatalogJSON(body)
	if e != nil {
		return errors.New("agent catalog invalid bounded JSON")
	}
	var inventory []any
	envelopes := 0
	if x, ok := request["tools"]; ok && x != nil {
		var good bool
		inventory, good = x.([]any)
		if !good {
			return errors.New("invalid tools array")
		}
		envelopes++
	}
	if x, ok := request["input"]; ok {
		input, good := x.([]any)
		if !good {
			return errors.New("invalid input array")
		}
		for _, x := range input {
			item, good := x.(map[string]any)
			if !good {
				return errors.New("invalid input item")
			}
			if item["type"] == "additional_tools" {
				if item["role"] != "developer" {
					return errors.New("invalid catalog role")
				}
				inventory, good = item["tools"].([]any)
				if !good {
					return errors.New("invalid additional tools")
				}
				envelopes++
			}
		}
	}
	if envelopes != 1 {
		return errors.New("agent catalog requires exactly one tool inventory")
	}
	var spawn map[string]any
	count := 0
	var walk func([]any, string, int) error
	walk = func(items []any, namespace string, depth int) error {
		if depth > 4 {
			return errors.New("namespace nesting cap")
		}
		names := map[string]bool{}
		for _, x := range items {
			item, ok := x.(map[string]any)
			if !ok {
				return errors.New("tool object required")
			}
			kind, ok := item["type"].(string)
			if !ok {
				return errors.New("tool type required")
			}
			name, _ := item["name"].(string)
			if name != "" {
				if names[name] {
					return errors.New("duplicate tool identity")
				}
				names[name] = true
			}
			switch kind {
			case "namespace":
				if depth != 0 {
					return errors.New("nested namespace is not an established catalog envelope")
				}
				if name == "" {
					return errors.New("namespace identity required")
				}
				children, ok := item["tools"].([]any)
				if !ok {
					return errors.New("namespace tools required")
				}
				if e := walk(children, name, depth+1); e != nil {
					return e
				}
			case "function":
				if name == "spawn_agent" {
					if namespace != "" && namespace != "functions" && namespace != "multi_agent_v1" && namespace != "collaboration" {
						return errors.New("unestablished spawn namespace")
					}
					count++
					spawn = item
				}
			case "custom", "tool_search", "web_search":
			default:
				return errors.New("unknown tool declaration type")
			}
		}
		return nil
	}
	if e = walk(inventory, "", 0); e != nil {
		return e
	}
	if count != 1 {
		return errors.New("full spawn schema absent or ambiguous; exposure discriminator unresolved")
	}
	if spawn["defer_loading"] == true {
		return errors.New("spawn schema deferred; no catalog inferred")
	}
	params, ok := spawn["parameters"].(map[string]any)
	if !ok {
		return errors.New("spawn parameters unavailable")
	}
	props, ok := params["properties"].(map[string]any)
	if !ok {
		return errors.New("spawn properties unavailable")
	}
	raw, exists := props["agent_type"]
	if !exists {
		if present {
			return errors.New("custom agent_type missing")
		}
		return nil
	}
	role, ok := raw.(map[string]any)
	if !ok || role["type"] != "string" {
		return errors.New("agent_type string schema required")
	}
	desc, ok := role["description"].(string)
	if !ok || len(desc) > 65536 {
		return errors.New("agent_type description unavailable")
	}
	header := "Available roles:\n"
	if strings.Count(desc, header) != 1 {
		return errors.New("role catalog heading missing or ambiguous")
	}
	catalog := strings.SplitN(desc, header, 2)[1]
	entries := map[string]string{}
	lines := strings.Split(catalog, "\n")
	for i := 0; i < len(lines); i++ {
		name, suffix, found := strings.Cut(lines[i], ": ")
		if !found || name == "" || strings.ContainsAny(name, " {}\t\r") {
			return errors.New("invalid top-level role identity")
		}
		if _, exists := entries[name]; exists {
			return errors.New("duplicate top-level role identity")
		}
		if suffix == "no description" {
			entries[name] = ""
			continue
		}
		if suffix != "{" {
			return errors.New("unestablished role entry")
		}
		start := i + 1
		for i++; i < len(lines) && lines[i] != "}"; i++ {
		}
		if i == len(lines) {
			return errors.New("unterminated role entry")
		}
		entries[name] = strings.Join(lines[start:i], "\n")
	}
	got, exists := entries[nativeAgentRoleName]
	if present {
		if !exists || got != nativeAgentRoleDescription {
			return errors.New("selected custom role catalog entry missing or incorrect")
		}
	} else if exists || strings.Contains(catalog, nativeAgentRoleDescription) {
		return errors.New("absent role appeared in catalog")
	}
	return nil
}

// The target is paused at the verified ready/release boundary. Pin every
// directory and refuse aliases instead of resolving host-side writes through
// target-controlled .codex/agents path components.
func seedNativeAgentRole(home string, present bool) error {
	if !filepath.IsAbs(home) || filepath.Clean(home) != home || home == "/" {
		return errors.New("role fixture HOME must be an absolute clean directory")
	}
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	root, err := unix.Open("/", flags, 0)
	if err != nil {
		return errors.New("role fixture root unavailable")
	}
	descriptors := []int{root}
	defer func() {
		for i := len(descriptors) - 1; i >= 0; i-- {
			_ = unix.Close(descriptors[i])
		}
	}()
	current := root
	for _, component := range strings.Split(strings.TrimPrefix(home, "/"), "/") {
		next, err := unix.Openat(current, component, flags, 0)
		if err != nil {
			return errors.New("role fixture HOME ancestor unsafe or unavailable")
		}
		descriptors = append(descriptors, next)
		current = next
	}
	for _, component := range []string{".codex", "agents"} {
		next, err := unix.Openat(current, component, flags, 0)
		if errors.Is(err, unix.ENOENT) {
			if !present {
				return nil
			}
			if err = unix.Mkdirat(current, component, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
				return errors.New("role fixture directory creation failed")
			}
			next, err = unix.Openat(current, component, flags, 0)
		}
		if err != nil {
			return errors.New("role fixture ancestor unsafe or unavailable")
		}
		descriptors = append(descriptors, next)
		current = next
	}
	const leaf = "acs-reviewer.toml"
	var st unix.Stat_t
	if err = unix.Fstatat(current, leaf, &st, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		return errors.New("role fixture already present or unavailable")
	}
	if !present {
		return nil
	}
	fd, err := unix.Openat(current, leaf, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errors.New("exclusive role fixture creation failed")
	}
	f := os.NewFile(uintptr(fd), "synthetic-role-fixture")
	if f == nil {
		_ = unix.Close(fd)
		return errors.New("role fixture descriptor unavailable")
	}
	n, err := f.WriteString(nativeAgentRoleDefinition)
	closeErr := f.Close()
	if err != nil || closeErr != nil || n != len(nativeAgentRoleDefinition) {
		return errors.New("incomplete role fixture")
	}
	return nil
}
