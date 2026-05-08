package auth

import (
	"fmt"
	"strings"
)

// ParseGroupMap parses an LDAP group→projects mapping from the env-encoded
// grammar `<group>:<proj>(,<proj>)*(;<group>:<proj>(,<proj>)*)*`. Whitespace
// around groups and projects is trimmed. Empty entries (e.g. consecutive
// semicolons) are skipped. Duplicate groups, empty group names, missing
// colon separators, and empty projects lists are rejected with a startup-grade
// error so misconfiguration fails loudly at boot.
func ParseGroupMap(raw string) (map[string][]string, error) {
	out := make(map[string][]string)
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		colon := strings.Index(entry, ":")
		if colon < 0 {
			return nil, fmt.Errorf("group map entry %q: missing ':' separator", entry)
		}
		group := strings.TrimSpace(entry[:colon])
		if group == "" {
			return nil, fmt.Errorf("group map entry %q: empty group name", entry)
		}
		if _, exists := out[group]; exists {
			return nil, fmt.Errorf("group map: duplicate group %q", group)
		}
		projects, err := parseProjectList(entry[colon+1:])
		if err != nil {
			return nil, fmt.Errorf("group map entry %q: %w", entry, err)
		}
		out[group] = projects
	}
	return out, nil
}

func parseProjectList(raw string) ([]string, error) {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, project := range strings.Split(raw, ",") {
		project = strings.TrimSpace(project)
		if project == "" {
			continue
		}
		if _, dup := seen[project]; dup {
			continue
		}
		seen[project] = struct{}{}
		out = append(out, project)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty projects list")
	}
	return out, nil
}

// ProjectsFor returns the union of projects authorized by the given groups,
// deduplicated and order-preserving by first appearance. Unknown groups are
// silently skipped — callers that need "deny when nothing maps" should treat
// an empty return as the deny signal.
func ProjectsFor(groups []string, m map[string][]string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, group := range groups {
		projects, ok := m[group]
		if !ok {
			continue
		}
		for _, project := range projects {
			if _, dup := seen[project]; dup {
				continue
			}
			seen[project] = struct{}{}
			out = append(out, project)
		}
	}
	return out
}
