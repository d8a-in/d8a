package server

import (
	"path"
	"strings"
)

// CapabilityBundle is one entry in the catalog: a named set of MCP
// tool/resource/prompt identifiers the bundle's owners are allowed
// to use. Use the literal "*" to mean "every name in this category."
type CapabilityBundle struct {
	Tools     []string `json:"tools,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Prompts   []string `json:"prompts,omitempty"`
}

// Catalog maps scope names (e.g. "postgres:read") to capability
// bundles. It is the policy decision point (PDP) that the protocol-
// layer PEP — initialize, tools/list, tools/call, etc. — consults to
// filter what each authenticated identity can see and do, per
// brainstorming #123.
//
// A nil *Catalog (returned by NewCatalog when no bundles are
// configured) means "no catalog" → permissive mode: every identity
// has the same access as the backing MCP exposes. A non-nil
// *Catalog whose bundles don't match an identity's scopes results in
// an empty EffectiveAccess — secure-by-default.
type Catalog struct {
	bundles map[string]CapabilityBundle
}

// NewCatalog constructs a Catalog. Returns nil when bundles is nil
// or empty — callers may compare the result to nil, or call Resolve
// regardless and rely on EffectiveAccess.Permissive.
func NewCatalog(bundles map[string]CapabilityBundle) *Catalog {
	if len(bundles) == 0 {
		return nil
	}
	cp := make(map[string]CapabilityBundle, len(bundles))
	for k, v := range bundles {
		cp[k] = v
	}
	return &Catalog{bundles: cp}
}

// EffectiveAccess is the resolved per-identity allowlist returned by
// Resolve. When Permissive is true (no catalog configured) the maps
// are ignored and every check returns true. When Permissive is false
// the maps are the literal sets of allowed names, with "*" as the
// per-category wildcard.
type EffectiveAccess struct {
	Permissive bool
	Tools      map[string]bool
	Resources  map[string]bool
	Prompts    map[string]bool
}

// Resolve translates a set of identity scopes into the union of
// capability grants matching bundles confer. Unknown scopes are
// silently ignored so a stale key referencing a removed bundle ends
// up with fewer privileges, not a hard failure.
func (c *Catalog) Resolve(scopes []string) EffectiveAccess {
	if c == nil {
		return EffectiveAccess{Permissive: true}
	}
	ea := EffectiveAccess{
		Tools:     map[string]bool{},
		Resources: map[string]bool{},
		Prompts:   map[string]bool{},
	}
	for _, s := range scopes {
		b, ok := c.bundles[s]
		if !ok {
			continue
		}
		for _, t := range b.Tools {
			ea.Tools[t] = true
		}
		for _, r := range b.Resources {
			ea.Resources[r] = true
		}
		for _, p := range b.Prompts {
			ea.Prompts[p] = true
		}
	}
	return ea
}

// AllowsTool reports whether the given tool name is granted. Patterns
// in the bundle are matched against name using globPatternMatches:
// the literal "*" matches anything; patterns containing wildcard
// characters use Go's path.Match (so "prefix*" matches anything
// starting with prefix, "*" within a path segment doesn't cross /);
// everything else is exact-match.
func (e EffectiveAccess) AllowsTool(name string) bool {
	if e.Permissive {
		return true
	}
	return anyPatternMatches(e.Tools, name)
}

// AllowsResource reports whether the given resource URI is granted.
// Patterns work as documented on AllowsTool.
func (e EffectiveAccess) AllowsResource(uri string) bool {
	if e.Permissive {
		return true
	}
	return anyPatternMatches(e.Resources, uri)
}

// AllowsPrompt reports whether the given prompt name is granted.
// Patterns work as documented on AllowsTool.
func (e EffectiveAccess) AllowsPrompt(name string) bool {
	if e.Permissive {
		return true
	}
	return anyPatternMatches(e.Prompts, name)
}

// anyPatternMatches returns true iff at least one pattern in the
// set matches name. Patterns are checked using globPatternMatches.
func anyPatternMatches(patterns map[string]bool, name string) bool {
	// Fast-path: exact-match literal. This handles the overwhelmingly
	// common "tool name match" case in O(1).
	if patterns[name] {
		return true
	}
	// Slow-path: scan for any pattern that's a glob and matches.
	for pattern := range patterns {
		if pattern == name {
			continue // already checked
		}
		if globPatternMatches(pattern, name) {
			return true
		}
	}
	return false
}

// globPatternMatches reports whether name matches pattern.
//
//   - The literal "*" matches anything (broad wildcard).
//   - A pattern containing any of *?[ uses Go's path.Match — so
//     "customers*" matches "customers" and "customers_archive",
//     "postgres://*" matches "postgres://anything" but NOT
//     "postgres://a/b" (path.Match doesn't cross /).
//   - Otherwise the pattern is treated as a literal exact-match.
func globPatternMatches(pattern, name string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return pattern == name
	}
	matched, _ := path.Match(pattern, name)
	return matched
}

// HasAnyTool reports whether the access grants at least one tool —
// used by initialize to decide whether to announce the "tools"
// capability key at all.
func (e EffectiveAccess) HasAnyTool() bool {
	return e.Permissive || len(e.Tools) > 0
}

// HasAnyResource is the resources analogue of HasAnyTool.
func (e EffectiveAccess) HasAnyResource() bool {
	return e.Permissive || len(e.Resources) > 0
}

// HasAnyPrompt is the prompts analogue of HasAnyTool.
func (e EffectiveAccess) HasAnyPrompt() bool {
	return e.Permissive || len(e.Prompts) > 0
}
