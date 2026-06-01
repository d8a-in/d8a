package server

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

// AllowsTool reports whether the given tool name is granted.
// The literal "*" in the bundle means every tool is allowed.
func (e EffectiveAccess) AllowsTool(name string) bool {
	if e.Permissive {
		return true
	}
	return e.Tools[name] || e.Tools["*"]
}

// AllowsResource reports whether the given resource URI is granted.
func (e EffectiveAccess) AllowsResource(uri string) bool {
	if e.Permissive {
		return true
	}
	return e.Resources[uri] || e.Resources["*"]
}

// AllowsPrompt reports whether the given prompt name is granted.
func (e EffectiveAccess) AllowsPrompt(name string) bool {
	if e.Permissive {
		return true
	}
	return e.Prompts[name] || e.Prompts["*"]
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
