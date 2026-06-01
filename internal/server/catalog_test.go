package server

import "testing"

func TestNewCatalog_NilBundlesIsPermissive(t *testing.T) {
	c := NewCatalog(nil)
	if c != nil {
		t.Fatalf("NewCatalog(nil) = %v, want nil (= permissive)", c)
	}
	ea := c.Resolve([]string{"anything"})
	if !ea.Permissive {
		t.Fatalf("nil catalog must Resolve to Permissive")
	}
	for _, name := range []string{"a", "b", "anything"} {
		if !ea.AllowsTool(name) || !ea.AllowsResource(name) || !ea.AllowsPrompt(name) {
			t.Errorf("permissive access denied %q", name)
		}
	}
}

func TestNewCatalog_EmptyMapIsPermissive(t *testing.T) {
	if NewCatalog(map[string]CapabilityBundle{}) != nil {
		t.Fatal("empty bundle map should produce nil catalog")
	}
}

func TestCatalog_ResolveMergesScopes(t *testing.T) {
	c := NewCatalog(map[string]CapabilityBundle{
		"read":  {Tools: []string{"query"}, Resources: []string{"customers"}},
		"write": {Tools: []string{"execute"}, Resources: []string{"orders"}},
	})
	ea := c.Resolve([]string{"read", "write"})
	if ea.Permissive {
		t.Fatal("scoped catalog must not be permissive")
	}
	for _, want := range []string{"query", "execute"} {
		if !ea.AllowsTool(want) {
			t.Errorf("AllowsTool(%q) = false; want true", want)
		}
	}
	for _, want := range []string{"customers", "orders"} {
		if !ea.AllowsResource(want) {
			t.Errorf("AllowsResource(%q) = false; want true", want)
		}
	}
	if ea.AllowsTool("delete") {
		t.Errorf("ungranted tool 'delete' incorrectly allowed")
	}
}

func TestCatalog_UnknownScopeIsIgnored(t *testing.T) {
	c := NewCatalog(map[string]CapabilityBundle{
		"read": {Tools: []string{"query"}},
	})
	// "stale" doesn't exist; "read" should still resolve normally.
	ea := c.Resolve([]string{"stale", "read"})
	if !ea.AllowsTool("query") {
		t.Errorf("'read' bundle was dropped by an unknown sibling scope")
	}
	if ea.AllowsTool("execute") {
		t.Errorf("unknown scope should grant nothing")
	}
}

func TestCatalog_WildcardAllowsAnyName(t *testing.T) {
	c := NewCatalog(map[string]CapabilityBundle{
		"admin": {Tools: []string{"*"}},
	})
	ea := c.Resolve([]string{"admin"})
	for _, name := range []string{"query", "execute", "anything_else"} {
		if !ea.AllowsTool(name) {
			t.Errorf("wildcard scope denied tool %q", name)
		}
	}
	// Wildcard on tools shouldn't leak into resources/prompts.
	if ea.AllowsResource("anything") {
		t.Errorf("tool wildcard incorrectly granted resource access")
	}
	if ea.AllowsPrompt("anything") {
		t.Errorf("tool wildcard incorrectly granted prompt access")
	}
}

func TestCatalog_EmptyScopesDeniesEverything(t *testing.T) {
	c := NewCatalog(map[string]CapabilityBundle{
		"read": {Tools: []string{"query"}},
	})
	ea := c.Resolve(nil)
	if ea.Permissive {
		t.Fatal("Resolve(nil) on a non-nil catalog must NOT be permissive")
	}
	if ea.AllowsTool("query") || ea.AllowsResource("x") || ea.AllowsPrompt("y") {
		t.Errorf("identity with no scopes should be denied everything")
	}
	if ea.HasAnyTool() || ea.HasAnyResource() || ea.HasAnyPrompt() {
		t.Errorf("HasAny* must all be false for empty scopes under a non-nil catalog")
	}
}

func TestCatalog_HasAnyReportsCategory(t *testing.T) {
	c := NewCatalog(map[string]CapabilityBundle{
		"read": {Tools: []string{"query"}}, // tools only
	})
	ea := c.Resolve([]string{"read"})
	if !ea.HasAnyTool() {
		t.Errorf("HasAnyTool should be true when a tool is granted")
	}
	if ea.HasAnyResource() {
		t.Errorf("HasAnyResource should be false when no resources are granted")
	}
	if ea.HasAnyPrompt() {
		t.Errorf("HasAnyPrompt should be false when no prompts are granted")
	}
}

func TestCatalog_PrefixGlobMatches(t *testing.T) {
	c := NewCatalog(map[string]CapabilityBundle{
		"customer-data": {Resources: []string{"postgres://d8a_demo/customers*"}},
	})
	ea := c.Resolve([]string{"customer-data"})
	for _, allowed := range []string{
		"postgres://d8a_demo/customers",
		"postgres://d8a_demo/customers_archive",
	} {
		if !ea.AllowsResource(allowed) {
			t.Errorf("prefix glob should allow %q", allowed)
		}
	}
	for _, denied := range []string{
		"postgres://d8a_demo/orders",
		"postgres://other_db/customers", // path.Match's * doesn't cross / — but here / appears earlier
	} {
		if ea.AllowsResource(denied) {
			t.Errorf("prefix glob should deny %q", denied)
		}
	}
}

func TestCatalog_GlobDoesNotCrossSlash(t *testing.T) {
	// path.Match's `*` does not cross /, which is the right semantic
	// for URI-shaped resources: an admin granting "postgres://db/*"
	// shouldn't accidentally grant "postgres://db/secret/table".
	c := NewCatalog(map[string]CapabilityBundle{
		"db-flat": {Resources: []string{"postgres://db/*"}},
	})
	ea := c.Resolve([]string{"db-flat"})
	if !ea.AllowsResource("postgres://db/customers") {
		t.Errorf("postgres://db/customers should be allowed")
	}
	if ea.AllowsResource("postgres://db/secret/table") {
		t.Errorf("postgres://db/secret/table should be denied — glob must not cross /")
	}
}

func TestCatalog_QuestionMarkMatchesSingleChar(t *testing.T) {
	c := NewCatalog(map[string]CapabilityBundle{
		"versioned": {Tools: []string{"query_v?"}},
	})
	ea := c.Resolve([]string{"versioned"})
	if !ea.AllowsTool("query_v1") || !ea.AllowsTool("query_v9") {
		t.Errorf("? should match a single character")
	}
	if ea.AllowsTool("query_v") || ea.AllowsTool("query_v10") {
		t.Errorf("? should match exactly one character (not zero, not two)")
	}
}

func TestCatalog_LiteralMatchUnchanged(t *testing.T) {
	// Regression: bundles without glob characters must behave
	// exactly like exact-match (no surprise matches).
	c := NewCatalog(map[string]CapabilityBundle{
		"echo-only": {Tools: []string{"echo"}},
	})
	ea := c.Resolve([]string{"echo-only"})
	if !ea.AllowsTool("echo") {
		t.Errorf("literal 'echo' must still match exactly")
	}
	if ea.AllowsTool("echoes") || ea.AllowsTool("ech") {
		t.Errorf("literal 'echo' must NOT match similar names")
	}
}

func TestCatalog_BundleSnapshotIsIndependent(t *testing.T) {
	// Mutating the bundle map we passed in must not change the
	// catalog's internal copy.
	in := map[string]CapabilityBundle{
		"read": {Tools: []string{"query"}},
	}
	c := NewCatalog(in)
	delete(in, "read")
	ea := c.Resolve([]string{"read"})
	if !ea.AllowsTool("query") {
		t.Fatalf("catalog reused caller's map; bundle was lost when caller mutated input")
	}
}
