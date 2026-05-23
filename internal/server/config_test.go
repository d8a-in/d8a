package server

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempConfig(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestLoadFileConfig_Valid(t *testing.T) {
	path := writeTempConfig(t, `{
		"listen": "127.0.0.1:9000",
		"audience": "https://x.example/mcp",
		"allowedOrigins": ["https://app.example"],
		"apiKeys": [{
			"tokenHashHex": "0000000000000000000000000000000000000000000000000000000000000000",
			"audience": "https://x.example/mcp",
			"subject": "alice",
			"scopes": ["postgres:read"]
		}]
	}`)

	cfg, err := LoadFileConfig(path)
	if err != nil {
		t.Fatalf("LoadFileConfig: %v", err)
	}
	if cfg.Listen != "127.0.0.1:9000" {
		t.Errorf("Listen = %q", cfg.Listen)
	}
	if cfg.Audience != "https://x.example/mcp" {
		t.Errorf("Audience = %q", cfg.Audience)
	}
	if len(cfg.AllowedOrigins) != 1 || cfg.AllowedOrigins[0] != "https://app.example" {
		t.Errorf("AllowedOrigins = %v", cfg.AllowedOrigins)
	}
	if len(cfg.APIKeys) != 1 || cfg.APIKeys[0].Subject != "alice" {
		t.Errorf("APIKeys = %+v", cfg.APIKeys)
	}
}

func TestLoadFileConfig_MissingFile(t *testing.T) {
	if _, err := LoadFileConfig("/nonexistent/path/config.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadFileConfig_MalformedJSON(t *testing.T) {
	path := writeTempConfig(t, `{ "audience": missing-quotes }`)
	if _, err := LoadFileConfig(path); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}

func TestLoadFileConfig_RejectsUnknownField(t *testing.T) {
	path := writeTempConfig(t, `{ "audience": "x", "unknownField": "bad" }`)
	if _, err := LoadFileConfig(path); err == nil {
		t.Fatal("expected error for unknown field (DisallowUnknownFields)")
	}
}
