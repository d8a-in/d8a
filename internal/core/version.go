// Package core holds shared building blocks for d8a-server and d8a-client.
package core

// Version is the d8a release version. Releases override this via -ldflags
// (e.g. `go build -ldflags "-X d8a.in/d8a/internal/core.Version=v0.1.0"`).
var Version = "0.0.0-dev"
