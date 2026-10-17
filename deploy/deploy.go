// Package deploy embeds the system files (systemd units, journald limits) in
// the binary. They come from inside the binary verified by the release
// signature, not from loose files on the server.
package deploy

import "embed"

// Systemd holds the units and the journald configuration.
//
//go:embed systemd/*
var Systemd embed.FS
