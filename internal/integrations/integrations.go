// Package integrations definiert die Schnittstelle für werkzeugspezifische Fragmente (Spec 8).
package integrations

import (
	"sdbx/internal/audit"
	"sdbx/internal/config"
)

// RunContext beschreibt den Lauf aus Sicht einer Integration.
type RunContext struct {
	Argv      []string
	Workspace string
	Env       map[string]string // Host-Umgebung vor der Filterung
	Platform  string
	Home      string
	UID       int
	TmpRoot   string // Verzeichnis für Daemon-Sockets (Default /tmp)
	StateDir  string // für Sicherungen (z. B. MCP-Guard)
}

// Result ist das Ergebnis einer Integration.
type Result struct {
	Name            string
	Fragment        *config.File
	Required        []config.RequiredValue
	Argv            []string // umgeschriebene Kommandozeile (nil = unverändert)
	SocketDeny      []string
	SocketAllowDirs []string
	Notes           []string
	Errors          []string
	Post            func(log *audit.Logger) []string // Prüfungen nach Prozessende, liefert Warnungen
}

// Source ist der Herkunftsname einer Integration.
func Source(name string) string { return "integration:" + name }
