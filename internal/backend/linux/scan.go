package linux

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sdbx/internal/pathutil"
)

// ScanResult enthält gefundene Unix-Sockets.
type ScanResult struct {
	Sockets   []string
	Truncated bool // Zeitbudget oder Eintragslimit erreicht
}

// ScanOptions steuert den Socket-Scan (Spec 7.1).
type ScanOptions struct {
	Roots    []string      // flache Wurzeln (Tiefe 3): /run, /var/run, $XDG_RUNTIME_DIR, ggf. /tmp
	Home     string        // vollständig, mit Ausnahmen
	Skip     []string      // Pfade, die nicht gescannt werden (Workspace, privates Temp)
	Budget   time.Duration // Default 500 ms
	MaxDepth int           // für Roots, Default 3
}

var homeSkipNames = map[string]bool{"node_modules": true, ".git": true, ".cache": true, ".npm": true, ".cargo": true, ".rustup": true, "go": true}

// ScanSockets sucht Socket-Dateien.
func ScanSockets(o ScanOptions) ScanResult {
	if o.Budget == 0 {
		o.Budget = 500 * time.Millisecond
	}
	if o.MaxDepth == 0 {
		o.MaxDepth = 3
	}
	deadline := time.Now().Add(o.Budget)
	seen := map[string]bool{}
	var res ScanResult
	skip := func(p string) bool {
		for _, s := range o.Skip {
			if pathutil.IsUnder(p, s) {
				return true
			}
		}
		return false
	}
	walk := func(root string, maxDepth int, home bool) {
		base := strings.Count(root, "/")
		filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if time.Now().After(deadline) {
				res.Truncated = true
				return filepath.SkipAll
			}
			if err != nil {
				if d != nil && d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if skip(p) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				if p != root && maxDepth > 0 && strings.Count(p, "/")-base > maxDepth {
					return filepath.SkipDir
				}
				if home && homeSkipNames[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if d.Type()&os.ModeSocket != 0 && !seen[p] {
				seen[p] = true
				res.Sockets = append(res.Sockets, p)
			}
			return nil
		})
	}
	for _, r := range o.Roots {
		if rr, ok := pathutil.Resolve(r); ok {
			walk(rr, o.MaxDepth, false)
		}
	}
	if o.Home != "" {
		walk(o.Home, 0, true)
	}
	sort.Strings(res.Sockets)
	return res
}

// EmulateDeny berechnet für den Landlock-Modus (ohne Mount-Namespace) die Pfade,
// die statt grant freigegeben werden, damit die Pfade in deny ausgespart bleiben.
// Nur beim Start existierende Einträge werden berücksichtigt (Spec 5.6).
func EmulateDeny(grant string, deny []string) []string {
	var relevant []string
	for _, d := range deny {
		if d != grant && pathutil.IsUnder(d, grant) {
			relevant = append(relevant, d)
		}
		if pathutil.IsUnder(grant, d) {
			return nil // grant liegt komplett in einer Sperre
		}
	}
	if len(relevant) == 0 {
		return []string{grant}
	}
	entries, err := os.ReadDir(grant)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		child := filepath.Join(grant, e.Name())
		if grant == "/" {
			child = "/" + e.Name()
		}
		out = append(out, EmulateDeny(child, relevant)...)
	}
	return out
}
