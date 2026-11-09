// Package presets enthält die eingebauten Presets.
package presets

import (
	"embed"
	"sort"
	"strings"
)

//go:embed data/*.yaml
var fs embed.FS

// Get liefert den Inhalt eines Presets.
func Get(name string) ([]byte, bool) {
	b, err := fs.ReadFile("data/" + name + ".yaml")
	return b, err == nil
}

// Names listet alle Presets.
func Names() []string {
	ents, _ := fs.ReadDir("data")
	var out []string
	for _, e := range ents {
		out = append(out, strings.TrimSuffix(e.Name(), ".yaml"))
	}
	sort.Strings(out)
	return out
}

// Description liefert die erste Kommentarzeile eines Presets.
func Description(name string) string {
	b, ok := Get(name)
	if !ok {
		return ""
	}
	line, _, _ := strings.Cut(string(b), "\n")
	return strings.TrimSpace(strings.TrimPrefix(line, "#"))
}
