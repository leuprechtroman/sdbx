// Package pathutil enthält Variablenexpansion, Pfadauflösung und Glob-Funktionen.
package pathutil

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Vars sind die Werte für die Variablenexpansion (Spec 4.3).
type Vars struct {
	Home      string
	Workspace string
	UID       int
	GID       int
	TmpDir    string
	SdbxTmp   string
	LookupEnv func(string) (string, bool)
}

var varRe = regexp.MustCompile(`\$\$|\$\{([A-Za-z_][A-Za-z0-9_]*)(?::([A-Za-z_][A-Za-z0-9_]*))?\}`)

// ErrDropped signalisiert, dass ein Eintrag wegen leerer ${ENV:…}-Variable entfällt.
type ErrDropped struct{ Var string }

func (e *ErrDropped) Error() string {
	return fmt.Sprintf("Umgebungsvariable %s ist leer", e.Var)
}

// Expand ersetzt ~ und ${…}-Variablen. configDir ist der Wert von ${CONFIG_DIR}.
func (v Vars) Expand(s, configDir string) (string, error) {
	if s == "~" || strings.HasPrefix(s, "~/") {
		s = v.Home + s[1:]
	}
	var outErr error
	res := varRe.ReplaceAllStringFunc(s, func(m string) string {
		if m == "$$" {
			return "$"
		}
		sub := varRe.FindStringSubmatch(m)
		name, arg := sub[1], sub[2]
		if name == "ENV" {
			if arg == "" {
				outErr = fmt.Errorf("${ENV:NAME} braucht einen Variablennamen")
				return ""
			}
			val, ok := "", false
			if v.LookupEnv != nil {
				val, ok = v.LookupEnv(arg)
			}
			if !ok || val == "" {
				if outErr == nil {
					outErr = &ErrDropped{Var: arg}
				}
				return ""
			}
			return val
		}
		if arg != "" {
			outErr = fmt.Errorf("unbekannte Variable ${%s:%s}", name, arg)
			return ""
		}
		switch name {
		case "HOME":
			return v.Home
		case "WORKSPACE":
			return v.Workspace
		case "CONFIG_DIR":
			if configDir == "" {
				return v.Workspace
			}
			return configDir
		case "UID":
			return fmt.Sprint(v.UID)
		case "GID":
			return fmt.Sprint(v.GID)
		case "TMPDIR":
			return v.TmpDir
		case "SDBX_TMP":
			return v.SdbxTmp
		}
		outErr = fmt.Errorf("unbekannte Variable ${%s}", name)
		return ""
	})
	if outErr != nil {
		return "", outErr
	}
	if strings.Contains(strings.ReplaceAll(res, "$$", ""), "${") {
		return "", fmt.Errorf("unvollständige Variable in %q", s)
	}
	return res, nil
}

// Absolute macht p absolut relativ zu base und bereinigt ihn.
func Absolute(p, base string) string {
	if !filepath.IsAbs(p) {
		p = filepath.Join(base, p)
	}
	return filepath.Clean(p)
}

// Resolve löst Symlinks auf. Existiert der Pfad nicht, wird der tiefste
// existierende Vorfahre aufgelöst und der Rest angehängt.
func Resolve(p string) (resolved string, exists bool) {
	p = filepath.Clean(p)
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r, true
	}
	rest := []string{}
	cur := p
	for {
		parent := filepath.Dir(cur)
		rest = append([]string{filepath.Base(cur)}, rest...)
		if parent == cur {
			return p, false
		}
		if r, err := filepath.EvalSymlinks(parent); err == nil {
			return filepath.Join(append([]string{r}, rest...)...), false
		}
		cur = parent
	}
}

// IsUnder meldet, ob p gleich base ist oder darunter liegt.
func IsUnder(p, base string) bool {
	if base == "/" {
		return strings.HasPrefix(p, "/")
	}
	return p == base || strings.HasPrefix(p, base+"/")
}

// HasGlob meldet, ob s Glob-Metazeichen enthält.
func HasGlob(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// StaticPrefix liefert den Teil eines Globs bis vor das erste Segment mit Metazeichen.
func StaticPrefix(pattern string) string {
	parts := strings.Split(pattern, "/")
	var out []string
	for _, p := range parts {
		if HasGlob(p) {
			break
		}
		out = append(out, p)
	}
	s := strings.Join(out, "/")
	if s == "" {
		return "/"
	}
	return s
}

// Match prüft einen absoluten Pfad gegen ein Glob-Muster mit **-Unterstützung.
// Ein Treffer gilt auch für alles unterhalb eines passenden Pfads.
func Match(pattern, p string) bool {
	re, err := GlobRegex(pattern)
	if err != nil {
		return false
	}
	return regexp.MustCompile(re).MatchString(p)
}

// GlobRegex übersetzt ein Glob-Muster in einen verankerten regulären Ausdruck,
// der den Pfad selbst und alles darunter trifft.
func GlobRegex(pattern string) (string, error) {
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch c {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				// "**/" trifft null oder mehr Verzeichnisse, "**" am Ende alles.
				if i+2 < len(pattern) && pattern[i+2] == '/' {
					b.WriteString("(?:.*/)?")
					i += 2
				} else {
					b.WriteString(".*")
					i++
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		case '[':
			j := strings.IndexByte(pattern[i:], ']')
			if j < 0 {
				return "", fmt.Errorf("Glob %q: ']' fehlt", pattern)
			}
			class := pattern[i+1 : i+j]
			if strings.HasPrefix(class, "!") {
				class = "^" + class[1:]
			}
			b.WriteString("[" + strings.ReplaceAll(class, `\`, `\\`) + "]")
			i += j
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("(?:/.*)?$")
	return b.String(), nil
}

// POSIXRegex wandelt einen mit GlobRegex erzeugten Ausdruck in POSIX-ERE um
// (ohne nicht-fangende Gruppen), wie Seatbelt sie erwartet.
func POSIXRegex(re string) string {
	return strings.ReplaceAll(re, "(?:", "(")
}

// ExpandGlob findet existierende Pfade zu einem Muster. limit begrenzt die Zahl
// besuchter Einträge; truncated meldet, ob das Limit erreicht wurde.
func ExpandGlob(pattern string, limit int) (matches []string, truncated bool) {
	re, err := GlobRegex(pattern)
	if err != nil {
		return nil, false
	}
	exact := regexp.MustCompile(strings.TrimSuffix(re, "(?:/.*)?$") + "$")
	root := StaticPrefix(pattern)
	visited := 0
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		visited++
		if visited > limit {
			truncated = true
			return filepath.SkipAll
		}
		if exact.MatchString(p) {
			matches = append(matches, p)
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() && d.Name() == ".git" && !strings.Contains(pattern, ".git") {
			return filepath.SkipDir
		}
		return nil
	})
	return matches, truncated
}

// UserTempDir liefert das temporäre Verzeichnis des Nutzers außerhalb der Sandbox.
func UserTempDir() string {
	if t := os.Getenv("TMPDIR"); t != "" {
		return filepath.Clean(t)
	}
	return "/tmp"
}
