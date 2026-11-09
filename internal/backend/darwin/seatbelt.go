// Package darwin setzt die Policy mit Seatbelt (sandbox-exec) um (Spec 5.7).
package darwin

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"sdbx/internal/audit"
	"sdbx/internal/backend"
	"sdbx/internal/pathutil"
	"sdbx/internal/policy"
)

// Profile ist ein erzeugtes Seatbelt-Profil samt Parametern für sandbox-exec -D.
type Profile struct {
	Text   string
	Params []Param
}

// Param ist ein -D-Parameter.
type Param struct{ Key, Value string }

// Args liefert die -D-Argumente.
func (p Profile) Args() []string {
	var out []string
	for _, prm := range p.Params {
		out = append(out, "-D", prm.Key+"="+prm.Value)
	}
	return out
}

type gen struct {
	b      strings.Builder
	params []Param
	keys   map[string]string // Wert → Schlüssel
	n      map[string]int
	marker string
}

func (g *gen) line(format string, a ...any) {
	fmt.Fprintf(&g.b, format+"\n", a...)
}

// deny schreibt eine meldende deny-Regel. Die Markierung erscheint in der Log-Meldung
// und ordnet Verstöße dem Lauf zu (auch bei kurzlebigen Prozessen und parallelen Läufen).
func (g *gen) deny(rule string) {
	if g.marker != "" {
		rule += fmt.Sprintf(" (with message %q)", g.marker)
	}
	g.b.WriteString("(deny " + rule + ")\n")
}

// param registriert einen Pfad als Parameter und liefert den SBPL-Ausdruck.
func (g *gen) param(prefix, value string) string {
	if k, ok := g.keys[value]; ok {
		return fmt.Sprintf("(param %q)", k)
	}
	k := fmt.Sprintf("%s%d", prefix, g.n[prefix])
	g.n[prefix]++
	g.keys[value] = k
	g.params = append(g.params, Param{Key: k, Value: value})
	return fmt.Sprintf("(param %q)", k)
}

// regexLiteral erzeugt ein SBPL-Regex-Literal.
func regexLiteral(re string) (string, error) {
	re = pathutil.POSIXRegex(re)
	if strings.Contains(re, `"`) {
		return "", fmt.Errorf("Glob-Muster darf kein Anführungszeichen enthalten")
	}
	return `#"` + re + `"`, nil
}

// hookRegex liefert das Regex-Literal für Dateien unter .git/hooks in beliebiger Tiefe des Workspaces.
func hookRegex(ws, name string) (string, error) {
	re, err := pathutil.GlobRegex(ws + "/**/.git/hooks/" + name)
	if err != nil {
		return "", err
	}
	return regexLiteral(re)
}

func (g *gen) filter(r policy.Rule) (string, error) {
	if r.Glob != "" {
		lit, err := regexLiteral(r.Regex)
		if err != nil {
			return "", err
		}
		return "(regex " + lit + ")", nil
	}
	return "(subpath " + g.param("P", r.Path) + ")", nil
}

func (g *gen) socketFilter(path, glob string) (string, error) {
	if glob != "" {
		re, err := pathutil.GlobRegex(glob)
		if err != nil {
			return "", err
		}
		lit, err := regexLiteral(re)
		if err != nil {
			return "", err
		}
		return "(regex " + lit + ")", nil
	}
	return "(subpath " + g.param("S", path) + ")", nil
}

// renameGuards liefert die Elternverzeichnisse geschützter, schreibgeschützter und gesperrter Pfade,
// die in einem Schreibbereich liegen. Seatbelt prüft Pfade, nicht Inodes: Ließe sich ein solches
// Verzeichnis umbenennen, wäre sein Inhalt unter dem neuen Namen ungeschützt.
func renameGuards(p *policy.Policy) []string {
	var roots []string
	for _, r := range p.Rules {
		if r.Kind == policy.KindWrite && r.Glob == "" {
			roots = append(roots, r.Path)
		}
	}
	inWritable := func(a string) bool {
		for _, root := range roots {
			if a != root && pathutil.IsUnder(a, root) {
				return true
			}
		}
		return false
	}
	seen := map[string]bool{}
	var out []string
	for _, r := range p.Rules {
		if r.Glob != "" || (r.Kind != policy.KindProtected && r.Kind != policy.KindReadonly && r.Kind != policy.KindDeny) {
			continue
		}
		for a := filepath.Dir(r.Path); a != filepath.Dir(a); a = filepath.Dir(a) {
			if inWritable(a) && !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	sort.Strings(out)
	return out
}

// Generate erzeugt das Profil zur Policy.
func Generate(p *policy.Policy, rt *backend.Runtime) (Profile, error) {
	g := &gen{keys: map[string]string{}, n: map[string]int{}}
	if rt.RunID != "" {
		g.marker = audit.RunMarker(rt.RunID)
	}
	g.line("(version 1)")
	g.line(";; sdbx – erzeugtes Seatbelt-Profil. Nicht von Hand bearbeiten.")
	g.deny("default")
	g.line("")
	g.line(";; Prozesse")
	g.line("(allow process-fork)")
	g.line("(allow process-exec)")
	g.line(";; stumm, weil der Aufräumer mit kill(-1) jeden Prozess des Nutzers anfragt")
	g.line("(deny signal (with no-report))")
	g.line("(allow signal (target same-sandbox))")
	g.line("(allow process-info* (target same-sandbox))")
	if p.AllowPtrace {
		g.line("(allow mach-priv-task-port (target same-sandbox))")
	}
	g.line("(allow sysctl-read)")
	g.line("(allow user-preference-read)")
	g.line(`(allow iokit-open (iokit-registry-entry-class "RootDomainUserClient"))`)
	g.line("(allow ipc-posix-sem)")
	g.line("(allow ipc-posix-shm*)")
	g.line("(allow system-socket)")
	g.line("(allow pseudo-tty)")
	g.line("(allow file-ioctl)")
	g.line(";; Terminal-Injection verhindern (Spec 7.3)")
	g.deny("file-ioctl (ioctl-command TIOCSTI)")
	g.line("")

	g.line(";; Dateisystem: lesen")
	if p.FSDefault == "read" {
		g.line("(allow file-read*)")
	} else {
		g.line("(allow file-read-metadata)")
		for _, r := range p.Rules {
			if r.Kind == policy.KindRead || r.Kind == policy.KindSystem || r.Kind == policy.KindWrite {
				f, err := g.filter(r)
				if err != nil {
					return Profile{}, err
				}
				g.line("(allow file-read* %s)", f)
			}
		}
		if rt.SdbxExe != "" {
			g.line("(allow file-read* (literal %s))", g.param("X", rt.SdbxExe))
		}
	}
	g.line("")
	g.line(";; Dateisystem: schreiben")
	for _, r := range p.Rules {
		if r.Kind != policy.KindWrite {
			continue
		}
		f, err := g.filter(r)
		if err != nil {
			return Profile{}, err
		}
		g.line("(allow file-write* %s)", f)
	}
	g.line(`(allow file-read* file-write-data (literal "/dev/null") (literal "/dev/zero") (literal "/dev/tty") (literal "/dev/random") (literal "/dev/urandom") (literal "/dev/dtracehelper"))`)
	g.line(`(allow file-read* file-write* (literal "/dev/ptmx"))`)
	g.line(`(allow file-read* file-write-data (regex #"^/dev/ttys[0-9]+$"))`)
	g.line(`(allow file-read* file-write-data (subpath "/dev/fd"))`)
	g.line("")
	g.line(";; Schreibschutz (readonly, geschützte Pfade) – spätere Regeln gewinnen")
	if p.Workspace != "" {
		g.line(";; Hooks in jedem Repository im Workspace, auch in neuen; *.sample bleibt für git init/clone frei")
		hooks, err := hookRegex(p.Workspace, "*")
		if err != nil {
			return Profile{}, err
		}
		samples, err := hookRegex(p.Workspace, "*.sample")
		if err != nil {
			return Profile{}, err
		}
		g.deny("file-write* (regex " + hooks + ")")
		g.line("(allow file-write* (regex %s))", samples)
	}
	for _, r := range p.Rules {
		if r.Kind != policy.KindReadonly && r.Kind != policy.KindProtected {
			continue
		}
		f, err := g.filter(r)
		if err != nil {
			return Profile{}, err
		}
		g.deny("file-write* " + f)
	}
	g.line(";; Elternverzeichnisse geschützter Pfade nicht umbenennen oder entfernen (sonst Umweg: mv .git .gitx)")
	for _, a := range renameGuards(p) {
		g.deny("file-write-unlink (literal " + g.param("R", a) + ")")
	}
	g.line("")
	g.line(";; Sperren (deny gewinnt immer, Spec 5.2)")
	var excepts []string
	for _, r := range p.Rules {
		if r.Kind != policy.KindDeny {
			continue
		}
		f, err := g.filter(r)
		if err != nil {
			return Profile{}, err
		}
		g.deny("file-read* file-write* " + f)
		excepts = append(excepts, r.Except...)
	}
	for _, e := range excepts {
		g.line("(allow file-read* (literal %s))", g.param("E", e))
	}
	g.line("")

	g.line(";; Netzwerk")
	switch p.Net.Mode {
	case "host":
		g.line("(allow network*)")
	case "proxy":
		g.line(`(allow network-outbound (remote ip "localhost:%d"))`, rt.ProxyPort)
	}
	if p.Net.Mode != "host" {
		ports := append([]int(nil), p.Net.Local...)
		sort.Ints(ports)
		for _, port := range ports {
			g.line(`(allow network-outbound (remote ip "localhost:%d"))`, port)
		}
		g.line(`(allow network-bind (local ip "localhost:*"))`)
		g.line(`(allow network-inbound (local ip "localhost:*"))`)
	}
	g.line("")
	g.line(";; Unix-Sockets: nur Workspace, privates Temp und Freigaben (Spec 7.1)")
	sockDirs := []string{p.Workspace}
	if p.SdbxTmp != "" {
		sockDirs = append(sockDirs, p.SdbxTmp)
	}
	sockDirs = append(sockDirs, rt.SocketAllowDirs...)
	for _, d := range sockDirs {
		e := g.param("S", d)
		g.line("(allow network-outbound (remote unix-socket (subpath %s)))", e)
		g.line("(allow network-bind (local unix-socket (subpath %s)))", e)
	}
	for _, s := range p.Sockets {
		f, err := g.socketFilter(s.Path, s.Glob)
		if err != nil {
			return Profile{}, err
		}
		g.line("(allow network-outbound (remote unix-socket %s))", f)
	}
	for _, d := range p.SocketDeny {
		g.deny("network-outbound (remote unix-socket (path-literal " + g.param("S", d) + "))")
	}
	g.line("")
	g.line(";; Mach-Services (Spec 7.4)")
	if len(p.MachServices) > 0 {
		names := make([]string, len(p.MachServices))
		for i, s := range p.MachServices {
			names[i] = fmt.Sprintf("(global-name %q)", s)
		}
		g.line("(allow mach-lookup %s)", strings.Join(names, " "))
	}
	for _, s := range p.MachNoReport {
		g.line("(deny mach-lookup (global-name %q) (with no-report))", s)
	}
	return Profile{Text: g.b.String(), Params: g.params}, nil
}
