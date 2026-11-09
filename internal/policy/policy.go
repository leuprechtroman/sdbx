// Package policy erzeugt aus der zusammengeführten Konfiguration die plattformunabhängige Policy.
package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"sdbx/internal/config"
	"sdbx/internal/netmatch"
	"sdbx/internal/pathutil"
)

// Access ist eine Zugriffsstufe (Spec 5.1).
type Access int

const (
	None Access = iota
	Read
	Write
)

func (a Access) String() string {
	return [...]string{"none", "read", "write"}[a]
}

// Kind ist die Art einer Dateisystemregel.
type Kind int

const (
	KindRead Kind = iota
	KindWrite
	KindDeny
	KindReadonly
	KindProtected
	KindSystem
)

func (k Kind) String() string {
	return [...]string{"read", "write", "deny", "readonly", "protected", "system"}[k]
}

// Rule ist eine aufgelöste Dateisystemregel.
type Rule struct {
	Kind   Kind
	Path   string   // aufgelöster absoluter Pfad (bei Globs: leer)
	Glob   string   // absolutes Glob-Muster
	Regex  string   // übersetzter Glob
	Exists bool     // Pfad existiert beim Kompilieren
	IsDir  bool     // Pfad ist ein Verzeichnis
	Create bool     // vor dem Start anlegen (create_missing)
	Except []string // aufgelöste Ausnahmen (bei deny)
	Origin config.Origin
	Note   string
}

// Label beschreibt die Regel für Ausgaben.
func (r Rule) Label() string {
	t := r.Path
	if r.Glob != "" {
		t = r.Glob
	}
	s := fmt.Sprintf("%s %s", r.Kind, t)
	if r.Note != "" {
		s += " (" + r.Note + ")"
	}
	return s
}

// Matches meldet, ob p unter die Regel fällt.
func (r Rule) Matches(p string) bool {
	if r.Glob != "" {
		return pathutil.Match(r.Glob, p)
	}
	return pathutil.IsUnder(p, r.Path)
}

// Issue ist eine Warnung oder ein Fehler.
type Issue struct {
	Error bool
	Msg   string
}

// NetPolicy enthält die Netzwerkregeln.
type NetPolicy struct {
	Mode    string // proxy | none | host
	Matcher *netmatch.Matcher
	Local   []int
	SSH     bool
}

// EnvPolicy enthält die Umgebungsregeln.
type EnvPolicy struct {
	Mode        string
	Passthrough []string
	Deny        []string
	Set         map[string]string
}

// Limits sind die Ressourcenlimits.
type Limits struct {
	Timeout      time.Duration
	KillGrace    time.Duration
	CPUTime      time.Duration
	MaxProcesses int
	MaxOpenFiles int
	MaxMemory    int64
	MaxFileSize  int64
}

// LinuxPolicy enthält Linux-spezifische Einstellungen.
type LinuxPolicy struct {
	Backend  string
	Landlock string
	Seccomp  string
	Devices  []string
}

// SocketRule gibt einen Unix-Socket-Pfad bzw. ein Verzeichnis frei.
type SocketRule struct {
	Path   string
	Glob   string
	Origin config.Origin
}

// Policy ist die vollständig aufgelöste Regelmenge eines Laufs.
type Policy struct {
	Platform    string
	Workspace   string
	Home        string
	UID         int
	SdbxTmp     string
	UserTmp     string
	ConfigFiles []string
	Repos       []string // Workspace und Git-Repositories darin beim Start

	FSDefault string
	Rules     []Rule

	Net        NetPolicy
	Sockets    []SocketRule
	SocketDeny []string // literale Sperren (z. B. Daemons außerhalb)
	Env        EnvPolicy

	IsolatePids bool
	AllowPtrace bool
	PrivateTmp  bool

	Limits       Limits
	MachServices []string
	MachNoReport []string
	Linux        LinuxPolicy

	AuditFile    string
	AuditFormat  string
	AuditSummary bool
	Degraded     bool

	Issues []Issue
}

// Context liefert Laufzeitwerte für die Kompilierung.
type Context struct {
	Platform         string
	Home             string
	UID, GID         int
	UserTmp          string
	SdbxTmp          string
	DefaultWorkspace string // Verzeichnis der Projektdatei bzw. cwd
	ConfigFiles      []string
	LookupEnv        func(string) (string, bool)
	PathEnv          string
	ExtraWrite       []string // plattformspezifische Schreibpfade (z. B. DARWIN_USER_CACHE_DIR)
	SharedTmp        string   // Pfad von /tmp (Default /tmp bzw. /private/tmp)
	SocketDeny       []string
	GlobLimit        int
}

func (p *Policy) warn(format string, a ...any) {
	p.Issues = append(p.Issues, Issue{Msg: fmt.Sprintf(format, a...)})
}

// explicitWrite meldet, ob der Nutzer genau diesen Pfad als Schreibbereich freigegeben hat.
func (p *Policy) explicitWrite(path string) bool {
	for _, r := range p.Rules {
		if r.Kind == KindWrite && r.Glob == "" && r.Path == path && r.Origin.Source != "builtin" {
			return true
		}
	}
	return false
}

func (p *Policy) underWrite(path string) bool {
	for _, r := range p.Rules {
		if r.Kind == KindWrite && r.Glob == "" && pathutil.IsUnder(path, r.Path) {
			return true
		}
	}
	return false
}

func (p *Policy) fail(format string, a ...any) {
	p.Issues = append(p.Issues, Issue{Error: true, Msg: fmt.Sprintf(format, a...)})
}

// Errors liefert alle Fehler.
func (p *Policy) Errors() []Issue {
	var out []Issue
	for _, i := range p.Issues {
		if i.Error {
			out = append(out, i)
		}
	}
	return out
}

func optionalSource(src string) bool {
	return strings.HasPrefix(src, "preset:") || strings.HasPrefix(src, "integration:") || src == "builtin"
}

// Compile erzeugt die Policy. Fehler in einzelnen Regeln landen in Issues;
// ein zurückgegebener error bedeutet einen nicht verwertbaren Zustand.
func Compile(c *config.Config, ctx Context) (*Policy, error) {
	if ctx.GlobLimit == 0 {
		ctx.GlobLimit = 200000
	}
	p := &Policy{
		Platform:     ctx.Platform,
		Home:         ctx.Home,
		UID:          ctx.UID,
		SdbxTmp:      ctx.SdbxTmp,
		UserTmp:      ctx.UserTmp,
		FSDefault:    c.FSDefault,
		IsolatePids:  c.IsolatePids,
		AllowPtrace:  c.AllowPtrace,
		PrivateTmp:   c.PrivateTmp,
		AuditFile:    c.AuditFile,
		AuditFormat:  c.AuditFormat,
		AuditSummary: c.AuditSummary,
		Degraded:     c.Degraded,
		Limits: Limits{
			Timeout: c.Timeout, KillGrace: c.KillGrace, CPUTime: c.CPUTime,
			MaxProcesses: c.MaxProcesses, MaxOpenFiles: c.MaxOpenFiles,
			MaxMemory: c.MaxMemory, MaxFileSize: c.MaxFileSize,
		},
		Linux: LinuxPolicy{Backend: c.LinuxBackend, Landlock: c.LinuxLandlock, Seccomp: c.LinuxSeccomp},
	}
	vars := pathutil.Vars{Home: ctx.Home, UID: ctx.UID, GID: ctx.GID, TmpDir: ctx.UserTmp, SdbxTmp: ctx.SdbxTmp, LookupEnv: ctx.LookupEnv}

	// Workspace
	ws := ctx.DefaultWorkspace
	if c.Workspace != "" {
		vars.Workspace = ctx.DefaultWorkspace
		e, err := vars.Expand(c.Workspace, c.WorkspaceOrigin.Dir)
		if err != nil {
			return nil, fmt.Errorf("%s: workspace: %v", c.WorkspaceOrigin, err)
		}
		base := c.WorkspaceOrigin.Dir
		if base == "" {
			base = ctx.DefaultWorkspace
		}
		ws = pathutil.Absolute(e, base)
	}
	wsRes, ok := pathutil.Resolve(ws)
	if !ok {
		return nil, fmt.Errorf("Workspace %s existiert nicht", ws)
	}
	p.Workspace = wsRes
	vars.Workspace = wsRes

	for _, f := range ctx.ConfigFiles {
		r, _ := pathutil.Resolve(f)
		p.ConfigFiles = append(p.ConfigFiles, r)
	}

	// Dateisystem
	add := func(kind Kind, it config.Item, note string) {
		for _, r := range p.resolveItem(vars, kind, it, note, ctx) {
			p.Rules = append(p.Rules, r)
		}
	}
	builtin := config.Origin{Source: "builtin"}
	p.Rules = append(p.Rules,
		Rule{Kind: KindWrite, Path: wsRes, Exists: true, IsDir: true, Origin: builtin, Note: "Workspace"})
	if ctx.SdbxTmp != "" {
		p.Rules = append(p.Rules, Rule{Kind: KindWrite, Path: ctx.SdbxTmp, Exists: true, IsDir: true, Origin: builtin, Note: "privates Temp-Verzeichnis"})
	}
	tmp := ctx.SharedTmp
	if tmp == "" {
		tmp = "/tmp"
		if ctx.Platform == "darwin" {
			tmp = "/private/tmp"
		}
	}
	p.Rules = append(p.Rules, Rule{Kind: KindWrite, Path: tmp, Exists: true, IsDir: true, Origin: builtin, Note: "/tmp"})
	for _, x := range ctx.ExtraWrite {
		r, ex := pathutil.Resolve(x)
		if ex {
			p.Rules = append(p.Rules, Rule{Kind: KindWrite, Path: r, Exists: true, IsDir: true, Origin: builtin, Note: "System-Cache"})
		}
	}
	if c.FSDefault == "deny" {
		for _, b := range SystemBase[ctx.Platform] {
			if r, ex := pathutil.Resolve(b); ex {
				p.Rules = append(p.Rules, Rule{Kind: KindSystem, Path: r, Exists: true, IsDir: isDir(r), Origin: builtin, Note: "Systembasis"})
			}
		}
	}
	for _, it := range c.FSRead {
		add(KindRead, it, "")
	}
	for _, it := range c.FSWrite {
		add(KindWrite, it, "")
	}
	if c.FSCreateMissing {
		for i := range p.Rules {
			if p.Rules[i].Kind == KindWrite && !p.Rules[i].Exists && p.Rules[i].Glob == "" {
				p.Rules[i].Create = true
			}
		}
	}
	for _, it := range c.FSReadonly {
		add(KindReadonly, it, "")
	}
	for _, it := range c.FSDeny {
		add(KindDeny, it, "")
	}

	// Secret-Sperrliste abzüglich exempt
	exempt := map[string]config.Origin{}
	for _, it := range c.FSExempt {
		e, err := vars.Expand(it.Value, it.Origin.Dir)
		if err != nil {
			p.fail("%s: filesystem.exempt: %v", it.Origin, err)
			continue
		}
		r, _ := pathutil.Resolve(pathutil.Absolute(e, nz(it.Origin.Dir, wsRes)))
		exempt[r] = it.Origin
	}
	usedExempt := map[string]bool{}
	for _, s := range SecretDenylist {
		abs := s.Path
		if !filepath.IsAbs(abs) {
			abs = filepath.Join(ctx.Home, abs)
		}
		r, ex := pathutil.Resolve(abs)
		if _, ok := exempt[r]; ok {
			usedExempt[r] = true
			continue
		}
		rule := Rule{Kind: KindDeny, Path: r, Exists: ex, IsDir: ex && isDir(r), Origin: builtin, Note: "Secret-Sperrliste: " + s.Category}
		for _, e := range s.Except {
			er, eex := pathutil.Resolve(filepath.Join(r, e))
			if eex {
				rule.Except = append(rule.Except, er)
			}
		}
		p.Rules = append(p.Rules, rule)
	}
	for r, o := range exempt {
		if !usedExempt[r] {
			p.warn("%s: filesystem.exempt: %s steht nicht in der Secret-Sperrliste", o, r)
		}
	}

	// Geschützte Pfade abzüglich unprotect
	unprotect := map[string]config.Origin{}
	for _, it := range c.FSUnprotect {
		e, err := vars.Expand(it.Value, it.Origin.Dir)
		if err != nil {
			p.fail("%s: filesystem.unprotect: %v", it.Origin, err)
			continue
		}
		r, _ := pathutil.Resolve(pathutil.Absolute(e, nz(it.Origin.Dir, wsRes)))
		unprotect[r] = it.Origin
	}
	usedUnprotect := map[string]bool{}
	protect := func(path, note string) *Rule {
		r, ex := pathutil.Resolve(path)
		if o, ok := unprotect[r]; ok {
			usedUnprotect[r] = true
			p.warn("%s: Schutz für %s aufgehoben (filesystem.unprotect)", o, r)
			return nil
		}
		p.Rules = append(p.Rules, Rule{Kind: KindProtected, Path: r, Exists: ex, IsDir: ex && isDir(r), Origin: builtin, Note: note})
		return &p.Rules[len(p.Rules)-1]
	}
	for _, f := range p.ConfigFiles {
		protect(f, "sdbx-Konfiguration")
	}
	// Veraltete Projektdatei im Workspace: nicht laden, aber gegen Änderung schützen
	for _, n := range config.ProjectFileNames {
		protect(filepath.Join(wsRes, n), "veraltete Workspace-Konfiguration")
	}
	p.Repos = FindRepos(wsRes)
	for _, repo := range p.Repos {
		for _, rel := range ProtectedInRepo {
			protect(filepath.Join(repo, rel), "geschützt im Repository")
		}
	}
	if d := filepath.Dir(config.GlobalConfigPath(ctx.Home)); ctx.Home != "" && d != filepath.Join(ctx.Home, ".config", "sdbx") {
		protect(d, "sdbx-Konfigurationsverzeichnis")
	}
	for _, rel := range ProtectedInHome {
		full := filepath.Join(ctx.Home, rel)
		// Nur Bin-Verzeichnisse dürfen per explizitem write freigegeben werden (z. B. für
		// Installer); alles andere braucht filesystem.unprotect.
		if slices.Contains(HomeBinDirs, rel) {
			if fr, _ := pathutil.Resolve(full); p.explicitWrite(fr) {
				if !slices.Contains(filepath.SplitList(ctx.PathEnv), fr) && !slices.Contains(filepath.SplitList(ctx.PathEnv), full) {
					p.warn("%s ist beschreibbar freigegeben – Programme darin können ersetzt werden, sobald es in PATH steht", fr)
				}
				continue
			}
		}
		pr := protect(full, "geschützt im Home")
		// Fehlt ein PATH-Verzeichnis unter einem Schreibbereich, legt der Supervisor es vor dem
		// Start an – sonst könnte die Sandbox es selbst anlegen und befüllen.
		if pr != nil && !pr.Exists && slices.Contains(ProtectedHomeDirs, rel) && p.underWrite(pr.Path) {
			pr.Create, pr.IsDir = true, true
		}
	}
	for r, o := range unprotect {
		if !usedUnprotect[r] {
			p.warn("%s: filesystem.unprotect: %s ist kein geschützter Pfad", o, r)
		}
	}
	p.protectPathDirs(ctx.PathEnv, wsRes)

	// Netzwerk
	m := &netmatch.Matcher{DefaultAllow: c.NetDefault == "allow", Ports: c.NetPorts, AllowPrivate: c.NetAllowPrivate}
	for _, it := range c.NetAllow {
		pt, err := netmatch.Parse(it.Value)
		if err != nil {
			p.fail("%s: network.allow: %v", it.Origin, err)
			continue
		}
		pt.Source = it.Origin.String()
		m.Allow = append(m.Allow, pt)
	}
	for _, it := range c.NetDeny {
		pt, err := netmatch.Parse(it.Value)
		if err != nil {
			p.fail("%s: network.deny: %v", it.Origin, err)
			continue
		}
		pt.Source = it.Origin.String()
		m.Deny = append(m.Deny, pt)
	}
	p.Net = NetPolicy{Mode: c.NetMode, Matcher: m, Local: c.NetLocal, SSH: c.NetSSH}
	if c.NetMode == "host" {
		p.warn("network.mode: host – Netzwerk ist uneingeschränkt; network.allow/deny werden ignoriert")
	}
	if c.NetMode != "proxy" && (len(c.NetAllow) > 0 || len(c.NetDeny) > 0) && c.NetMode != "host" {
		p.warn("network.mode: %s – network.allow/deny haben keine Wirkung", c.NetMode)
	}

	// Sockets
	for _, it := range c.SocketsAllow {
		e, err := vars.Expand(it.Value, it.Origin.Dir)
		if err != nil {
			p.fail("%s: sockets.allow: %v", it.Origin, err)
			continue
		}
		a := pathutil.Absolute(e, nz(it.Origin.Dir, wsRes))
		if pathutil.HasGlob(a) {
			pre, _ := pathutil.Resolve(pathutil.StaticPrefix(a))
			p.Sockets = append(p.Sockets, SocketRule{Glob: pre + strings.TrimPrefix(a, pathutil.StaticPrefix(a)), Origin: it.Origin})
			continue
		}
		r, _ := pathutil.Resolve(a)
		p.Sockets = append(p.Sockets, SocketRule{Path: r, Origin: it.Origin})
	}
	for _, s := range ctx.SocketDeny {
		r, _ := pathutil.Resolve(s)
		p.SocketDeny = append(p.SocketDeny, r)
	}

	// Umgebung
	p.Env = EnvPolicy{Mode: c.EnvMode, Set: map[string]string{}}
	p.Env.Passthrough = c.EnvPassthrough.Values()
	p.Env.Deny = c.EnvDeny.Values()
	keys := make([]string, 0, len(c.EnvSet))
	for k := range c.EnvSet {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		sv := c.EnvSet[k]
		v, err := vars.Expand(sv.Value, sv.Origin.Dir)
		var dropped *pathutil.ErrDropped
		if errors.As(err, &dropped) {
			p.warn("%s: env.set.%s entfällt: %v", sv.Origin, k, err)
			continue
		}
		if err != nil {
			p.fail("%s: env.set.%s: %v", sv.Origin, k, err)
			continue
		}
		p.Env.Set[k] = v
	}

	// macOS
	p.MachServices, p.MachNoReport = p.expandMach(c.MachServices)

	// Linux-Geräte
	for _, it := range c.LinuxDevices {
		// Geräte werden beschreibbar eingebunden (--dev-bind): ".." oder ein Symlink nach außerhalb
		// von /dev würde beliebige Host-Pfade beschreibbar machen.
		d, _ := pathutil.Resolve(filepath.Clean(it.Value))
		if !filepath.IsAbs(it.Value) || d == "/dev" || !pathutil.IsUnder(d, "/dev") {
			p.fail("%s: linux.devices: %q liegt nicht unter /dev", it.Origin, it.Value)
			continue
		}
		p.Linux.Devices = append(p.Linux.Devices, d)
		p.warn("%s: Gerät %s ist in der Sandbox verfügbar", it.Origin, d)
	}
	p.checkOverlaps()
	return p, nil
}

func nz(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// resolveItem expandiert, löst auf und erzeugt Regeln für einen Konfigurationseintrag.
func (p *Policy) resolveItem(vars pathutil.Vars, kind Kind, it config.Item, note string, ctx Context) []Rule {
	section := map[Kind]string{KindRead: "read", KindWrite: "write", KindDeny: "deny", KindReadonly: "readonly"}[kind]
	e, err := vars.Expand(it.Value, it.Origin.Dir)
	var dropped *pathutil.ErrDropped
	if errors.As(err, &dropped) {
		p.warn("%s: filesystem.%s %q entfällt: %v", it.Origin, section, it.Value, err)
		return nil
	}
	if err != nil {
		p.fail("%s: filesystem.%s: %v", it.Origin, section, err)
		return nil
	}
	abs := pathutil.Absolute(e, nz(it.Origin.Dir, p.Workspace))
	if pathutil.HasGlob(abs) {
		prefix := pathutil.StaticPrefix(abs)
		pre, _ := pathutil.Resolve(prefix)
		glob := pre + strings.TrimPrefix(abs, prefix)
		re, err := pathutil.GlobRegex(glob)
		if err != nil {
			p.fail("%s: filesystem.%s: %v", it.Origin, section, err)
			return nil
		}
		if ctx.Platform == "linux" {
			p.warn("%s: Glob %q gilt unter Linux nur für Pfade, die beim Start existieren", it.Origin, it.Value)
		}
		return []Rule{{Kind: kind, Glob: glob, Regex: re, Origin: it.Origin, Note: note}}
	}
	r, ex := pathutil.Resolve(abs)
	if !ex && kind == KindWrite && !optionalSource(it.Origin.Source) {
		p.warn("%s: filesystem.write %s existiert nicht und wird übersprungen (create_missing: true legt es an)", it.Origin, r)
	}
	if !ex && (kind == KindRead || kind == KindReadonly) && !optionalSource(it.Origin.Source) {
		p.warn("%s: filesystem.%s %s existiert nicht", it.Origin, section, r)
	}
	return []Rule{{Kind: kind, Path: r, Exists: ex, IsDir: ex && isDir(r), Origin: it.Origin, Note: note}}
}

// protectPathDirs macht PATH-Verzeichnisse außerhalb des Workspaces schreibgeschützt (Spec 5.4).
func (p *Policy) protectPathDirs(pathEnv, ws string) {
	for _, d := range filepath.SplitList(pathEnv) {
		if d == "" || !filepath.IsAbs(d) {
			continue
		}
		r, ex := pathutil.Resolve(d)
		if !ex || pathutil.IsUnder(r, ws) {
			continue
		}
		exact, covered := false, false
		for _, rule := range p.Rules {
			if rule.Kind != KindWrite || rule.Glob != "" {
				continue
			}
			if rule.Path == r && rule.Origin.Source != "builtin" {
				exact = true
			}
			if pathutil.IsUnder(r, rule.Path) {
				covered = true
			}
		}
		if exact {
			p.warn("PATH-Verzeichnis %s ist beschreibbar freigegeben – Programme darin können ersetzt werden (PATH-Hijacking)", r)
			continue
		}
		if covered {
			p.Rules = append(p.Rules, Rule{Kind: KindReadonly, Path: r, Exists: true, IsDir: true, Origin: config.Origin{Source: "builtin"}, Note: "PATH-Verzeichnis"})
		}
	}
}

// checkOverlaps meldet Freigaben, die durch Sperren wirkungslos sind.
func (p *Policy) checkOverlaps() {
	for _, w := range p.Rules {
		if w.Kind != KindWrite || w.Glob != "" || w.Origin.Source == "builtin" {
			continue
		}
		for _, d := range p.Rules {
			if d.Kind == KindDeny && d.Glob == "" && pathutil.IsUnder(w.Path, d.Path) {
				p.warn("%s: filesystem.write %s liegt unter deny %s (%s) und bleibt gesperrt", w.Origin, w.Path, d.Path, d.Origin)
			}
		}
	}
}

// expandMach löst Gruppen auf und warnt bei gefährlichen Diensten.
func (p *Policy) expandMach(items config.List) (services, noReport []string) {
	seen := map[string]bool{}
	for _, it := range items {
		if g, ok := MachGroups[it.Value]; ok {
			for _, s := range g {
				if !seen[s] {
					seen[s] = true
					services = append(services, s)
				}
			}
			continue
		}
		if !strings.Contains(it.Value, ".") {
			p.fail("%s: macos.mach_services: unbekannte Gruppe %q (bekannt: default, keychain, fsevents, dns)", it.Origin, it.Value)
			continue
		}
		for _, d := range MachDangerousPrefixes {
			if strings.HasPrefix(it.Value, d) {
				p.warn("%s: Mach-Service %s ermöglicht Zugriff außerhalb der Sandbox (Spec 7.4)", it.Origin, it.Value)
			}
		}
		if !seen[it.Value] {
			seen[it.Value] = true
			services = append(services, it.Value)
		}
	}
	for _, s := range MachNoReport {
		if !seen[s] {
			noReport = append(noReport, s)
		}
	}
	return services, noReport
}

// Match ist eine Regel, die auf einen Pfad zutrifft.
type Match struct {
	Rule   Rule
	Effect string
}

// Decision ist das Ergebnis von Evaluate.
type Decision struct {
	Path    string
	Access  Access
	Matches []Match
	Reason  string
}

// Evaluate wertet einen Pfad nach Spec 5.2 aus.
func (p *Policy) Evaluate(path string) Decision {
	abs := pathutil.Absolute(path, p.Workspace)
	r, _ := pathutil.Resolve(abs)
	d := Decision{Path: r}
	var deny, protected, readonly, write, read *Rule
	for i := range p.Rules {
		rule := p.Rules[i]
		if !rule.Matches(r) {
			continue
		}
		effect := ""
		switch rule.Kind {
		case KindDeny:
			excepted := false
			for _, e := range rule.Except {
				if pathutil.IsUnder(r, e) {
					excepted = true
				}
			}
			if excepted {
				effect = "Ausnahme: lesbar"
				if read == nil {
					read = &p.Rules[i]
				}
			} else {
				effect = "sperrt"
				if deny == nil {
					deny = &p.Rules[i]
				}
			}
		case KindProtected:
			effect = "höchstens lesen"
			protected = &p.Rules[i]
		case KindReadonly:
			effect = "höchstens lesen"
			readonly = &p.Rules[i]
		case KindWrite:
			effect = "schreiben"
			write = &p.Rules[i]
		case KindRead, KindSystem:
			effect = "lesen"
			read = &p.Rules[i]
		}
		d.Matches = append(d.Matches, Match{Rule: rule, Effect: effect})
	}
	base := None
	switch {
	case write != nil:
		base, d.Reason = Write, "Schreibbereich "+write.Label()
	case read != nil:
		base, d.Reason = Read, "Lesebereich "+read.Label()
	case p.FSDefault == "read":
		base, d.Reason = Read, "filesystem.default: read"
	default:
		d.Reason = "filesystem.default: deny"
	}
	switch {
	case deny != nil:
		d.Access, d.Reason = None, "gesperrt durch "+deny.Label()+" ["+deny.Origin.String()+"]"
	case (protected != nil || readonly != nil) && base == Write:
		x := protected
		if x == nil {
			x = readonly
		}
		d.Access, d.Reason = Read, "schreibgeschützt durch "+x.Label()+" ["+x.Origin.String()+"]"
	default:
		d.Access = base
	}
	return d
}

// FindRepos liefert den Workspace und alle Git-Repositories darunter (ohne Abhängigkeits- und Build-Verzeichnisse).
func FindRepos(ws string) []string {
	repos := []string{ws}
	skip := map[string]bool{"node_modules": true, "vendor": true, ".cache": true, "target": true, "dist": true, "build": true, ".venv": true}
	_ = filepath.WalkDir(ws, func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		if p == ws {
			return nil
		}
		if skip[d.Name()] {
			return filepath.SkipDir
		}
		if d.Name() == ".git" {
			if parent := filepath.Dir(p); parent != ws {
				repos = append(repos, parent)
			}
			return filepath.SkipDir
		}
		return nil
	})
	return repos
}
