// Package clausona setzt die clausona-Integration um (Spec 8.2).
package clausona

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"sdbx/internal/audit"
	"sdbx/internal/config"
	"sdbx/internal/integrations"
)

// Name der Integration.
const Name = "clausona"

// Profile entspricht clausonas Profile-Typ (Registry Version 2).
type Profile struct {
	Key           string            `json:"-"`
	Tool          string            `json:"tool"`
	Kind          string            `json:"kind,omitempty"`
	ConfigDir     string            `json:"configDir"`
	Email         string            `json:"email"`
	Label         string            `json:"label,omitempty"`
	IsPrimary     bool              `json:"isPrimary,omitempty"`
	MergeSessions bool              `json:"mergeSessions,omitempty"`
	API           *APIEndpoint      `json:"api,omitempty"`
	Env           map[string]string `json:"env,omitempty"`
}

// APIEndpoint enthält die Basis-URL eines API-Profils (der Schlüssel liegt nie in der Registry).
type APIEndpoint struct {
	BaseURL string          `json:"baseUrl"`
	Secret  json.RawMessage `json:"secret,omitempty"`
}

// Registry entspricht ~/.clausona/profiles.json.
type Registry struct {
	Version        int                 `json:"version"`
	PrimarySources map[string]string   `json:"primarySources"`
	ActiveProfiles map[string]string   `json:"activeProfiles"`
	Profiles       map[string]*Profile `json:"profiles"`
}

// Dir liefert ~/.clausona.
func Dir(home string) string { return filepath.Join(home, ".clausona") }

// Detect meldet, ob clausona installiert ist.
func Detect(home string) bool {
	if _, err := exec.LookPath("clausona"); err == nil {
		return true
	}
	st, err := os.Stat(Dir(home))
	return err == nil && st.IsDir()
}

// LoadRegistry liest und prüft die Registry.
func LoadRegistry(home string) (*Registry, error) {
	path := filepath.Join(Dir(home), "profiles.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("clausona-Registry %s nicht lesbar: %w", path, err)
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("clausona-Registry %s ist kein gültiges JSON: %w", path, err)
	}
	if _, v1 := probe["primarySource"]; v1 {
		if _, hasVersion := probe["version"]; !hasVersion {
			return nil, fmt.Errorf("clausona-Registry hat das alte Format (v1); einmal \"clausona list\" ausführen, dann migriert clausona sie selbst")
		}
	}
	var r Registry
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("clausona-Registry: %w", err)
	}
	if r.Version != 2 {
		return nil, fmt.Errorf("clausona-Registry Version %d wird nicht unterstützt (erwartet 2)", r.Version)
	}
	for tool, d := range r.PrimarySources {
		r.PrimarySources[tool] = expandHome(d, home)
	}
	for k, p := range r.Profiles {
		if p == nil || p.ConfigDir == "" || (p.Tool != "claude" && p.Tool != "codex") {
			return nil, fmt.Errorf("clausona-Registry: Profil %q ist unvollständig", k)
		}
		p.Key = k
		p.ConfigDir = expandHome(p.ConfigDir, home)
	}
	return &r, nil
}

func expandHome(p, home string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		return home + p[1:]
	}
	return p
}

// Lookup findet ein Profil per "tool:name" oder eindeutigem Namen.
func (r *Registry) Lookup(ref string) (*Profile, error) {
	if p, ok := r.Profiles[ref]; ok {
		return p, nil
	}
	var hits []*Profile
	for k, p := range r.Profiles {
		if _, name, _ := strings.Cut(k, ":"); name == ref {
			hits = append(hits, p)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return nil, fmt.Errorf("clausona-Profil %q unbekannt", ref)
	}
	return nil, fmt.Errorf("clausona-Profil %q ist mehrdeutig; claude:%s oder codex:%s angeben", ref, ref, ref)
}

// Primary liefert das Primärverzeichnis eines Werkzeugs.
func (r *Registry) Primary(tool string) string {
	if d := r.PrimarySources[tool]; d != "" {
		return d
	}
	for _, p := range r.Profiles {
		if p.Tool == tool && p.IsPrimary {
			return p.ConfigDir
		}
	}
	return ""
}

func (r *Registry) sorted() []*Profile {
	out := make([]*Profile, 0, len(r.Profiles))
	for _, p := range r.Profiles {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// Pfadtabellen (Spec 8.2, nach clausonas eigener Analyse).
var (
	ClaudeConfig = []string{"settings.json", "settings.local.json", "CLAUDE.md", "keybindings.json", "agents", "commands",
		"skills", "output-styles", "hooks", "plugins", "mcp-servers", "loop.md"}
	ClaudeAccount = []string{".credentials.json", "projects", "jobs", "teams", "sessions", "todos", "tasks", "plans",
		"file-history", "shell-snapshots", "session-env", "history.jsonl", "state", "daemon", "daemon.json", "daemon.lock",
		"telemetry", "backups", "chrome", "cache", "statsig", "policy-limits.json", "remote-settings.json"}
	ClaudeMerged = []string{"projects", "jobs", "teams"}
	CodexConfig  = []string{"config.toml", "*.config.toml", "hooks.json", "AGENTS*.md", "rules", "skills", "plugins",
		"agents", "prompts", "vendor_imports", ".env", "packages"}
	CodexAccount   = []string{"auth.json", "sessions", "archived_sessions", "history.jsonl", "memories", "*.sqlite", "memories_*.sqlite"}
	ClausonaState  = []string{"usage.json", "quota.json", "notices.json", "locks"}
	ClausonaConfig = []string{"profiles.json", "routes.json", "cache", "bin"}
)

// ClaudeJSON liefert den Pfad von .claude.json zu einem Config-Verzeichnis.
func ClaudeJSON(home, configDir string) string {
	if filepath.Clean(configDir) == filepath.Join(home, ".claude") {
		return filepath.Join(home, ".claude.json")
	}
	return filepath.Join(configDir, ".claude.json")
}

// ClaudeDaemonSocket berechnet den Socket-Pfad des Claude-Code-Daemons
// (erste 8 Hex-Zeichen von SHA-256 über den absoluten Config-Pfad).
func ClaudeDaemonSocket(tmpRoot string, uid int, configDir string) string {
	abs, _ := filepath.Abs(configDir)
	sum := sha256.Sum256([]byte(abs))
	return filepath.Join(tmpRoot, fmt.Sprintf("cc-daemon-%d", uid), hex.EncodeToString(sum[:])[:8], "control.sock")
}

// CodexDaemonSockets liest die Socket-Symlinks, die Codex in CODEX_HOME anlegt.
func CodexDaemonSockets(codexHome string) []string {
	var out []string
	for _, rel := range []string{"app-server-control/app-server-control.sock", "app-server-daemon/daemon-updater.sock"} {
		if t, err := os.Readlink(filepath.Join(codexHome, rel)); err == nil {
			out = append(out, t)
		}
	}
	return out
}

func socketAlive(path string) bool {
	c, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func base(s string) string { return filepath.Base(s) }

// DetermineProfiles ermittelt die zugänglichen Profile (Spec 8.2).
func DetermineProfiles(r *Registry, s config.ClausonaSettings, rc integrations.RunContext) ([]*Profile, error) {
	switch s.Profiles.Kind {
	case "all":
		return r.sorted(), nil
	case "list":
		var out []*Profile
		for _, ref := range s.Profiles.List {
			p, err := r.Lookup(ref)
			if err != nil {
				return nil, err
			}
			out = append(out, p)
		}
		return out, nil
	}
	if s.Profile != "" {
		p, err := r.Lookup(s.Profile)
		if err != nil {
			return nil, err
		}
		return []*Profile{p}, nil
	}
	argv := rc.Argv
	if len(argv) == 0 {
		return nil, errNoProfile
	}
	switch b := base(argv[0]); b {
	case "clausona", "csn":
		if len(argv) > 1 && argv[1] == "run" {
			return fromRun(r, argv[2:], rc.Home)
		}
	case "claude", "codex":
		envKey := map[string]string{"claude": "CLAUDE_CONFIG_DIR", "codex": "CODEX_HOME"}[b]
		if d := rc.Env[envKey]; d != "" {
			for _, p := range r.sorted() {
				if p.Tool == b && filepath.Clean(p.ConfigDir) == filepath.Clean(expandHome(d, rc.Home)) {
					return []*Profile{p}, nil
				}
			}
			return nil, fmt.Errorf("clausona: %s=%s gehört zu keinem Profil", envKey, d)
		}
		return active(r, b)
	}
	return nil, errNoProfile
}

var errNoProfile = fmt.Errorf("clausona: aktives Profil nicht ermittelbar – \"sdbx run -- clausona run claude:<profil>\" verwenden, " +
	"--integration clausona.profile=<profil> angeben oder integrations.clausona.profiles: all setzen")

func active(r *Registry, tool string) ([]*Profile, error) {
	key := r.ActiveProfiles[tool]
	p, ok := r.Profiles[key]
	if !ok {
		return nil, fmt.Errorf("clausona: kein aktives %s-Profil", tool)
	}
	return []*Profile{p}, nil
}

func fromRun(r *Registry, args []string, home string) ([]*Profile, error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if a == "--route" || strings.HasPrefix(a, "--route=") {
			name := strings.TrimPrefix(a, "--route=")
			if a == "--route" && i+1 < len(args) {
				name = args[i+1]
			}
			return routeProfiles(r, name, home)
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		tool, prof, hasProf := strings.Cut(a, ":")
		if tool != "claude" && tool != "codex" {
			return nil, fmt.Errorf("clausona run: unbekanntes Werkzeug %q", tool)
		}
		if hasProf {
			p, err := r.Lookup(tool + ":" + prof)
			if err != nil {
				return nil, err
			}
			return []*Profile{p}, nil
		}
		return active(r, tool)
	}
	return nil, errNoProfile
}

// routeProfiles liest die Profile einer Route. Das Format des Routen-Speichers ist
// nicht dokumentiert; gesucht wird defensiv nach Profilschlüsseln unter dem Routennamen.
func routeProfiles(r *Registry, name, home string) ([]*Profile, error) {
	data, err := os.ReadFile(filepath.Join(Dir(home), "routes.json"))
	if err != nil {
		return nil, fmt.Errorf("clausona: Route %q nicht lesbar (%v); --integration clausona.profiles=all verwenden", name, err)
	}
	var raw any
	if json.Unmarshal(data, &raw) != nil {
		return nil, fmt.Errorf("clausona: routes.json ist kein gültiges JSON")
	}
	var node any = raw
	if m, ok := raw.(map[string]any); ok {
		if routes, ok := m["routes"].(map[string]any); ok {
			node = routes[name]
		} else {
			node = m[name]
		}
	}
	if node == nil {
		return nil, fmt.Errorf("clausona: Route %q nicht gefunden", name)
	}
	seen := map[string]bool{}
	var out []*Profile
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			if p, ok := r.Profiles[x]; ok && !seen[x] {
				seen[x] = true
				out = append(out, p)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(node)
	if len(out) == 0 {
		return nil, fmt.Errorf("clausona: Route %q enthält keine bekannten Profile", name)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// Resolve erzeugt das Fragment der Integration.
func Resolve(s config.ClausonaSettings, rc integrations.RunContext) (*integrations.Result, error) {
	res := &integrations.Result{Name: Name}
	if s.Mode == "off" {
		return res, nil
	}
	if !Detect(rc.Home) {
		return nil, fmt.Errorf("Integration clausona ist aktiviert, aber clausona ist nicht installiert")
	}
	reg, err := LoadRegistry(rc.Home)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("Integration clausona ist aktiviert, aber clausona ist noch nicht eingerichtet (%s fehlt) – "+
			"clausona einrichten oder integrations.clausona aus der Konfiguration entfernen (einmalig: --integration clausona=off)",
			filepath.Join(Dir(rc.Home), "profiles.json"))
	}
	if err != nil {
		return nil, err
	}
	profs, err := DetermineProfiles(reg, s, rc)
	if err != nil {
		return nil, err
	}
	src := integrations.Source(Name)
	o := config.Origin{Source: src}
	f := &config.File{Version: config.Ptr(1)}
	fs := &config.Filesystem{}
	net := &config.Network{}
	env := &config.Env{Set: map[string]string{"NODE_USE_ENV_PROXY": "1"}}
	f.Filesystem, f.Network, f.Env = fs, net, env
	f.Process = &config.Process{IsolatePids: config.Ptr(false), PrivateTmp: config.Ptr(false)}
	res.Required = []config.RequiredValue{
		{Key: "process.isolate_pids", Value: false, Source: src},
		{Key: "process.private_tmp", Value: false, Source: src},
	}
	items := func(vals ...string) config.List { return config.Items(o, vals...) }
	join := func(dir string, rels []string) []string {
		out := make([]string, len(rels))
		for i, r := range rels {
			out[i] = filepath.Join(dir, r)
		}
		return out
	}
	accessible := map[string]bool{}
	tools := map[string]bool{}
	hasAPI := false
	mergedTools := map[string]bool{}
	for _, p := range profs {
		accessible[filepath.Clean(p.ConfigDir)] = true
		tools[p.Tool] = true
		if p.Kind == "api" {
			hasAPI = true
		}
		if p.MergeSessions {
			mergedTools[p.Tool] = true
		}
		fs.Write = append(fs.Write, items(p.ConfigDir)...)
		switch p.Tool {
		case "claude":
			cj := ClaudeJSON(rc.Home, p.ConfigDir)
			fs.Write = append(fs.Write, items(cj, cj+".*")...)
			if s.Mode == "ro" {
				fs.Readonly = append(fs.Readonly, items(join(p.ConfigDir, ClaudeConfig)...)...)
			}
		case "codex":
			if s.Mode == "ro" {
				fs.Readonly = append(fs.Readonly, items(join(p.ConfigDir, CodexConfig)...)...)
			}
		}
		if p.API != nil && p.API.BaseURL != "" {
			if u, err := url.Parse(p.API.BaseURL); err == nil && u.Hostname() != "" {
				net.Allow = append(net.Allow, items(u.Hostname())...)
			}
		}
	}
	// Nicht zugängliche Profile sperren; Primärverzeichnisse nur kontoeigen sperren.
	for _, p := range reg.sorted() {
		if accessible[filepath.Clean(p.ConfigDir)] {
			continue
		}
		primary := filepath.Clean(reg.Primary(p.Tool)) == filepath.Clean(p.ConfigDir)
		if !primary {
			fs.Deny = append(fs.Deny, items(p.ConfigDir)...)
			continue
		}
		switch p.Tool {
		case "claude":
			acct := ClaudeAccount
			if mergedTools["claude"] {
				acct = without(acct, ClaudeMerged...)
				fs.Write = append(fs.Write, items(join(p.ConfigDir, ClaudeMerged)...)...)
			}
			fs.Deny = append(fs.Deny, items(join(p.ConfigDir, acct)...)...)
			fs.Deny = append(fs.Deny, items(ClaudeJSON(rc.Home, p.ConfigDir))...)
		case "codex":
			if mergedTools["codex"] {
				fs.Write = append(fs.Write, items(p.ConfigDir)...)
				fs.Deny = append(fs.Deny, items(join(p.ConfigDir, []string{"auth.json", "memories", "memories_*.sqlite"})...)...)
				if s.Mode == "ro" {
					fs.Readonly = append(fs.Readonly, items(join(p.ConfigDir, CodexConfig)...)...)
				}
			} else {
				fs.Deny = append(fs.Deny, items(join(p.ConfigDir, CodexAccount)...)...)
			}
		}
	}
	// ~/.clausona
	cd := Dir(rc.Home)
	fs.Write = append(fs.Write, items(cd)...)
	if s.Mode == "ro" {
		fs.Readonly = append(fs.Readonly, items(join(cd, ClausonaConfig)...)...)
	}
	if s.Profiles.Kind == "active" || s.Profiles.Kind == "list" {
		fs.Deny = append(fs.Deny, items(filepath.Join(cd, "backups"))...)
	}
	if !hasAPI {
		fs.Deny = append(fs.Deny, items(filepath.Join(cd, "secrets.json"))...)
	}
	// Netzwerk
	if tools["claude"] {
		net.Allow = append(net.Allow, items("api.anthropic.com", "platform.claude.com")...)
	}
	if tools["codex"] {
		net.Allow = append(net.Allow, items("chatgpt.com", "auth.openai.com")...)
	}
	if s.Mode == "rw" {
		net.Allow = append(net.Allow, items("github.com", "*.githubusercontent.com")...)
	}
	if s.IDE && tools["claude"] {
		for _, p := range profs {
			if p.Tool == "claude" {
				net.Local = append(net.Local, IDEPorts(filepath.Join(p.ConfigDir, "ide"))...)
			}
		}
	}
	// Umgebung
	env.Passthrough = items("CLAUDE_CONFIG_DIR", "CODEX_HOME", "ANTHROPIC_BASE_URL")
	if hasAPI {
		env.Passthrough = append(env.Passthrough, items("ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY")...)
	}
	if len(profs) == 1 && len(rc.Argv) > 0 {
		p := profs[0]
		switch base(rc.Argv[0]) {
		case "claude":
			if p.Tool == "claude" && rc.Env["CLAUDE_CONFIG_DIR"] == "" {
				env.Set["CLAUDE_CONFIG_DIR"] = p.ConfigDir
			}
		case "codex":
			if p.Tool == "codex" && rc.Env["CODEX_HOME"] == "" {
				env.Set["CODEX_HOME"] = p.ConfigDir
			}
		}
	}
	f.MacOS = &config.MacOS{MachServices: items("keychain")}
	f.Integrations = nil
	// Daemons (Spec 8.2)
	tmpRoot := rc.TmpRoot
	if tmpRoot == "" {
		tmpRoot = "/tmp"
	}
	ccDir := filepath.Join(tmpRoot, fmt.Sprintf("cc-daemon-%d", rc.UID))
	cxDir := filepath.Join(tmpRoot, fmt.Sprintf("codex-daemon-%d", rc.UID))
	existing := append(listSockets(ccDir), listSockets(cxDir)...)
	switch s.Daemons {
	case "off":
		res.SocketDeny = existing
		if tools["codex"] {
			res.Argv = RewriteCodex(rc.Argv)
		}
	case "sandboxed":
		for _, p := range profs {
			var socks []string
			stop := ""
			if p.Tool == "claude" {
				socks = []string{ClaudeDaemonSocket(tmpRoot, rc.UID, p.ConfigDir)}
				stop = fmt.Sprintf("CLAUDE_CONFIG_DIR=%s claude daemon stop", p.ConfigDir)
			} else {
				socks = CodexDaemonSockets(p.ConfigDir)
				stop = fmt.Sprintf("CODEX_HOME=%s codex app-server daemon stop", p.ConfigDir)
			}
			for _, sk := range socks {
				if socketAlive(sk) {
					res.Errors = append(res.Errors, fmt.Sprintf("clausona: Daemon für %s läuft außerhalb der Sandbox (%s); vorher beenden: %s", p.Key, sk, stop))
				}
			}
		}
		res.SocketDeny = existing
		res.SocketAllowDirs = []string{ccDir, cxDir}
	case "host":
		res.SocketAllowDirs = []string{ccDir, cxDir}
		res.Notes = append(res.Notes, "integrations.clausona.daemons: host – Agenten-Daemons außerhalb der Sandbox sind erreichbar; ihre Aktionen sind nicht eingeschränkt")
	}
	if rc.Platform == "linux" {
		res.Notes = append(res.Notes, "Linux: .claude.json im Home-Verzeichnis ist per Bind-Mount beschreibbar; atomares Ersetzen durch Umbenennen ist dort nicht möglich")
	}
	// MCP-Guard
	if s.GuardMCP != "off" {
		var files []string
		for _, p := range profs {
			if p.Tool == "claude" {
				files = append(files, ClaudeJSON(rc.Home, p.ConfigDir))
			}
		}
		g := NewGuard(files, s.GuardMCP, rc.StateDir)
		res.Post = g.Check
	}
	f.Integrations = nil
	res.Fragment = f
	config.Stamp(f, o, "")
	return res, nil
}

func without(list []string, remove ...string) []string {
	var out []string
	for _, l := range list {
		keep := true
		for _, r := range remove {
			keep = keep && l != r
		}
		if keep {
			out = append(out, l)
		}
	}
	return out
}

func listSockets(dir string) []string {
	var out []string
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && d.Type()&os.ModeSocket != 0 {
			out = append(out, p)
		}
		return nil
	})
	return out
}

// IDEPorts liest die Ports aus den Lock-Dateien der IDE-Erweiterung (<port>.lock).
func IDEPorts(dir string) []int {
	ents, _ := os.ReadDir(dir)
	var out []int
	for _, e := range ents {
		if n, err := strconv.Atoi(strings.TrimSuffix(e.Name(), ".lock")); err == nil && n > 0 && n < 65536 {
			out = append(out, n)
		}
	}
	return out
}

// RewriteCodex fügt "-c daemon_auto_start=false" ein (Spec 8.2). Nicht erkannte
// Aufrufwege bleiben unverändert (nil).
func RewriteCodex(argv []string) []string {
	if len(argv) == 0 {
		return nil
	}
	ov := []string{"-c", "daemon_auto_start=false"}
	switch base(argv[0]) {
	case "codex":
		out := append([]string{argv[0]}, ov...)
		return append(out, argv[1:]...)
	case "clausona", "csn":
		if len(argv) < 2 || argv[1] != "run" {
			return nil
		}
		isCodex := false
		for i, a := range argv[2:] {
			if a == "--" {
				break
			}
			if strings.HasPrefix(a, "codex") {
				isCodex = true
			}
			if (a == "--route" || strings.HasPrefix(a, "--route=")) && i >= 0 {
				isCodex = true // Routen können Codex-Profile enthalten
			}
		}
		if !isCodex {
			return nil
		}
		for i, a := range argv {
			if a == "--" {
				out := append([]string{}, argv[:i+1]...)
				out = append(out, ov...)
				return append(out, argv[i+1:]...)
			}
		}
		return append(append([]string{}, argv...), append([]string{"--"}, ov...)...)
	}
	return nil
}

// Guard prüft MCP- und Trust-Einträge in .claude.json (Spec 8.2).
type Guard struct {
	files    []string
	mode     string
	stateDir string
	snap     map[string]map[string]json.RawMessage
}

// guardedKeys liefert die geschützten Einträge einer .claude.json.
func guardedKeys(doc map[string]json.RawMessage) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	if v, ok := doc["mcpServers"]; ok {
		out["mcpServers"] = v
	}
	var projects map[string]map[string]json.RawMessage
	if raw, ok := doc["projects"]; ok && json.Unmarshal(raw, &projects) == nil {
		for dir, pr := range projects {
			for _, k := range []string{"mcpServers", "hasTrustDialogAccepted", "enabledMcpjsonServers", "disabledMcpjsonServers"} {
				if v, ok := pr[k]; ok {
					out["projects/"+dir+"/"+k] = v
				}
			}
		}
	}
	return out
}

func readDoc(path string) (map[string]json.RawMessage, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return doc, nil
}

// NewGuard erstellt den Guard und liest den Ausgangszustand.
func NewGuard(files []string, mode, stateDir string) *Guard {
	g := &Guard{files: files, mode: mode, stateDir: stateDir, snap: map[string]map[string]json.RawMessage{}}
	for _, f := range files {
		if doc, err := readDoc(f); err == nil {
			g.snap[f] = guardedKeys(doc)
		} else {
			g.snap[f] = map[string]json.RawMessage{}
		}
	}
	return g
}

func equalJSON(a, b json.RawMessage) bool {
	var x, y any
	json.Unmarshal(a, &x)
	json.Unmarshal(b, &y)
	xa, _ := json.Marshal(x)
	ya, _ := json.Marshal(y)
	return string(xa) == string(ya)
}

// Check vergleicht nach dem Lauf und meldet bzw. revertiert Änderungen.
func (g *Guard) Check(log *audit.Logger) []string {
	var warns []string
	for _, f := range g.files {
		doc, err := readDoc(f)
		if err != nil {
			continue
		}
		now := guardedKeys(doc)
		before := g.snap[f]
		var changed []string
		for k, v := range now {
			if b, ok := before[k]; !ok || !equalJSON(b, v) {
				changed = append(changed, k)
			}
		}
		for k := range before {
			if _, ok := now[k]; !ok {
				changed = append(changed, k)
			}
		}
		if len(changed) == 0 {
			continue
		}
		sort.Strings(changed)
		log.Emit("integration.clausona.mcp_changed", map[string]any{"file": f, "keys": changed, "mode": g.mode})
		if g.mode != "revert" {
			warns = append(warns, fmt.Sprintf("MCP-/Trust-Einträge in %s wurden in der Sandbox geändert: %s – bitte prüfen (guard_mcp: revert stellt sie automatisch zurück)", f, strings.Join(changed, ", ")))
			continue
		}
		if err := g.revert(f, doc, before); err != nil {
			warns = append(warns, fmt.Sprintf("Zurücksetzen von %s fehlgeschlagen: %v", f, err))
			continue
		}
		warns = append(warns, fmt.Sprintf("MCP-/Trust-Einträge in %s wurden zurückgesetzt: %s", f, strings.Join(changed, ", ")))
	}
	return warns
}

func (g *Guard) revert(path string, doc map[string]json.RawMessage, before map[string]json.RawMessage) error {
	orig, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if g.stateDir != "" {
		os.MkdirAll(g.stateDir, 0o700)
		os.WriteFile(filepath.Join(g.stateDir, filepath.Base(path)+".before-revert."+time.Now().Format("20060102-150405")), orig, 0o600)
	}
	if v, ok := before["mcpServers"]; ok {
		doc["mcpServers"] = v
	} else {
		delete(doc, "mcpServers")
	}
	var projects map[string]map[string]json.RawMessage
	if raw, ok := doc["projects"]; ok && json.Unmarshal(raw, &projects) == nil {
		for dir, pr := range projects {
			for _, k := range []string{"mcpServers", "hasTrustDialogAccepted", "enabledMcpjsonServers", "disabledMcpjsonServers"} {
				if v, ok := before["projects/"+dir+"/"+k]; ok {
					pr[k] = v
				} else {
					delete(pr, k)
				}
			}
		}
		b, _ := json.Marshal(projects)
		doc["projects"] = b
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".sdbx-tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
