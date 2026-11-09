// Package initwizard implementiert sdbx init (Spec 3.4).
package initwizard

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"sdbx/internal/config"
	"sdbx/internal/integrations/clausona"
	"sdbx/internal/netmatch"
	"sdbx/internal/version"
)

// Answers sind alle Angaben für die erzeugte Datei.
type Answers struct {
	Project          string // absoluter Workspace-Pfad für project: (Override unter ~/.config/sdbx/projects/)
	Workspace        string // relativ zum Projekt, "" = Projektwurzel
	Presets          []string
	ClausonaMode     string // off | ro | rw | "" (nicht installiert)
	ClausonaProfiles config.Profiles
	Agents           []string // claude, codex (ohne clausona)
	NetMode          string   // proxy | none | host
	Domains          []string
	Write            []string
	Deny             []string
	Sockets          []string
}

// Detection sind die Vorschläge aus der Erkennung.
type Detection struct {
	Presets      []string
	Clausona     bool
	ClausonaKeys []string // Profilschlüssel aus der Registry
	Agents       []string
	EnvFiles     []string
	Hints        []string
	GitRoot      string
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

// Detect sammelt Vorschläge für den Workspace (Spec 3.4, Erkennung).
func Detect(ws, home, platform string) Detection {
	var d Detection
	has := func(names ...string) bool {
		for _, n := range names {
			if m, _ := filepath.Glob(filepath.Join(ws, n)); len(m) > 0 {
				return true
			}
		}
		return false
	}
	if has("package.json", "pnpm-lock.yaml", "yarn.lock") {
		d.Presets = append(d.Presets, "node")
	}
	if has("go.mod") {
		d.Presets = append(d.Presets, "go")
	}
	if has("Cargo.toml") {
		d.Presets = append(d.Presets, "rust")
	}
	if has("pyproject.toml", "requirements*.txt", "uv.lock") {
		d.Presets = append(d.Presets, "python")
	}
	if gitRemoteHosted(ws) {
		d.Presets = append(d.Presets, "git-https")
	}
	// Integration nur mit lesbarer Registry vorschlagen (Spec 3.4), sonst wie ohne clausona
	if clausona.Detect(home) {
		if r, err := clausona.LoadRegistry(home); err == nil {
			d.Clausona = true
			for k := range r.Profiles {
				d.ClausonaKeys = append(d.ClausonaKeys, k)
			}
			sort.Strings(d.ClausonaKeys)
		} else {
			d.Hints = append(d.Hints, "clausona ist installiert, aber nicht nutzbar – keine Integration vorgeschlagen: "+err.Error())
		}
	}
	if !d.Clausona {
		for _, a := range []string{"claude", "codex"} {
			if _, err := exec.LookPath(a); err == nil {
				d.Agents = append(d.Agents, a)
			}
		}
	}
	deadline := time.Now().Add(300 * time.Millisecond)
	filepath.WalkDir(ws, func(p string, e os.DirEntry, err error) error {
		if err != nil || time.Now().After(deadline) {
			return filepath.SkipDir
		}
		if e.IsDir() && (e.Name() == "node_modules" || e.Name() == ".git" || e.Name() == "vendor") {
			return filepath.SkipDir
		}
		if !e.IsDir() && (e.Name() == ".env" || strings.HasPrefix(e.Name(), ".env.") && !strings.HasSuffix(e.Name(), ".example")) {
			rel, _ := filepath.Rel(ws, p)
			d.EnvFiles = append(d.EnvFiles, rel)
		}
		return nil
	})
	if platform == "linux" {
		if _, err := exec.LookPath("bwrap"); err != nil {
			d.Hints = append(d.Hints, "bwrap fehlt – vor dem ersten Lauf installieren (sdbx doctor)")
		}
	}
	return d
}

func gitRemoteHosted(ws string) bool {
	f, err := os.Open(filepath.Join(ws, ".git", "config"))
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if strings.Contains(l, "url") && (strings.Contains(l, "github.com") || strings.Contains(l, "gitlab.com") || strings.Contains(l, "bitbucket.org")) {
			return true
		}
	}
	return false
}

// Defaults leitet aus der Erkennung die Vorauswahl ab.
func (d Detection) Defaults() Answers {
	a := Answers{Presets: d.Presets, NetMode: "proxy", Agents: d.Agents}
	if d.Clausona {
		a.ClausonaMode = "ro"
		a.ClausonaProfiles = config.Profiles{Kind: "active"}
	}
	if len(d.EnvFiles) > 0 {
		a.Deny = []string{"**/.env"}
	}
	return a
}

// ValidateDomain prüft ein Domain-Muster.
func ValidateDomain(s string) error {
	_, err := netmatch.Parse(s)
	return err
}

func quote(s string) string {
	if s == "" || strings.ContainsAny(s, ":#*[]{}&!|>'\"%@`,") || strings.HasPrefix(s, "-") || strings.HasPrefix(s, "?") {
		return fmt.Sprintf("%q", s)
	}
	return s
}

func list(b *strings.Builder, indent, key string, vals []string) {
	if len(vals) == 0 {
		return
	}
	v := append([]string(nil), vals...)
	sort.Strings(v)
	fmt.Fprintf(b, "%s%s:\n", indent, key)
	for _, x := range v {
		fmt.Fprintf(b, "%s  - %s\n", indent, quote(x))
	}
}

// Generate erzeugt die kommentierte YAML (nur Abweichungen vom Default, feste Reihenfolge).
func Generate(a Answers, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# sdbx-Konfiguration – erzeugt von sdbx %s am %s\n", version.Version, now.Format("2006-01-02"))
	b.WriteString("# Prüfen: sdbx check · Regel erklären: sdbx explain <pfad|host>\n")
	b.WriteString("version: 1\n")
	if a.Project != "" {
		b.WriteString("\n# Workspace, für den diese Ausnahme gilt (liegt unter ~/.config/sdbx/projects/)\n")
		fmt.Fprintf(&b, "project: %s\n", quote(a.Project))
	}
	if len(a.Presets) > 0 {
		b.WriteString("\n# Presets für die erkannten Werkzeuge\n")
		list(&b, "", "include", a.Presets)
	}
	if a.Workspace != "" && a.Workspace != "." {
		fmt.Fprintf(&b, "\nworkspace: %s\n", quote(a.Workspace))
	}
	write := append([]string(nil), a.Write...)
	var agentDomains []string
	var passthrough, mach []string
	for _, ag := range a.Agents {
		switch ag {
		case "claude":
			write = append(write, "~/.claude", "~/.claude.json")
			agentDomains = append(agentDomains, "api.anthropic.com", "platform.claude.com")
			passthrough = append(passthrough, "CLAUDE_CONFIG_DIR")
		case "codex":
			write = append(write, "~/.codex")
			agentDomains = append(agentDomains, "chatgpt.com", "auth.openai.com", "api.openai.com")
			passthrough = append(passthrough, "CODEX_HOME")
		}
		mach = []string{"default", "keychain"}
	}
	if len(write) > 0 || len(a.Deny) > 0 {
		b.WriteString("\n# Dateisystem: der Workspace ist immer beschreibbar, alles andere lesbar außer Secrets\n")
		b.WriteString("filesystem:\n")
		list(&b, "  ", "write", dedupe(write))
		list(&b, "  ", "deny", a.Deny)
	}
	domains := dedupe(append(append([]string(nil), a.Domains...), agentDomains...))
	if a.NetMode != "" && a.NetMode != "proxy" || len(domains) > 0 {
		b.WriteString("\n# Netzwerk: nur freigegebene Ziele über den sdbx-Proxy\n")
		if a.NetMode == "none" || a.NetMode == "host" {
			fmt.Fprintf(&b, "network: %s\n", a.NetMode)
			if a.NetMode == "host" {
				b.WriteString("# ACHTUNG: host hebt alle Netzwerkregeln auf\n")
			}
		} else {
			b.WriteString("network:\n")
			list(&b, "  ", "allow", domains)
		}
	}
	if len(a.Sockets) > 0 {
		b.WriteString("\n# Unix-Sockets außerhalb des Workspaces, die erreichbar sein sollen\n")
		b.WriteString("sockets:\n")
		list(&b, "  ", "allow", a.Sockets)
	}
	if len(passthrough) > 0 {
		b.WriteString("\nenv:\n")
		list(&b, "  ", "passthrough", passthrough)
	}
	if len(mach) > 0 {
		b.WriteString("\n# macOS: Schlüsselbund für die Anmeldung der Agenten\n")
		b.WriteString("macos:\n")
		list(&b, "  ", "mach_services", mach)
	}
	if a.ClausonaMode != "" && a.ClausonaMode != "off" {
		b.WriteString("\n# clausona: ro schützt Einstellungen, Hooks und Plugins aller Accounts\n")
		b.WriteString("integrations:\n  clausona:\n")
		fmt.Fprintf(&b, "    mode: %s\n", a.ClausonaMode)
		switch a.ClausonaProfiles.Kind {
		case "all":
			b.WriteString("    profiles: all\n")
		case "list":
			list(&b, "    ", "profiles", a.ClausonaProfiles.List)
		}
	}
	return b.String()
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// FromFile liest eine vorhandene Datei als Vorauswahl (für "Ergänzen").
func FromFile(path string) (Answers, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Answers{}, err
	}
	f, err := config.Parse(data, path, filepath.Dir(path))
	if err != nil {
		return Answers{}, err
	}
	a := Answers{NetMode: "proxy"}
	for _, it := range f.Include {
		if !strings.ContainsAny(it.Value, "/.~") {
			a.Presets = append(a.Presets, it.Value)
		}
	}
	if f.Project != nil {
		a.Project = *f.Project
	}
	if f.Workspace != nil {
		a.Workspace = *f.Workspace
	}
	if f.Filesystem != nil {
		a.Write, a.Deny = f.Filesystem.Write.Values(), f.Filesystem.Deny.Values()
	}
	if f.Network != nil {
		if f.Network.Mode != nil {
			a.NetMode = *f.Network.Mode
		}
		a.Domains = f.Network.Allow.Values()
	}
	if f.Sockets != nil {
		a.Sockets = f.Sockets.Allow.Values()
	}
	if f.Integrations != nil && f.Integrations.Clausona != nil {
		c := f.Integrations.Clausona
		if c.Mode != nil {
			a.ClausonaMode = *c.Mode
		}
		a.ClausonaProfiles = config.Profiles{Kind: "active"}
		if c.Profiles != nil {
			a.ClausonaProfiles = *c.Profiles
		}
	}
	return a, nil
}

// Diff erzeugt einen einfachen zeilenbasierten Diff (LCS).
func Diff(oldText, newText string) string {
	a, b := strings.Split(oldText, "\n"), strings.Split(newText, "\n")
	n, m := len(a), len(b)
	dp := make([][]int, n+1)
	for i := range dp {
		dp[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				dp[i][j] = dp[i+1][j+1] + 1
			} else if dp[i+1][j] >= dp[i][j+1] {
				dp[i][j] = dp[i+1][j]
			} else {
				dp[i][j] = dp[i][j+1]
			}
		}
	}
	var out strings.Builder
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			out.WriteString("  " + a[i] + "\n")
			i, j = i+1, j+1
		case dp[i+1][j] >= dp[i][j+1]:
			out.WriteString("- " + a[i] + "\n")
			i++
		default:
			out.WriteString("+ " + b[j] + "\n")
			j++
		}
	}
	for ; i < n; i++ {
		out.WriteString("- " + a[i] + "\n")
	}
	for ; j < m; j++ {
		out.WriteString("+ " + b[j] + "\n")
	}
	return out.String()
}
