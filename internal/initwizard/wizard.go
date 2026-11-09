package initwizard

import (
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"sdbx/internal/config"
	"sdbx/internal/pathutil"
	"sdbx/internal/policy"
	"sdbx/internal/presets"
	"sdbx/internal/tui"
)

// Env enthält die Host-Werte für init.
type Env struct {
	Cwd              string
	Home             string
	Platform         string
	Environ          []string
	ForceInteractive bool // Tests: TUI ohne Terminal
	Now              func() time.Time
}

func (e Env) get(k string) string {
	for _, kv := range e.Environ {
		if key, v, _ := strings.Cut(kv, "="); key == k {
			return v
		}
	}
	return ""
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

type opts struct {
	presets, integration, write, domains, sockets, deny multi
	agents, network, workspace, output                  string
	global, yes, force, accessible                      bool
}

const exitConfig = 125

func gitRoot(dir string) string {
	d := dir
	for {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		if p := filepath.Dir(d); p != d {
			d = p
		} else {
			return ""
		}
	}
}

// Main führt sdbx init aus.
func Main(args []string, env Env, in io.Reader, out, errw io.Writer) int {
	if env.Now == nil {
		env.Now = time.Now
	}
	var o opts
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(errw)
	fs.Var(&o.presets, "preset", "Preset einbinden (mehrfach; none = keine)")
	fs.Var(&o.integration, "integration", "z. B. clausona=ro, clausona.profiles=all")
	fs.StringVar(&o.agents, "agents", "", "ohne clausona: claude,codex oder none")
	fs.Var(&o.write, "allow-write", "zusätzlicher Schreibpfad")
	fs.Var(&o.domains, "allow-domain", "Domain freigeben")
	fs.Var(&o.sockets, "allow-socket", "Unix-Socket freigeben")
	fs.Var(&o.deny, "deny", "Pfad sperren")
	fs.StringVar(&o.network, "network", "", "proxy | none | host")
	fs.StringVar(&o.workspace, "workspace", "", "Zielverzeichnis")
	fs.StringVar(&o.output, "output", "", "Zieldatei (Default: ~/.config/sdbx/projects/<name>.yaml)")
	fs.BoolVar(&o.global, "global", false, "globale Konfiguration anlegen (~/.config/sdbx/config.yaml)")
	fs.BoolVar(&o.yes, "yes", false, "Vorschläge annehmen, nichts fragen")
	fs.BoolVar(&o.force, "force", false, "bestehende Datei ohne Rückfrage ersetzen")
	fs.BoolVar(&o.accessible, "accessible", false, "barrierearmer Modus")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return exitConfig
	}
	if env.get("SDBX") == "1" {
		fmt.Fprintln(errw, "sdbx: init läuft nicht innerhalb einer Sandbox – eine Sandbox soll ihre eigenen Regeln nicht erzeugen")
		return exitConfig
	}
	if env.get("SDBX_ACCESSIBLE") == "1" {
		o.accessible = true
	}
	// Ziel
	dir := env.Cwd
	if o.workspace != "" {
		dir = pathutil.Absolute(config.ExpandHomeOnly(o.workspace), env.Cwd)
	} else if g := gitRoot(env.Cwd); g != "" {
		dir = g
	}
	det := Detect(dir, env.Home, env.Platform)
	a := det.Defaults()
	given := map[string]bool{}
	if err := applyFlags(&o, &a, given, det); err != nil {
		fmt.Fprintf(errw, "sdbx: %v\n", err)
		return exitConfig
	}
	target := ""
	switch {
	case o.global:
		target = config.GlobalConfigPath(env.Home)
	case o.output != "":
		target = pathutil.Absolute(config.ExpandHomeOnly(o.output), dir)
		a.Project = dir
		if pathutil.IsUnder(target, dir) {
			fmt.Fprintf(errw, "sdbx: Hinweis: %s liegt im Workspace – sdbx lädt sie nur mit --config\n", target)
		}
	default:
		a.Project = dir
		target = projectOverridePath(env.Home, dir)
	}

	interactive := env.ForceInteractive
	if !interactive {
		if f, ok := in.(*os.File); ok && tui.IsTerminal(int(f.Fd())) {
			if g, ok := out.(*os.File); ok && tui.IsTerminal(int(g.Fd())) {
				interactive = true
			}
		}
	}
	var old []byte
	merge := false
	if b, err := os.ReadFile(target); err == nil {
		old = b
		switch {
		case o.force:
		case !interactive || o.yes:
			fmt.Fprintf(errw, "sdbx: %s existiert bereits (--force ersetzt sie, eine Sicherung bleibt als .bak)\n", target)
			return exitConfig
		}
	}
	missing := missingFlags(det, given)
	if !interactive && !o.yes && len(missing) > 0 {
		fmt.Fprintf(errw, "sdbx: kein Terminal – fehlende Angaben per Flag übergeben oder --yes für die Vorschläge:\n")
		for _, m := range missing {
			fmt.Fprintf(errw, "  %s\n", m)
		}
		return exitConfig
	}
	ui := tui.New(in, out, o.accessible)
	if interactive && !o.yes {
		if !o.accessible {
			if f, ok := in.(*os.File); ok {
				if st, err := tui.MakeRaw(int(f.Fd())); err == nil {
					defer tui.Restore(int(f.Fd()), st)
				}
			}
		}
		if old != nil && !o.force {
			i, err := ui.Select(target+" existiert bereits", "", []tui.Option{
				{Label: "Ersetzen", Desc: "Sicherung als .bak"}, {Label: "Ergänzen", Desc: "vorhandene Werte als Vorauswahl, am Ende ein Diff"}, {Label: "Abbrechen"},
			}, 1)
			if err != nil || i == 2 {
				ui.Note("Abgebrochen – nichts geschrieben.")
				return exitConfig
			}
			if i == 1 {
				prev, err := FromFile(target)
				if err != nil {
					ui.Note(fmt.Sprintf("Bestehende Datei nicht lesbar (%v) – starte mit den Vorschlägen.", err))
				} else {
					a = prev
					applyFlags(&o, &a, given, det)
					merge = true
				}
			}
		}
		for _, h := range det.Hints {
			ui.Note("Hinweis: " + h)
		}
		res, saved, err := runSteps(ui, &a, det, given, dir, target, old, merge, env)
		if err != nil || !saved {
			ui.Note("Abgebrochen – nichts geschrieben.")
			return exitConfig
		}
		if err := writeFile(target, res, old != nil); err != nil {
			fmt.Fprintf(errw, "sdbx: %v\n", err)
			return exitConfig
		}
		ui.Note(fmt.Sprintf("Geschrieben: %s", target))
		nextSteps(ui, a)
		if i, err := ui.Select("Probelauf im Lernmodus starten?", "Zeigt, welche Domains und Pfade der Befehl zusätzlich braucht.",
			[]tui.Option{{Label: "Nein, fertig"}, {Label: "Ja"}}, 0); err == nil && i == 1 {
			if cmdline, err := ui.Input("Befehl", "z. B. npm test", "", nil); err == nil && cmdline != "" {
				if f, ok := in.(*os.File); ok {
					tui.Restore(int(f.Fd()), nil)
				}
				exe, _ := os.Executable()
				c := exec.Command(exe, append([]string{"learn", "--config", target, "--"}, strings.Fields(cmdline)...)...)
				c.Stdin, c.Stdout, c.Stderr, c.Dir = os.Stdin, os.Stdout, os.Stderr, dir
				c.Run()
			}
		}
		return 0
	}
	text := Generate(a, env.Now())
	if err := writeFile(target, text, old != nil); err != nil {
		fmt.Fprintf(errw, "sdbx: %v\n", err)
		return exitConfig
	}
	fmt.Fprintf(out, "Geschrieben: %s\n", target)
	nextSteps(tui.New(strings.NewReader(""), out, true), a)
	return 0
}

func applyFlags(o *opts, a *Answers, given map[string]bool, det Detection) error {
	if len(o.presets) > 0 {
		given["presets"] = true
		a.Presets = nil
		for _, p := range o.presets {
			for _, x := range strings.Split(p, ",") {
				if x = strings.TrimSpace(x); x == "" || x == "none" {
					continue
				}
				if _, ok := presets.Get(x); !ok {
					return fmt.Errorf("--preset: unbekanntes Preset %q (verfügbar: %s)", x, strings.Join(presets.Names(), ", "))
				}
				a.Presets = append(a.Presets, x)
			}
		}
	}
	for _, spec := range o.integration {
		k, v, ok := strings.Cut(spec, "=")
		if !ok || !strings.HasPrefix(k, "clausona") {
			return fmt.Errorf("--integration %q: erwartet clausona=ro|rw|off oder clausona.profiles=…", spec)
		}
		switch k {
		case "clausona", "clausona.mode":
			if v != "ro" && v != "rw" && v != "off" {
				return fmt.Errorf("--integration clausona=%s: erlaubt sind ro, rw, off", v)
			}
			a.ClausonaMode = v
			given["clausona"] = true
		case "clausona.profiles":
			a.ClausonaProfiles = config.ParseProfiles(v)
		default:
			return fmt.Errorf("--integration: unbekannte Option %s", k)
		}
	}
	if o.agents != "" {
		given["agents"] = true
		a.Agents = nil
		for _, x := range strings.Split(o.agents, ",") {
			switch x = strings.TrimSpace(x); x {
			case "claude", "codex":
				a.Agents = append(a.Agents, x)
			case "none", "":
			default:
				return fmt.Errorf("--agents: %q unbekannt (claude, codex, none)", x)
			}
		}
	}
	if o.network != "" {
		if o.network != "proxy" && o.network != "none" && o.network != "host" {
			return fmt.Errorf("--network: %q ungültig (proxy, none, host)", o.network)
		}
		a.NetMode = o.network
		given["network"] = true
	}
	for _, d := range o.domains {
		if err := ValidateDomain(d); err != nil {
			return fmt.Errorf("--allow-domain: %v", err)
		}
	}
	a.Domains = dedupe(append(a.Domains, o.domains...))
	a.Write = dedupe(append(a.Write, o.write...))
	a.Deny = dedupe(append(a.Deny, o.deny...))
	a.Sockets = dedupe(append(a.Sockets, o.sockets...))
	if o.workspace != "" {
		given["workspace"] = true
	}
	if len(o.write)+len(o.deny)+len(o.sockets) > 0 {
		given["paths"] = true
	}
	return nil
}

func missingFlags(det Detection, given map[string]bool) []string {
	var m []string
	if !given["presets"] {
		m = append(m, "--preset <name> (mehrfach) oder --preset none")
	}
	if det.Clausona && !given["clausona"] {
		m = append(m, "--integration clausona=ro|rw|off")
	}
	if !det.Clausona && len(det.Agents) > 0 && !given["agents"] {
		m = append(m, "--agents claude,codex|none")
	}
	if !given["network"] {
		m = append(m, "--network proxy|none|host")
	}
	return m
}

func writeFile(target, text string, backup bool) error {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if backup {
		if old, err := os.ReadFile(target); err == nil {
			if err := os.WriteFile(target+".bak", old, 0o644); err != nil {
				return fmt.Errorf("Sicherung: %w", err)
			}
		}
	}
	tmp := target + ".sdbx-tmp"
	if err := os.WriteFile(tmp, []byte(text), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}

func nextSteps(ui *tui.UI, a Answers) {
	cmd := "sdbx run -- <befehl>"
	if a.ClausonaMode == "ro" || a.ClausonaMode == "rw" {
		cmd = "sdbx run -- clausona run claude:<profil>"
	} else if len(a.Agents) > 0 {
		cmd = "sdbx run -- " + a.Agents[0]
	}
	ui.Note("Nächste Schritte:\n  sdbx check\n  " + cmd)
}

// projectOverridePath wählt ~/.config/sdbx/projects/<slug>.yaml; bei Namenskollision mit kurzem Hash.
func projectOverridePath(home, workspace string) string {
	ws := filepath.Clean(workspace)
	if r, err := filepath.EvalSymlinks(ws); err == nil {
		ws = r
	}
	pdir := config.ProjectsDir(home)
	slug := config.ProjectSlug(ws)
	cand := filepath.Join(pdir, slug+".yaml")
	if _, err := os.Stat(cand); os.IsNotExist(err) {
		return cand
	}
	if match, err := config.ProjectOf(cand, home); err == nil && match == ws {
		return cand
	}
	sum := sha256.Sum256([]byte(ws))
	return filepath.Join(pdir, fmt.Sprintf("%s-%x.yaml", slug, sum[:4]))
}

// CheckText prüft erzeugten Text wie sdbx check (ohne Integrationen auszuführen).
func CheckText(text, dir, home, platform string) []string {
	f, err := config.Parse([]byte(text), "<entwurf>", dir)
	if err != nil {
		return []string{"Fehler: " + err.Error()}
	}
	var frags []config.Fragment
	for _, inc := range f.Include {
		if pf, err := config.LoadPreset(inc.Value); err == nil {
			frags = append(frags, pf)
		}
	}
	frags = append(frags, config.Fragment{File: f, Source: "<entwurf>", Dir: dir})
	c, err := config.Build(nil, nil, frags, nil, nil)
	if err != nil {
		return []string{"Fehler: " + err.Error()}
	}
	p, err := policy.Compile(c, policy.Context{Platform: platform, Home: home, DefaultWorkspace: dir, UserTmp: os.TempDir(),
		SdbxTmp: filepath.Join(os.TempDir(), "sdbx-init"), LookupEnv: os.LookupEnv})
	if err != nil {
		return []string{"Fehler: " + err.Error()}
	}
	var out []string
	for _, i := range p.Issues {
		prefix := "Warnung: "
		if i.Error {
			prefix = "Fehler: "
		}
		out = append(out, prefix+i.Msg)
	}
	return out
}

// runSteps führt die TUI-Schritte aus (Spec 3.4) und liefert den Dateitext.
func runSteps(ui *tui.UI, a *Answers, det Detection, given map[string]bool, dir, target string, old []byte, merge bool, env Env) (string, bool, error) {
	steps := []func() error{
		func() error { // 1 Workspace
			if given["workspace"] {
				return nil
			}
			help := "Verzeichnis, das beschreibbar ist (relativ zur Datei)."
			if gitRoot(dir) != dir {
				help += "\nHinweis: Das ist nicht die Wurzel eines Git-Repositories."
			}
			def := a.Workspace
			if def == "" {
				def = "."
			}
			v, err := ui.Input("Workspace", help, def, func(s string) error {
				if st, err := os.Stat(pathutil.Absolute(config.ExpandHomeOnly(s), dir)); err != nil || !st.IsDir() {
					return fmt.Errorf("%s ist kein Verzeichnis", s)
				}
				return nil
			})
			if err == nil {
				a.Workspace = v
			}
			return err
		},
		func() error { // 2 Werkzeuge
			if given["presets"] {
				return nil
			}
			names := presets.Names()
			var opts []tui.Option
			var sel []bool
			for _, n := range names {
				opts = append(opts, tui.Option{Label: n, Desc: presets.Description(n)})
				sel = append(sel, contains(a.Presets, n))
			}
			res, err := ui.MultiSelect("Werkzeuge", "Vorausgewählt nach Erkennung im Workspace.", opts, sel)
			if err != nil {
				return err
			}
			a.Presets = nil
			for i, s := range res {
				if s {
					a.Presets = append(a.Presets, names[i])
				}
			}
			return nil
		},
		func() error { // 3 Agenten
			if det.Clausona {
				if given["clausona"] {
					return nil
				}
				modes := []string{"ro", "rw", "off"}
				def := 0
				for i, m := range modes {
					if m == a.ClausonaMode {
						def = i
					}
				}
				i, err := ui.Select("clausona-Integration", "Erkannt: clausona ist installiert.", []tui.Option{
					{Label: "ro", Desc: "empfohlen: Sitzungen funktionieren, Einstellungen/Hooks/Plugins sind geschützt"},
					{Label: "rw", Desc: "alles beschreibbar, inklusive Plugin-Installation und Self-Update"},
					{Label: "off", Desc: "keine Integration"},
				}, def)
				if err != nil {
					return err
				}
				a.ClausonaMode = modes[i]
				if a.ClausonaMode == "rw" {
					ui.Note("Achtung: Mit rw kann ein Agent Hooks und Einstellungen aller Accounts ändern, die später außerhalb der Sandbox wirken.")
				}
				if a.ClausonaMode == "off" {
					return nil
				}
				j, err := ui.Select("Profile", "Welche Accounts darf ein Lauf sehen?", []tui.Option{
					{Label: "active", Desc: "nur das gestartete Profil (empfohlen)"}, {Label: "all", Desc: "alle Profile"}, {Label: "Auswahl", Desc: "bestimmte Profile"},
				}, 0)
				if err != nil {
					return err
				}
				switch j {
				case 0:
					a.ClausonaProfiles = config.Profiles{Kind: "active"}
				case 1:
					a.ClausonaProfiles = config.Profiles{Kind: "all"}
				case 2:
					var opts []tui.Option
					for _, k := range det.ClausonaKeys {
						opts = append(opts, tui.Option{Label: k})
					}
					sel, err := ui.MultiSelect("Profile auswählen", "", opts, nil)
					if err != nil {
						return err
					}
					a.ClausonaProfiles = config.Profiles{Kind: "list"}
					for i, s := range sel {
						if s {
							a.ClausonaProfiles.List = append(a.ClausonaProfiles.List, det.ClausonaKeys[i])
						}
					}
				}
				return nil
			}
			if given["agents"] {
				return nil
			}
			opts := []tui.Option{{Label: "claude", Desc: "Claude Code"}, {Label: "codex", Desc: "Codex CLI"}}
			sel, err := ui.MultiSelect("Agenten", "Basisfreigaben für Agenten-CLIs (Konfigurationsverzeichnis, Anmeldung, API).", opts,
				[]bool{contains(a.Agents, "claude"), contains(a.Agents, "codex")})
			if err != nil {
				return err
			}
			a.Agents = nil
			for i, s := range sel {
				if s {
					a.Agents = append(a.Agents, opts[i].Label)
				}
			}
			return nil
		},
		func() error { // 4 Netzwerk
			if !given["network"] {
				modes := []string{"proxy", "none", "host"}
				def := 0
				for i, m := range modes {
					if m == a.NetMode {
						def = i
					}
				}
				i, err := ui.Select("Netzwerk", "", []tui.Option{
					{Label: "proxy", Desc: "empfohlen: nur freigegebene Domains"}, {Label: "none", Desc: "kein Netzwerk"}, {Label: "host", Desc: "uneingeschränkt"},
				}, def)
				if err != nil {
					return err
				}
				a.NetMode = modes[i]
				if a.NetMode == "host" {
					ui.Note("Achtung: Mit host kann der Prozess beliebige Ziele erreichen und Daten abfließen lassen.")
				}
			}
			if a.NetMode != "proxy" {
				return nil
			}
			help := "Bereits freigegeben: " + strings.Join(inherited(*a), ", ")
			if len(inherited(*a)) == 0 {
				help = "Noch keine Domains freigegeben."
			}
			d, err := ui.ListInput("Weitere Domains", help+"\nMuster: example.com, *.example.com, **.example.com, host:443", a.Domains, ValidateDomain)
			if err == nil {
				a.Domains = d
			}
			return err
		},
		func() error { // 5 Zusätzliche Pfade
			if given["paths"] {
				return nil
			}
			help := ""
			if len(det.EnvFiles) > 0 {
				help = fmt.Sprintf("Gefunden: %s – vorgeschlagen ist, **/.env zu sperren.", strings.Join(det.EnvFiles, ", "))
			}
			i, err := ui.Select("Zusätzliche Pfade", help, []tui.Option{{Label: "Übernehmen", Desc: listOrNone(a.Write, a.Deny, a.Sockets)}, {Label: "Bearbeiten"}}, 0)
			if err != nil || i == 0 {
				return err
			}
			check := func(s string) error {
				if strings.ContainsAny(s, "*?[") {
					return nil
				}
				if _, err := os.Stat(pathutil.Absolute(config.ExpandHomeOnly(s), dir)); err != nil {
					return fmt.Errorf("%s existiert nicht", s)
				}
				return nil
			}
			if a.Write, err = ui.ListInput("Schreibpfade", "", a.Write, check); err != nil {
				return err
			}
			if a.Deny, err = ui.ListInput("Gesperrte Pfade", "", a.Deny, nil); err != nil {
				return err
			}
			a.Sockets, err = ui.ListInput("Freigegebene Unix-Sockets", "", a.Sockets, check)
			return err
		},
	}
	var text string
	for i := 0; i <= len(steps); {
		if i == len(steps) { // 6 Zusammenfassung
			text = Generate(*a, env.Now())
			shown := text
			title := "Vorschau " + target
			if merge && old != nil {
				shown, title = Diff(string(old), text), "Änderungen an "+target
			}
			for _, c := range CheckText(text, dir, env.Home, env.Platform) {
				shown += "\n# sdbx check: " + c
			}
			j, err := ui.Preview(title, shown, []tui.Option{{Label: "Speichern"}, {Label: "Zurück"}, {Label: "Abbrechen"}}, 0)
			if errors.Is(err, tui.ErrBack) || err == nil && j == 1 {
				i--
				continue
			}
			if err != nil || j == 2 {
				return "", false, tui.ErrCancel
			}
			return text, true, nil
		}
		err := steps[i]()
		switch {
		case errors.Is(err, tui.ErrBack):
			if i > 0 {
				i--
			}
		case err != nil:
			return "", false, err
		default:
			i++
		}
	}
	return text, true, nil
}

func inherited(a Answers) []string {
	var out []string
	for _, p := range a.Presets {
		if pf, err := config.LoadPreset(p); err == nil && pf.File.Network != nil {
			out = append(out, pf.File.Network.Allow.Values()...)
		}
	}
	if a.ClausonaMode == "ro" || a.ClausonaMode == "rw" {
		out = append(out, "api.anthropic.com (clausona)")
	}
	return out
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func listOrNone(lists ...[]string) string {
	var all []string
	for _, l := range lists {
		all = append(all, l...)
	}
	if len(all) == 0 {
		return "keine"
	}
	return strings.Join(all, ", ")
}
