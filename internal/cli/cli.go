// Package cli implementiert die Kommandozeile (Spec 3).
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"sdbx/internal/audit"
	"sdbx/internal/backend"
	"sdbx/internal/backend/darwin"
	"sdbx/internal/backend/linux"
	"sdbx/internal/doctor"
	"sdbx/internal/initwizard"
	"sdbx/internal/netmatch"
	"sdbx/internal/policy"
	"sdbx/internal/presets"
	"sdbx/internal/supervisor"
	"sdbx/internal/version"
)

// IO bündelt die Ein- und Ausgaben.
type IO struct {
	In       io.Reader
	Out, Err io.Writer
}

const usage = `sdbx – Sandbox auf Betriebssystemebene für Agenten und Werkzeuge

Verwendung:
  sdbx run [flags] -- <befehl> [args…]   Befehl in der Sandbox ausführen
  sdbx <befehl> [args…]                  Kurzform für sdbx run -- <befehl> [args…] (ohne sdbx-Flags)
  sdbx shell [flags]                     $SHELL in der Sandbox starten
  sdbx check [flags]                     Konfiguration prüfen, Warnungen und Plattformmatrix zeigen
  sdbx policy [--format yaml|json|seatbelt|bwrap]
                                         aufgelöste Policy bzw. Backend-Konfiguration ausgeben
  sdbx explain <pfad|host[:port]>        zeigen, welche Regel gilt und woher sie stammt
  sdbx learn [flags] -- <befehl>         Lernmodus: Verstöße sammeln, Konfiguration vorschlagen
  sdbx init [flags]                      Projekt-Override unter ~/.config/sdbx/projects/ anlegen
  sdbx doctor                            Plattformvoraussetzungen prüfen
  sdbx presets                           eingebaute Presets und Integrationen auflisten
  sdbx version                           Version und Plattformfähigkeiten

Globale Flags (run, shell, check, policy, explain, learn):
  -c, --config <datei>        Projekt-Override (sonst ~/.config/sdbx/projects/)
      --no-global             globale Konfiguration ignorieren
  -w, --workspace <dir>       Workspace überschreiben
      --allow-write <pfad>    zusätzlicher Schreibpfad (mehrfach)
      --allow-read <pfad>     zusätzlicher Lesepfad (mehrfach)
      --deny <pfad>           zusätzlich sperren (mehrfach)
      --allow-domain <muster> Domain freigeben (mehrfach)
      --no-network            kein Netzwerk
      --integration n=w       z. B. clausona=ro, clausona.profiles=all
      --timeout <dauer>       Zeitlimit (z. B. 30m)
      --degraded              nicht durchsetzbare Regeln nur warnen
      --log <datei>           Audit-Log schreiben
      --log-format text|json
  -q, --quiet / -v, --verbose
      --dry-run               nur die Startbeschreibung ausgeben
      --keep-tmp              privates Temp-Verzeichnis behalten
      --no-rewrite            Kommandozeile nicht durch Integrationen umschreiben

Exit-Codes: Zielbefehl unverändert; 124 Timeout, 125 Konfigurationsfehler,
126 Sandbox nicht einrichtbar, 127 Befehl nicht gefunden, 128+n Signal n.
`

func flags(name string, c *Common, w io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(w)
	fs.Usage = func() { fmt.Fprint(w, usage) }
	fs.StringVar(&c.Config, "config", "", "")
	fs.StringVar(&c.Config, "c", "", "")
	fs.BoolVar(&c.NoGlobal, "no-global", false, "")
	fs.StringVar(&c.Workspace, "workspace", "", "")
	fs.StringVar(&c.Workspace, "w", "", "")
	fs.Var(&c.AllowWrite, "allow-write", "")
	fs.Var(&c.AllowRead, "allow-read", "")
	fs.Var(&c.Deny, "deny", "")
	fs.Var(&c.AllowDomain, "allow-domain", "")
	fs.BoolVar(&c.NoNetwork, "no-network", false, "")
	fs.Var(&c.Integration, "integration", "")
	fs.StringVar(&c.Timeout, "timeout", "", "")
	fs.BoolVar(&c.Degraded, "degraded", false, "")
	fs.StringVar(&c.Log, "log", "", "")
	fs.StringVar(&c.LogFormat, "log-format", "", "")
	fs.BoolVar(&c.Quiet, "quiet", false, "")
	fs.BoolVar(&c.Quiet, "q", false, "")
	fs.BoolVar(&c.Verbose, "verbose", false, "")
	fs.BoolVar(&c.Verbose, "v", false, "")
	fs.BoolVar(&c.DryRun, "dry-run", false, "")
	fs.BoolVar(&c.KeepTmp, "keep-tmp", false, "")
	fs.BoolVar(&c.NoRewrite, "no-rewrite", false, "")
	return fs
}

// Main führt sdbx aus und liefert den Exit-Code.
func Main(args []string, env Env, s IO) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(s.Out, usage)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "version", "--version":
		caps := DetectCaps(env)
		fmt.Fprintf(s.Out, "sdbx %s (Commit %s), %s\n", version.Version, version.Commit, env.Platform)
		for _, c := range capsLines(caps) {
			fmt.Fprintln(s.Out, "  "+c)
		}
		return 0
	case "presets":
		for _, n := range presets.Names() {
			fmt.Fprintf(s.Out, "%-10s %s\n", n, presets.Description(n))
		}
		fmt.Fprintln(s.Out, "\nIntegrationen:\n  clausona   Profilmanager für Claude Code und Codex (integrations.clausona: ro|rw)")
		return 0
	case "doctor":
		return doctor.Run(s.Out, doctor.Options{Platform: env.Platform, Home: env.Home, UID: env.UID})
	case "init":
		return initwizard.Main(rest, initwizard.Env{Cwd: env.Cwd, Home: env.Home, Platform: env.Platform, Environ: env.Environ}, s.In, s.Out, s.Err)
	case "run", "shell", "check", "policy", "explain", "learn":
	default:
		if strings.HasPrefix(cmd, "-") {
			fmt.Fprintf(s.Err, "sdbx: unbekannter Befehl %q (sdbx --help)\n", cmd)
			return supervisor.ExitConfig
		}
		// Kurzform: sdbx <programm> [args…] = sdbx run -- <programm> [args…]
		path, _ := env.lookup("PATH")
		if _, err := supervisor.LookPath(cmd, path, env.Cwd); err != nil {
			fmt.Fprintf(s.Err, "sdbx: unbekannter Befehl %q – weder sdbx-Befehl noch Programm im PATH (sdbx --help)\n", cmd)
			return supervisor.ExitNotFound
		}
		cmd, rest = "run", append([]string{"--"}, args...)
	}
	var c Common
	fs := flags(cmd, &c, s.Err)
	format := ""
	if cmd == "policy" {
		fs.StringVar(&format, "format", "yaml", "")
	}
	if err := fs.Parse(rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return supervisor.ExitConfig
	}
	positional := fs.Args()
	var argv []string
	switch cmd {
	case "run", "learn":
		argv = positional
		if len(argv) == 0 {
			fmt.Fprintf(s.Err, "sdbx: kein Befehl angegeben (sdbx %s -- <befehl>)\n", cmd)
			return supervisor.ExitConfig
		}
	case "shell":
		sh, _ := env.lookup("SHELL")
		if sh == "" {
			sh = "/bin/sh"
		}
		argv = []string{sh}
	}
	if v, _ := env.lookup("SDBX"); v == "1" && (cmd == "run" || cmd == "shell" || cmd == "learn") {
		fmt.Fprintln(s.Err, "sdbx: Hinweis: Aufruf innerhalb einer Sandbox – die Regeln der äußeren Sandbox gelten weiter")
	}
	caps := DetectCaps(env)
	b, err := Build(&c, env, argv, caps)
	if err != nil {
		fmt.Fprintf(s.Err, "sdbx: %v\n", err)
		return supervisor.ExitConfig
	}
	switch cmd {
	case "check":
		return cmdCheck(b, s)
	case "policy":
		return cmdPolicy(b, format, env, s)
	case "explain":
		if len(positional) != 1 {
			fmt.Fprintln(s.Err, "sdbx: explain erwartet genau einen Pfad oder host[:port]")
			return supervisor.ExitConfig
		}
		return cmdExplain(b, positional[0], s)
	}
	return cmdRun(b, &c, env, argv, cmd == "learn", s)
}

func capsLines(c policy.Caps) []string {
	switch c.Platform {
	case "linux":
		return []string{fmt.Sprintf("bwrap: %v", c.HaveBwrap), fmt.Sprintf("Landlock-ABI: %d", c.LandlockABI), fmt.Sprintf("cgroup v2 (systemd-run --user): %v", c.Cgroup)}
	case "darwin":
		return []string{fmt.Sprintf("sandbox-exec: %v", c.HaveSandboxExec)}
	}
	return nil
}

func printIssues(b *Built, s IO, quiet bool) bool {
	hasErr := false
	for _, i := range b.Issues {
		if i.Error {
			hasErr = true
			fmt.Fprintf(s.Err, "sdbx: Fehler: %s\n", i.Msg)
		} else if !quiet {
			fmt.Fprintf(s.Err, "sdbx: Warnung: %s\n", i.Msg)
		}
	}
	return hasErr
}

func cmdCheck(b *Built, s IO) int {
	fmt.Fprintln(s.Out, "Quellen (in Anwendungsreihenfolge):")
	for _, src := range b.Config.Sources {
		fmt.Fprintf(s.Out, "  %s\n", src)
	}
	fmt.Fprintf(s.Out, "Workspace: %s\n", b.Policy.Workspace)
	fmt.Fprintf(s.Out, "\nPlattformmatrix (%s):\n", b.Caps.Platform)
	for _, c := range policy.Matrix(b.Policy, b.Caps) {
		fmt.Fprintf(s.Out, "  %-32s %-18s %s\n", c.Name, c.Status, c.Detail)
	}
	if len(b.Issues) > 0 {
		fmt.Fprintln(s.Out)
	}
	if printIssues(b, IO{Err: s.Out}, false) {
		return supervisor.ExitConfig
	}
	fmt.Fprintln(s.Out, "\nKonfiguration ist gültig.")
	return 0
}

type ruleOut struct {
	Kind   string   `yaml:"kind" json:"kind"`
	Path   string   `yaml:"path,omitempty" json:"path,omitempty"`
	Glob   string   `yaml:"glob,omitempty" json:"glob,omitempty"`
	Except []string `yaml:"except,omitempty" json:"except,omitempty"`
	Note   string   `yaml:"note,omitempty" json:"note,omitempty"`
	Source string   `yaml:"source" json:"source"`
}

type policyOut struct {
	Workspace  string    `yaml:"workspace" json:"workspace"`
	Default    string    `yaml:"filesystem_default" json:"filesystem_default"`
	Rules      []ruleOut `yaml:"filesystem" json:"filesystem"`
	Network    any       `yaml:"network" json:"network"`
	Sockets    []string  `yaml:"sockets,omitempty" json:"sockets,omitempty"`
	SocketDeny []string  `yaml:"socket_deny,omitempty" json:"socket_deny,omitempty"`
	Env        any       `yaml:"env" json:"env"`
	Process    any       `yaml:"process" json:"process"`
	Limits     any       `yaml:"limits" json:"limits"`
	Mach       []string  `yaml:"mach_services,omitempty" json:"mach_services,omitempty"`
	Linux      any       `yaml:"linux" json:"linux"`
}

func patterns(ps []netmatch.Pattern) []string {
	var out []string
	for _, p := range ps {
		out = append(out, fmt.Sprintf("%s  [%s]", p.Raw, p.Source))
	}
	return out
}

func summarize(p *policy.Policy) policyOut {
	o := policyOut{Workspace: p.Workspace, Default: p.FSDefault, Mach: p.MachServices, SocketDeny: p.SocketDeny}
	for _, r := range p.Rules {
		o.Rules = append(o.Rules, ruleOut{Kind: r.Kind.String(), Path: r.Path, Glob: r.Glob, Except: r.Except, Note: r.Note, Source: r.Origin.String()})
	}
	o.Network = map[string]any{"mode": p.Net.Mode, "default_allow": p.Net.Matcher.DefaultAllow, "allow": patterns(p.Net.Matcher.Allow),
		"deny": patterns(p.Net.Matcher.Deny), "ports": p.Net.Matcher.Ports, "allow_private": p.Net.Matcher.AllowPrivate, "local": p.Net.Local, "ssh": p.Net.SSH}
	for _, s := range p.Sockets {
		o.Sockets = append(o.Sockets, s.Path+s.Glob)
	}
	o.Env = map[string]any{"mode": p.Env.Mode, "passthrough": p.Env.Passthrough, "deny": p.Env.Deny, "set": p.Env.Set}
	o.Process = map[string]any{"isolate_pids": p.IsolatePids, "allow_ptrace": p.AllowPtrace, "private_tmp": p.PrivateTmp}
	o.Limits = map[string]any{"timeout": p.Limits.Timeout.String(), "kill_grace": p.Limits.KillGrace.String(), "max_processes": p.Limits.MaxProcesses,
		"max_memory": p.Limits.MaxMemory, "max_file_size": p.Limits.MaxFileSize, "max_open_files": p.Limits.MaxOpenFiles, "cpu_time": p.Limits.CPUTime.String()}
	o.Linux = map[string]any{"backend": p.Linux.Backend, "landlock": p.Linux.Landlock, "seccomp": p.Linux.Seccomp, "devices": p.Linux.Devices}
	return o
}

func cmdPolicy(b *Built, format string, env Env, s IO) int {
	printIssues(b, s, true)
	p := b.Policy
	rt := &backend.Runtime{RunDir: p.SdbxTmp + "/.sdbx", SdbxTmp: p.SdbxTmp, SdbxExe: env.Exe, Cwd: env.Cwd, ProxyPort: 0, Argv: []string{"<befehl>"}}
	switch format {
	case "yaml":
		out, _ := yaml.Marshal(summarize(p))
		s.Out.Write(out)
	case "json":
		out, _ := json.MarshalIndent(summarize(p), "", "  ")
		fmt.Fprintln(s.Out, string(out))
	case "seatbelt":
		prof, err := darwin.Generate(p, rt)
		if err != nil {
			fmt.Fprintf(s.Err, "sdbx: %v\n", err)
			return supervisor.ExitConfig
		}
		fmt.Fprint(s.Out, prof.Text)
		for _, prm := range prof.Params {
			fmt.Fprintf(s.Out, ";; -D %s=%s\n", prm.Key, prm.Value)
		}
	case "bwrap":
		l := linux.NewLayout(p, rt)
		args, _ := linux.BuildArgs(p, rt, linux.HostFacts(p, rt), l)
		fmt.Fprintln(s.Out, "bwrap "+strings.Join(args, " "))
		spec, _ := json.MarshalIndent(linux.BuildInitSpec(p, rt, l, p.Linux.Backend == "landlock", b.Caps.Cgroup), "", "  ")
		fmt.Fprintf(s.Out, "\n# init.json\n%s\n", spec)
	default:
		fmt.Fprintf(s.Err, "sdbx: --format %q unbekannt (yaml, json, seatbelt, bwrap)\n", format)
		return supervisor.ExitConfig
	}
	return 0
}

func looksLikePath(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, ".") || strings.HasPrefix(s, "~")
}

func cmdExplain(b *Built, target string, s IO) int {
	p := b.Policy
	if looksLikePath(target) {
		if strings.HasPrefix(target, "~") {
			target = p.Home + target[1:]
		}
		d := p.Evaluate(target)
		fmt.Fprintf(s.Out, "%s\n  Zugriff: %s\n  Grund:   %s\n", d.Path, d.Access, d.Reason)
		if len(d.Matches) > 0 {
			fmt.Fprintln(s.Out, "  Zutreffende Regeln:")
			for _, m := range d.Matches {
				fmt.Fprintf(s.Out, "    %-18s %s  [%s]\n", m.Effect, m.Rule.Label(), m.Rule.Origin)
			}
		}
		return 0
	}
	host, port := target, 443
	if h, ps, ok := strings.Cut(target, ":"); ok && !strings.Contains(ps, ":") {
		fmt.Sscan(ps, &port)
		host = h
	}
	if p.Net.Mode != "proxy" {
		fmt.Fprintf(s.Out, "%s:%d\n  network.mode: %s – %s\n", host, port, p.Net.Mode, map[string]string{"none": "kein Netzwerk", "host": "uneingeschränkt"}[p.Net.Mode])
		return 0
	}
	d, err := p.Net.Matcher.Decide(host, port)
	if err != nil {
		fmt.Fprintf(s.Err, "sdbx: %v\n", err)
		return supervisor.ExitConfig
	}
	verdict := "blockiert"
	if d.Allowed {
		verdict = "erlaubt"
	}
	fmt.Fprintf(s.Out, "%s:%d\n  Entscheidung: %s\n  Regel:        %s", host, port, verdict, d.Rule)
	if d.Source != "" {
		fmt.Fprintf(s.Out, "  [%s]", d.Source)
	}
	fmt.Fprintln(s.Out)
	if d.Allowed && !p.Net.Matcher.AllowPrivate {
		fmt.Fprintln(s.Out, "  Hinweis: Löst der Name auf eine private/lokale Adresse auf, wird die Verbindung trotzdem abgelehnt.")
	}
	return 0
}

func cmdRun(b *Built, c *Common, env Env, argv []string, learn bool, s IO) int {
	if printIssues(b, s, c.Quiet) {
		fmt.Fprintln(s.Err, "sdbx: nicht gestartet (Fail-closed). --degraded behandelt nicht durchsetzbare Regeln als Warnung.")
		return supervisor.ExitSetup
	}
	p := b.Policy
	var out io.Writer
	if p.AuditFile != "" {
		f, err := os.OpenFile(p.AuditFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(s.Err, "sdbx: Audit-Log: %v\n", err)
			return supervisor.ExitConfig
		}
		defer f.Close()
		out = f
	}
	log := audit.New(b.RunID, out, p.AuditFormat)
	if c.Verbose {
		log.SetLive(s.Err)
	}
	if learn {
		fmt.Fprintln(s.Err, "sdbx: Lernmodus – Netzwerkverbindungen werden protokolliert, aber NICHT eingeschränkt. Das Dateisystem bleibt geschützt.")
	}
	code, err := supervisor.Run(supervisor.Options{
		Policy: p, Caps: b.Caps, Integrations: b.Integrations, Argv: argv, HostEnv: env.Environ, Cwd: env.Cwd, Exe: env.Exe,
		RunID: b.RunID, Log: log, Stdin: s.In, Stdout: s.Out, Stderr: s.Err, Learn: learn, KeepTmp: c.KeepTmp, DryRun: c.DryRun, Verbose: c.Verbose,
	})
	if err != nil {
		var nf *supervisor.NotFoundError
		if errors.As(err, &nf) {
			fmt.Fprintf(s.Err, "sdbx: %v\n", err)
		} else {
			fmt.Fprintf(s.Err, "sdbx: %v\n", err)
		}
		return code
	}
	if p.AuditSummary && !c.Quiet && !learn {
		log.Summary(s.Err)
	}
	if learn {
		writeSuggestions(log, p, s.Err)
	}
	return code
}

// writeSuggestions gibt einen Konfigurationsvorschlag aus (Spec 9.3), schreibt aber nie.
func writeSuggestions(log *audit.Logger, p *policy.Policy, w io.Writer) {
	hosts := map[string]bool{}
	paths := map[string]string{}
	for _, e := range log.Events() {
		switch e.Type {
		case "net.learn":
			hosts[fmt.Sprint(e.Fields["host"])] = true
		case "fs.deny":
			paths[fmt.Sprint(e.Fields["path"])] = fmt.Sprint(e.Fields["op"])
		}
	}
	if len(hosts) == 0 && len(paths) == 0 {
		fmt.Fprintln(w, "sdbx: Lernmodus: keine Verstöße – die Konfiguration reicht für diesen Befehl.")
		return
	}
	fmt.Fprintln(w, "sdbx: Vorschlag für die Projekt-Konfiguration (bitte prüfen, nichts wurde geschrieben):")
	fmt.Fprintln(w, "---")
	if len(hosts) > 0 {
		fmt.Fprintln(w, "network:\n  allow:")
		var hs []string
		for h := range hosts {
			hs = append(hs, h)
		}
		sort.Strings(hs)
		for _, h := range hs {
			fmt.Fprintf(w, "    - %s\n", h)
		}
	}
	if len(paths) > 0 {
		fmt.Fprintln(w, "# Verweigerte Dateizugriffe – nur freigeben, wenn sie erwartet sind:")
		fmt.Fprintln(w, "# filesystem:\n#   write:")
		var ps []string
		for pth := range paths {
			ps = append(ps, pth)
		}
		sort.Strings(ps)
		for _, pth := range ps {
			fmt.Fprintf(w, "#     - %s   # %s, aktuell: %s\n", pth, paths[pth], p.Evaluate(pth).Access)
		}
	}
}
