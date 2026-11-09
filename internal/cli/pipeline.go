package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"sdbx/internal/backend/linux"
	"sdbx/internal/config"
	"sdbx/internal/integrations"
	"sdbx/internal/integrations/clausona"
	"sdbx/internal/pathutil"
	"sdbx/internal/policy"
	"sdbx/internal/supervisor"
)

// Common sind die globalen Flags (Spec 3.2).
type Common struct {
	Config      string
	NoGlobal    bool
	Workspace   string
	AllowWrite  multi
	AllowRead   multi
	Deny        multi
	AllowDomain multi
	NoNetwork   bool
	Integration multi
	Timeout     string
	Degraded    bool
	Log         string
	LogFormat   string
	Quiet       bool
	Verbose     bool
	DryRun      bool
	KeepTmp     bool
	NoRewrite   bool
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

// Env abstrahiert Host-Werte für Tests.
type Env struct {
	Platform string
	Home     string
	Cwd      string
	UID, GID int
	UserTmp  string
	Environ  []string
	Exe      string
}

// HostEnv liefert die echte Umgebung.
func HostEnv() Env {
	home, _ := os.UserHomeDir()
	cwd, _ := os.Getwd()
	exe, _ := os.Executable()
	exe, _ = filepath.EvalSymlinks(exe)
	ut := pathutil.UserTempDir()
	if r, ok := pathutil.Resolve(ut); ok {
		ut = r
	}
	return Env{Platform: runtime.GOOS, Home: home, Cwd: cwd, UID: os.Getuid(), GID: os.Getgid(), UserTmp: ut, Environ: os.Environ(), Exe: exe}
}

func (e Env) lookup(k string) (string, bool) {
	for i := len(e.Environ) - 1; i >= 0; i-- {
		key, v, _ := strings.Cut(e.Environ[i], "=")
		if key == k {
			return v, true
		}
	}
	return "", false
}

func (e Env) envMap() map[string]string {
	m := map[string]string{}
	for _, kv := range e.Environ {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	return m
}

// cliFragment baut aus den Flags ein Fragment (höchste Priorität).
func (c *Common) cliFragment(cwd string) (*config.File, error) {
	o := config.Origin{Source: "cli", Dir: cwd}
	f := &config.File{Version: config.Ptr(1)}
	if c.Workspace != "" {
		f.Workspace = &c.Workspace
	}
	if len(c.AllowWrite)+len(c.AllowRead)+len(c.Deny) > 0 {
		f.Filesystem = &config.Filesystem{Write: config.Items(o, c.AllowWrite...), Read: config.Items(o, c.AllowRead...), Deny: config.Items(o, c.Deny...)}
	}
	if len(c.AllowDomain) > 0 || c.NoNetwork {
		f.Network = &config.Network{Allow: config.Items(o, c.AllowDomain...)}
		if c.NoNetwork {
			f.Network.Mode = config.Ptr("none")
		}
	}
	if c.Timeout != "" {
		d, err := config.ParseDuration(c.Timeout)
		if err != nil {
			return nil, fmt.Errorf("--timeout: %v", err)
		}
		f.Limits = &config.Limits{Timeout: &config.Duration{Duration: d}}
	}
	if c.Degraded {
		f.Degraded = config.Ptr(true)
	}
	if c.Log != "" || c.LogFormat != "" {
		f.Audit = &config.Audit{}
		if c.Log != "" {
			f.Audit.File = &c.Log
		}
		if c.LogFormat != "" {
			f.Audit.Format = &c.LogFormat
		}
	}
	for _, spec := range c.Integration {
		k, v, ok := strings.Cut(spec, "=")
		if !ok {
			return nil, fmt.Errorf("--integration %q: Format name=wert", spec)
		}
		name, sub, _ := strings.Cut(k, ".")
		if name != "clausona" {
			return nil, fmt.Errorf("--integration: unbekannte Integration %q (verfügbar: clausona)", name)
		}
		if f.Integrations == nil {
			f.Integrations = &config.Integrations{Clausona: &config.Clausona{}}
		}
		cl := f.Integrations.Clausona
		switch sub {
		case "", "mode":
			cl.Mode = config.Ptr(v)
		case "profiles":
			p := config.ParseProfiles(v)
			cl.Profiles = &p
		case "profile":
			cl.Profile = config.Ptr(v)
		case "daemons":
			cl.Daemons = config.Ptr(v)
		case "guard_mcp":
			cl.GuardMCP = config.Ptr(v)
		case "ide":
			b, err := strconv.ParseBool(v)
			if err != nil {
				return nil, fmt.Errorf("--integration clausona.ide: %q ist kein Wahrheitswert", v)
			}
			cl.IDE = &b
		default:
			return nil, fmt.Errorf("--integration: unbekannte Option clausona.%s", sub)
		}
	}
	config.Stamp(f, o, cwd)
	if err := config.Validate(f); err != nil {
		return nil, err
	}
	return f, nil
}

// Built ist das Ergebnis der Pipeline.
type Built struct {
	Loaded       *config.Loaded
	Config       *config.Config
	Policy       *policy.Policy
	Caps         policy.Caps
	Integrations []*integrations.Result
	RunID        string
	Issues       []policy.Issue
}

// Errors liefert die Fehler.
func (b *Built) Errors() []policy.Issue {
	var out []policy.Issue
	for _, i := range b.Issues {
		if i.Error {
			out = append(out, i)
		}
	}
	return out
}

// DetectCaps erkennt die Plattformfähigkeiten.
func DetectCaps(env Env) policy.Caps {
	c := policy.Caps{Platform: env.Platform}
	switch env.Platform {
	case "linux":
		_, err := exec.LookPath("bwrap")
		c.HaveBwrap = err == nil
		c.LandlockABI = linux.LandlockABI()
		if _, err := exec.LookPath("systemd-run"); err == nil {
			_, bus := env.lookup("DBUS_SESSION_BUS_ADDRESS")
			_, sterr := os.Stat(fmt.Sprintf("/run/user/%d/bus", env.UID))
			c.Cgroup = bus || sterr == nil
		}
	case "darwin":
		_, err := os.Stat("/usr/bin/sandbox-exec")
		c.HaveSandboxExec = err == nil
	}
	return c
}

func darwinCacheDir() []string {
	if runtime.GOOS != "darwin" {
		return nil
	}
	out, err := exec.Command("getconf", "DARWIN_USER_CACHE_DIR").Output()
	if err != nil {
		return nil
	}
	return []string{strings.TrimSpace(string(out))}
}

// Build führt Laden, Integrationen, Zusammenführung und Kompilierung aus.
func Build(c *Common, env Env, argv []string, caps policy.Caps) (*Built, error) {
	loaded, err := config.Load(config.LoadOptions{ConfigPath: c.Config, NoGlobal: c.NoGlobal, StartDir: env.Cwd, Home: env.Home})
	if err != nil {
		return nil, err
	}
	cliF, err := c.cliFragment(env.Cwd)
	if err != nil {
		return nil, err
	}
	cli := []config.Fragment{{File: cliF, Source: "cli", Dir: env.Cwd}}
	b := &Built{Loaded: loaded, Caps: caps, RunID: supervisor.NewRunID()}

	// Erster Durchlauf: Integrationseinstellungen ermitteln.
	pre, err := config.Build(loaded.Global, nil, loaded.Project, cli, nil)
	if err != nil {
		return nil, err
	}
	var intFrags []config.Fragment
	var required []config.RequiredValue
	if pre.Clausona.Mode != "off" {
		stateDir := filepath.Join(stateHome(env), "sdbx", "clausona-guard")
		rc := integrations.RunContext{Argv: argv, Env: env.envMap(), Platform: env.Platform, Home: env.Home, UID: env.UID, StateDir: stateDir}
		res, err := clausona.Resolve(pre.Clausona, rc)
		if err != nil {
			return nil, err
		}
		if c.NoRewrite {
			res.Argv = nil
		}
		for _, e := range res.Errors {
			b.Issues = append(b.Issues, policy.Issue{Error: true, Msg: e})
		}
		for _, n := range res.Notes {
			b.Issues = append(b.Issues, policy.Issue{Msg: n})
		}
		b.Integrations = append(b.Integrations, res)
		if res.Fragment != nil {
			intFrags = append(intFrags, config.Fragment{File: res.Fragment, Source: integrations.Source(res.Name)})
		}
		required = append(required, res.Required...)
	}
	cfg, err := config.Build(loaded.Global, intFrags, loaded.Project, cli, required)
	if err != nil {
		return nil, err
	}
	b.Config = cfg

	defWS := loaded.Workspace
	if defWS == "" {
		defWS = env.Cwd
	}
	for _, w := range loaded.Warnings {
		b.Issues = append(b.Issues, policy.Issue{Msg: w})
	}
	var socketDeny []string
	for _, r := range b.Integrations {
		socketDeny = append(socketDeny, r.SocketDeny...)
	}
	ctx := policy.Context{
		Platform: env.Platform, Home: env.Home, UID: env.UID, GID: env.GID, UserTmp: env.UserTmp,
		SdbxTmp: supervisor.TmpDirFor(env.UserTmp, b.RunID), DefaultWorkspace: defWS, ConfigFiles: loaded.Files,
		LookupEnv: env.lookup, ExtraWrite: darwinCacheDir(), SocketDeny: socketDeny,
	}
	ctx.PathEnv, _ = env.lookup("PATH")
	p, err := policy.Compile(cfg, ctx)
	if err != nil {
		return nil, err
	}
	b.Policy = p
	b.Issues = append(b.Issues, p.Issues...)
	b.Issues = append(b.Issues, policy.EnforcementIssues(p, caps)...)
	return b, nil
}

func stateHome(env Env) string {
	if x, ok := env.lookup("XDG_STATE_HOME"); ok && x != "" {
		return x
	}
	return filepath.Join(env.Home, ".local", "state")
}
