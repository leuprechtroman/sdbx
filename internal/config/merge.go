package config

import (
	"fmt"
	"regexp"
	"sort"
	"time"
)

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func oneOf(field string, v *string, allowed ...string) error {
	if v == nil {
		return nil
	}
	for _, a := range allowed {
		if *v == a {
			return nil
		}
	}
	return fmt.Errorf("%s: %q ist ungültig (erlaubt: %v)", field, *v, allowed)
}

// Validate prüft Aufzählungswerte und einfache Formate eines Fragments.
func Validate(f *File) error {
	if fs := f.Filesystem; fs != nil {
		if err := oneOf("filesystem.default", fs.Default, "read", "deny"); err != nil {
			return err
		}
	}
	if n := f.Network; n != nil {
		if err := oneOf("network.mode", n.Mode, "proxy", "none", "host"); err != nil {
			return err
		}
		if err := oneOf("network.default", n.Default, "deny", "allow"); err != nil {
			return err
		}
	}
	if e := f.Env; e != nil {
		if err := oneOf("env.mode", e.Mode, "allowlist", "inherit"); err != nil {
			return err
		}
		for k := range e.Set {
			if !envNameRe.MatchString(k) {
				return fmt.Errorf("env.set: %q ist kein gültiger Variablenname", k)
			}
		}
	}
	if l := f.Linux; l != nil {
		if err := oneOf("linux.backend", l.Backend, "bwrap", "landlock"); err != nil {
			return err
		}
		if err := oneOf("linux.landlock", l.Landlock, "auto", "required", "off"); err != nil {
			return err
		}
		if err := oneOf("linux.seccomp", l.Seccomp, "default", "strict", "off"); err != nil {
			return err
		}
	}
	if a := f.Audit; a != nil {
		if err := oneOf("audit.format", a.Format, "json", "text"); err != nil {
			return err
		}
	}
	if lim := f.Limits; lim != nil {
		for name, v := range map[string]*int{"limits.max_processes": lim.MaxProcesses, "limits.max_open_files": lim.MaxOpenFiles} {
			if v != nil && *v < 0 {
				return fmt.Errorf("%s: negativer Wert", name)
			}
		}
	}
	if i := f.Integrations; i != nil && i.Clausona != nil {
		c := i.Clausona
		if err := oneOf("integrations.clausona.mode", c.Mode, "off", "ro", "rw"); err != nil {
			return err
		}
		if err := oneOf("integrations.clausona.guard_mcp", c.GuardMCP, "off", "warn", "revert"); err != nil {
			return err
		}
		if err := oneOf("integrations.clausona.daemons", c.Daemons, "off", "sandboxed", "host"); err != nil {
			return err
		}
	}
	return nil
}

// SetValue ist ein Wert aus env.set mit Herkunft.
type SetValue struct {
	Value  string
	Origin Origin
}

// ClausonaSettings ist die zusammengeführte clausona-Konfiguration.
type ClausonaSettings struct {
	Mode     string
	Profiles Profiles
	GuardMCP string
	IDE      bool
	Daemons  string
	Profile  string
}

// Config ist die vollständig zusammengeführte Konfiguration (noch ohne Pfadauflösung).
type Config struct {
	Workspace       string
	WorkspaceOrigin Origin

	FSDefault       string
	FSRead          List
	FSWrite         List
	FSDeny          List
	FSReadonly      List
	FSExempt        List
	FSUnprotect     List
	FSCreateMissing bool

	NetMode         string
	NetDefault      string
	NetAllow        List
	NetDeny         List
	NetPorts        []int
	NetAllowPrivate bool
	NetLocal        []int
	NetSSH          bool

	SocketsAllow List

	EnvMode        string
	EnvPassthrough List
	EnvDeny        List
	EnvSet         map[string]SetValue

	IsolatePids bool
	AllowPtrace bool
	PrivateTmp  bool

	Timeout      time.Duration
	KillGrace    time.Duration
	CPUTime      time.Duration
	MaxProcesses int
	MaxOpenFiles int
	MaxMemory    int64
	MaxFileSize  int64

	MachServices List

	LinuxBackend  string
	LinuxLandlock string
	LinuxSeccomp  string
	LinuxDevices  List

	Clausona ClausonaSettings

	AuditFile    string
	AuditFormat  string
	AuditSummary bool

	Degraded bool

	// ScalarOrigin hält fest, welche Quelle einen Skalar zuletzt gesetzt hat.
	ScalarOrigin map[string]string
	// Sources listet alle angewandten Fragmente in Reihenfolge.
	Sources []string
}

// Defaults liefert die eingebauten Standardwerte (Spec 4.5).
func Defaults() *Config {
	return &Config{
		FSDefault:     "read",
		NetMode:       "proxy",
		NetDefault:    "deny",
		EnvMode:       "allowlist",
		EnvSet:        map[string]SetValue{},
		IsolatePids:   true,
		PrivateTmp:    true,
		KillGrace:     10 * time.Second,
		MachServices:  Items(Origin{Source: "builtin"}, "default"),
		LinuxBackend:  "bwrap",
		LinuxLandlock: "auto",
		LinuxSeccomp:  "default",
		Clausona:      ClausonaSettings{Mode: "off", Profiles: Profiles{Kind: "active"}, GuardMCP: "warn", Daemons: "off"},
		AuditFormat:   "json",
		AuditSummary:  false,
		ScalarOrigin:  map[string]string{},
		Sources:       []string{"builtin"},
	}
}

func setStr(c *Config, key string, dst *string, v *string, src string) {
	if v != nil {
		*dst = *v
		c.ScalarOrigin[key] = src
	}
}

func setBool(c *Config, key string, dst *bool, v *bool, src string) {
	if v != nil {
		*dst = *v
		c.ScalarOrigin[key] = src
	}
}

func setInt(c *Config, key string, dst *int, v *int, src string) {
	if v != nil {
		*dst = *v
		c.ScalarOrigin[key] = src
	}
}

func setDur(c *Config, key string, dst *time.Duration, v *Duration, src string) {
	if v != nil {
		*dst = v.Duration
		c.ScalarOrigin[key] = src
	}
}

func setSize(c *Config, key string, dst *int64, v *Size, src string) {
	if v != nil {
		*dst = v.Bytes
		c.ScalarOrigin[key] = src
	}
}

func uniqInts(a, b []int) []int {
	seen := map[int]bool{}
	var out []int
	for _, v := range append(append([]int{}, a...), b...) {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Ints(out)
	return out
}

// Apply wendet ein Fragment auf die Konfiguration an.
func (c *Config) Apply(fr Fragment) {
	f, src := fr.File, fr.Source
	if f == nil {
		return
	}
	c.Sources = append(c.Sources, src)
	if f.Workspace != nil {
		c.Workspace = *f.Workspace
		c.WorkspaceOrigin = Origin{Source: src, Dir: fr.Dir}
		c.ScalarOrigin["workspace"] = src
	}
	if fs := f.Filesystem; fs != nil {
		setStr(c, "filesystem.default", &c.FSDefault, fs.Default, src)
		c.FSRead = append(c.FSRead, fs.Read...)
		c.FSWrite = append(c.FSWrite, fs.Write...)
		c.FSDeny = append(c.FSDeny, fs.Deny...)
		c.FSReadonly = append(c.FSReadonly, fs.Readonly...)
		c.FSExempt = append(c.FSExempt, fs.Exempt...)
		c.FSUnprotect = append(c.FSUnprotect, fs.Unprotect...)
		setBool(c, "filesystem.create_missing", &c.FSCreateMissing, fs.CreateMissing, src)
	}
	if n := f.Network; n != nil {
		setStr(c, "network.mode", &c.NetMode, n.Mode, src)
		setStr(c, "network.default", &c.NetDefault, n.Default, src)
		c.NetAllow = append(c.NetAllow, n.Allow...)
		c.NetDeny = append(c.NetDeny, n.Deny...)
		if len(n.Ports) > 0 {
			c.NetPorts = uniqInts(c.NetPorts, n.Ports)
		}
		c.NetLocal = uniqInts(c.NetLocal, n.Local)
		setBool(c, "network.allow_private", &c.NetAllowPrivate, n.AllowPrivate, src)
		setBool(c, "network.ssh", &c.NetSSH, n.SSH, src)
	}
	if s := f.Sockets; s != nil {
		c.SocketsAllow = append(c.SocketsAllow, s.Allow...)
	}
	if e := f.Env; e != nil {
		setStr(c, "env.mode", &c.EnvMode, e.Mode, src)
		c.EnvPassthrough = append(c.EnvPassthrough, e.Passthrough...)
		c.EnvDeny = append(c.EnvDeny, e.Deny...)
		for k, v := range e.Set {
			c.EnvSet[k] = SetValue{Value: v, Origin: Origin{Source: src, Dir: fr.Dir}}
		}
	}
	if p := f.Process; p != nil {
		setBool(c, "process.isolate_pids", &c.IsolatePids, p.IsolatePids, src)
		setBool(c, "process.allow_ptrace", &c.AllowPtrace, p.AllowPtrace, src)
		setBool(c, "process.private_tmp", &c.PrivateTmp, p.PrivateTmp, src)
	}
	if l := f.Limits; l != nil {
		setDur(c, "limits.timeout", &c.Timeout, l.Timeout, src)
		setDur(c, "limits.kill_grace", &c.KillGrace, l.KillGrace, src)
		setDur(c, "limits.cpu_time", &c.CPUTime, l.CPUTime, src)
		setInt(c, "limits.max_processes", &c.MaxProcesses, l.MaxProcesses, src)
		setInt(c, "limits.max_open_files", &c.MaxOpenFiles, l.MaxOpenFiles, src)
		setSize(c, "limits.max_memory", &c.MaxMemory, l.MaxMemory, src)
		setSize(c, "limits.max_file_size", &c.MaxFileSize, l.MaxFileSize, src)
	}
	if m := f.MacOS; m != nil {
		c.MachServices = append(c.MachServices, m.MachServices...)
	}
	if l := f.Linux; l != nil {
		setStr(c, "linux.backend", &c.LinuxBackend, l.Backend, src)
		setStr(c, "linux.landlock", &c.LinuxLandlock, l.Landlock, src)
		setStr(c, "linux.seccomp", &c.LinuxSeccomp, l.Seccomp, src)
		c.LinuxDevices = append(c.LinuxDevices, l.Devices...)
	}
	if i := f.Integrations; i != nil && i.Clausona != nil {
		cl := i.Clausona
		setStr(c, "integrations.clausona.mode", &c.Clausona.Mode, cl.Mode, src)
		if cl.Profiles != nil {
			c.Clausona.Profiles = *cl.Profiles
			c.ScalarOrigin["integrations.clausona.profiles"] = src
		}
		setStr(c, "integrations.clausona.guard_mcp", &c.Clausona.GuardMCP, cl.GuardMCP, src)
		setBool(c, "integrations.clausona.ide", &c.Clausona.IDE, cl.IDE, src)
		setStr(c, "integrations.clausona.daemons", &c.Clausona.Daemons, cl.Daemons, src)
		setStr(c, "integrations.clausona.profile", &c.Clausona.Profile, cl.Profile, src)
	}
	if a := f.Audit; a != nil {
		setStr(c, "audit.file", &c.AuditFile, a.File, src)
		setStr(c, "audit.format", &c.AuditFormat, a.Format, src)
		setBool(c, "audit.summary", &c.AuditSummary, a.Summary, src)
	}
	setBool(c, "degraded", &c.Degraded, f.Degraded, src)
}

// RequiredValue ist ein von einer Integration erzwungener Skalar.
type RequiredValue struct {
	Key    string
	Value  any
	Source string
}

// ScalarValue liefert den aktuellen Wert eines erzwingbaren Skalars.
func (c *Config) ScalarValue(key string) (any, bool) {
	switch key {
	case "process.isolate_pids":
		return c.IsolatePids, true
	case "process.private_tmp":
		return c.PrivateTmp, true
	case "process.allow_ptrace":
		return c.AllowPtrace, true
	case "network.mode":
		return c.NetMode, true
	case "env.mode":
		return c.EnvMode, true
	}
	return nil, false
}

// CheckRequired meldet, wenn eine spätere Quelle einen erzwungenen Wert überschrieben hat.
func (c *Config) CheckRequired(req []RequiredValue) error {
	for _, r := range req {
		v, ok := c.ScalarValue(r.Key)
		if !ok {
			return fmt.Errorf("interner Fehler: %s ist nicht erzwingbar", r.Key)
		}
		if fmt.Sprint(v) != fmt.Sprint(r.Value) {
			return fmt.Errorf("%s: %s=%v widerspricht %s (erfordert %v)", c.ScalarOrigin[r.Key], r.Key, v, r.Source, r.Value)
		}
	}
	return nil
}

// Build führt alle Fragmente in der Reihenfolge der Spec (4.6) zusammen.
// integration wird zwischen globaler und Projektkonfiguration eingefügt.
func Build(global, integration, project, cli []Fragment, required []RequiredValue) (*Config, error) {
	c := Defaults()
	for _, fr := range global {
		c.Apply(fr)
	}
	for _, fr := range integration {
		c.Apply(fr)
	}
	for _, fr := range project {
		c.Apply(fr)
	}
	for _, fr := range cli {
		c.Apply(fr)
	}
	if err := c.CheckRequired(required); err != nil {
		return nil, err
	}
	return c, nil
}
