// Package linux setzt die Policy mit bubblewrap, Landlock und seccomp um (Spec 5.6).
package linux

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"sdbx/internal/backend"
	"sdbx/internal/pathutil"
	"sdbx/internal/policy"
)

// Facts sind Host-Informationen, die BuildArgs braucht (für Tests austauschbar).
type Facts struct {
	Stat       func(path string) (exists, isDir bool)
	ExpandGlob func(pattern string) []string
	Sockets    []string // gefundene Socket-Dateien zum Maskieren
	MaskDirs   []string // bekannte Socket-Verzeichnisse zum Maskieren
	Cgroup     bool
}

// HostFacts liefert die echten Host-Informationen.
func HostFacts(p *policy.Policy, rt *backend.Runtime) Facts {
	f := Facts{
		Stat: func(path string) (bool, bool) {
			st, err := os.Lstat(path)
			if err != nil {
				return false, false
			}
			return true, st.IsDir()
		},
		ExpandGlob: func(pattern string) []string {
			m, _ := pathutil.ExpandGlob(pattern, 200000)
			return m
		},
	}
	allowed := func(path string) bool {
		for _, s := range p.Sockets {
			if s.Path != "" && pathutil.IsUnder(path, s.Path) || s.Glob != "" && pathutil.Match(s.Glob, path) {
				return true
			}
		}
		for _, d := range rt.SocketAllowDirs {
			if pathutil.IsUnder(path, d) {
				return true
			}
		}
		return false
	}
	for _, k := range policy.KnownSocketLocations {
		d := k
		if !filepath.IsAbs(d) {
			d = filepath.Join(p.Home, d)
		}
		r, ok := pathutil.Resolve(d)
		if !ok || pathutil.IsUnder(p.Workspace, r) || allowed(r) {
			continue
		}
		// docker.sock & Co. sind Dateien: --tmpfs geht nur auf Verzeichnisse
		if _, isDir := f.Stat(r); isDir {
			f.MaskDirs = append(f.MaskDirs, r)
		} else {
			f.Sockets = append(f.Sockets, r)
		}
	}
	if x := os.Getenv("XDG_RUNTIME_DIR"); x != "" {
		if r, ok := pathutil.Resolve(x); ok && !pathutil.IsUnder(p.Workspace, r) {
			f.MaskDirs = append(f.MaskDirs, r)
		}
	} else if r, ok := pathutil.Resolve(fmt.Sprintf("/run/user/%d", p.UID)); ok {
		f.MaskDirs = append(f.MaskDirs, r)
	}
	roots := []string{"/run", "/var/run"}
	if !p.PrivateTmp {
		roots = append(roots, "/tmp")
	}
	res := ScanSockets(ScanOptions{Roots: roots, Home: p.Home, Skip: []string{p.Workspace, rt.SdbxTmp}})
	for _, s := range res.Sockets {
		if allowed(s) {
			continue
		}
		masked := false
		for _, d := range f.MaskDirs {
			masked = masked || pathutil.IsUnder(s, d)
		}
		if !masked {
			f.Sockets = append(f.Sockets, s)
		}
	}
	for _, s := range p.SocketDeny {
		f.Sockets = append(f.Sockets, s)
	}
	f.Sockets, f.MaskDirs = dedupe(f.Sockets), dedupe(f.MaskDirs)
	return f
}

// Layout beschreibt die Pfade innerhalb der Sandbox.
type Layout struct {
	InnerTmp    string
	RunDirHost  string
	RunDirInner string
	ExeInner    string
	SpecInner   string
	Cwd         string
}

// NewLayout berechnet die Pfade innerhalb der Sandbox.
func NewLayout(p *policy.Policy, rt *backend.Runtime) Layout {
	l := Layout{RunDirHost: rt.RunDir}
	if p.PrivateTmp {
		l.InnerTmp = "/tmp"
	} else {
		l.InnerTmp = rt.SdbxTmp
	}
	l.RunDirInner = l.inner(p, rt, rt.RunDir)
	l.ExeInner = filepath.Join(l.RunDirInner, "sdbx")
	l.SpecInner = filepath.Join(l.RunDirInner, "init.json")
	l.Cwd = l.inner(p, rt, rt.Cwd)
	if !visible(p, rt, rt.Cwd) {
		l.Cwd = p.Workspace
	}
	return l
}

// inner bildet einen Host-Pfad auf den Pfad in der Sandbox ab. Pfade unter dem
// privaten Temp-Verzeichnis landen unter /tmp; alle anderen behalten ihren Pfad
// (auch unter /tmp, wenn sie ausdrücklich eingebunden werden).
func (l Layout) inner(p *policy.Policy, rt *backend.Runtime, host string) string {
	if p.PrivateTmp && pathutil.IsUnder(host, rt.SdbxTmp) {
		return filepath.Join("/tmp", strings.TrimPrefix(host, rt.SdbxTmp))
	}
	return host
}

// visible meldet, ob ein Host-Pfad in der Sandbox existiert. Bei privatem /tmp
// sind Pfade unter /tmp nur sichtbar, wenn sie in einem eingebundenen Schreibbereich liegen.
func visible(p *policy.Policy, rt *backend.Runtime, host string) bool {
	if !p.PrivateTmp || !pathutil.IsUnder(host, "/tmp") || pathutil.IsUnder(host, rt.SdbxTmp) {
		return true
	}
	for _, r := range p.Rules {
		if r.Kind == policy.KindWrite && r.Glob == "" && r.Path != "/tmp" && pathutil.IsUnder(host, r.Path) {
			return true
		}
	}
	return false
}

// BuildArgs erzeugt die bwrap-Argumente.
func BuildArgs(p *policy.Policy, rt *backend.Runtime, f Facts, l Layout) ([]string, []string) {
	var a, notes []string
	add := func(s ...string) { a = append(a, s...) }
	add("--die-with-parent", "--unshare-user-try", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try")
	if p.Net.Mode != "host" {
		add("--unshare-net")
	}
	if p.IsolatePids {
		add("--unshare-pid")
	}
	add("--cap-drop", "ALL")

	// Basis
	if p.FSDefault == "read" {
		add("--ro-bind", "/", "/")
	} else {
		add("--tmpfs", "/")
		for _, r := range p.Rules {
			if (r.Kind == policy.KindSystem || r.Kind == policy.KindRead) && r.Glob == "" && r.Exists {
				add("--ro-bind-try", r.Path, r.Path)
			}
		}
		add("--ro-bind-try", "/sys", "/sys")
		if !p.IsolatePids {
			add("--ro-bind", "/proc", "/proc")
		}
	}
	add("--dev", "/dev")
	for _, d := range p.Linux.Devices {
		add("--dev-bind-try", d, d)
	}
	if p.IsolatePids {
		add("--proc", "/proc")
	}
	if p.PrivateTmp {
		add("--bind", rt.SdbxTmp, "/tmp")
	} else {
		add("--bind", "/tmp", "/tmp")
	}

	inner := func(h string) string {
		if !visible(p, rt, h) {
			return ""
		}
		return l.inner(p, rt, h)
	}
	expand := func(r policy.Rule) []string {
		if r.Glob != "" {
			return f.ExpandGlob(r.Glob)
		}
		if ok, _ := f.Stat(r.Path); ok {
			return []string{r.Path}
		}
		return nil
	}
	// Schreibbereiche
	for _, r := range p.Rules {
		if r.Kind != policy.KindWrite || r.Path == "/tmp" || r.Path == rt.SdbxTmp {
			continue
		}
		for _, h := range expand(r) {
			if in := inner(h); in != "" {
				add("--bind", h, in)
			}
		}
	}
	// Schreibschutz
	for _, r := range p.Rules {
		if r.Kind != policy.KindReadonly && r.Kind != policy.KindProtected {
			continue
		}
		for _, h := range expand(r) {
			if in := inner(h); in != "" {
				add("--ro-bind", h, in)
			}
		}
	}
	// Sperren
	for _, r := range p.Rules {
		if r.Kind != policy.KindDeny {
			continue
		}
		for _, h := range expand(r) {
			in := inner(h)
			if in == "" {
				continue
			}
			_, isDir := f.Stat(h)
			if !isDir {
				add("--ro-bind", "/dev/null", in)
				continue
			}
			add("--tmpfs", in)
			for _, e := range r.Except {
				if ok, _ := f.Stat(e); ok {
					add("--ro-bind", e, inner(e))
				}
			}
			add("--remount-ro", in)
		}
	}
	// Socket-Maskierung (Spec 7.1)
	for _, d := range f.MaskDirs {
		if in := inner(d); in != "" {
			add("--tmpfs", in)
			for _, s := range p.Sockets {
				if s.Path != "" && pathutil.IsUnder(s.Path, d) {
					if ok, _ := f.Stat(s.Path); ok {
						add("--bind", s.Path, inner(s.Path))
					}
				}
			}
			add("--remount-ro", in)
		}
	}
	for _, s := range f.Sockets {
		if in := inner(s); in != "" {
			add("--ro-bind", "/dev/null", in)
		}
	}
	if len(f.Sockets) > 0 {
		notes = append(notes, fmt.Sprintf("%d Unix-Sockets maskiert", len(f.Sockets)))
	}
	// sdbx-Laufzeit (schreibgeschützt)
	add("--ro-bind", l.RunDirHost, l.RunDirInner)
	add("--ro-bind", rt.SdbxExe, l.ExeInner)
	add("--chdir", l.Cwd)
	add("--", l.ExeInner, "__init", l.SpecInner)
	return a, notes
}

// BuildInitSpec erzeugt die Spezifikation für __init.
func BuildInitSpec(p *policy.Policy, rt *backend.Runtime, l Layout, landlockBackend bool, cgroup bool) InitSpec {
	s := InitSpec{Argv: rt.Argv, NoNewPrivs: true, BridgeExe: l.ExeInner}
	lim := p.Limits
	if lim.CPUTime > 0 {
		s.Rlimits = append(s.Rlimits, Rlimit{Name: "cpu_time", Resource: RlimitCPU, Value: uint64(lim.CPUTime.Seconds())})
	}
	if lim.MaxFileSize > 0 {
		s.Rlimits = append(s.Rlimits, Rlimit{Name: "max_file_size", Resource: RlimitFsize, Value: uint64(lim.MaxFileSize)})
	}
	if lim.MaxOpenFiles > 0 {
		s.Rlimits = append(s.Rlimits, Rlimit{Name: "max_open_files", Resource: RlimitNofile, Value: uint64(lim.MaxOpenFiles)})
	}
	if lim.MaxProcesses > 0 && !cgroup {
		s.Rlimits = append(s.Rlimits, Rlimit{Name: "max_processes", Resource: RlimitNproc, Value: uint64(lim.MaxProcesses)})
	}
	inner := func(h string) string {
		if !visible(p, rt, h) {
			return ""
		}
		return l.inner(p, rt, h)
	}
	if p.Linux.Landlock != "off" || landlockBackend {
		ll := &LandlockSpec{Mode: p.Linux.Landlock, Scope: true, ReadWriteFile: []string{"/proc"}}
		if landlockBackend {
			ll.Mode = "required"
		}
		var denies []string
		for _, r := range p.Rules {
			if r.Kind == policy.KindDeny && r.Glob == "" {
				denies = append(denies, r.Path)
			}
		}
		addGrant := func(dst *[]string, path string) {
			if landlockBackend {
				*dst = append(*dst, EmulateDeny(path, denies)...)
			} else if in := inner(path); in != "" {
				*dst = append(*dst, in)
			}
		}
		if p.FSDefault == "read" {
			addGrant(&ll.Read, "/")
		} else {
			for _, r := range p.Rules {
				if (r.Kind == policy.KindRead || r.Kind == policy.KindSystem) && r.Glob == "" {
					addGrant(&ll.Read, r.Path)
				}
			}
			ll.Read = append(ll.Read, l.RunDirInner)
		}
		for _, r := range p.Rules {
			if r.Kind == policy.KindWrite && r.Glob == "" {
				if !landlockBackend && p.PrivateTmp && r.Path == "/tmp" {
					continue
				}
				addGrant(&ll.Write, r.Path)
			}
		}
		if !landlockBackend {
			ll.Write = append(ll.Write, l.InnerTmp)
		}
		ll.Write = append(ll.Write, "/dev")
		if landlockBackend && p.Net.Mode == "proxy" {
			ll.RestrictNet = true
			ll.ConnectPorts = append([]int{rt.ProxyPort}, p.Net.Local...)
		}
		ll.Read, ll.Write = dedupe(ll.Read), dedupe(ll.Write)
		s.Landlock = ll
	}
	if p.Linux.Seccomp != "off" {
		s.Seccomp = &SeccompSpec{Profile: p.Linux.Seccomp, AllowPtrace: p.AllowPtrace}
		if landlockBackend {
			s.Seccomp.BlockUDP = true
			s.Seccomp.BlockInet = p.Net.Mode == "none"
		}
	}
	if !landlockBackend && p.Net.Mode == "proxy" {
		s.Bridges = append(s.Bridges, fmt.Sprintf("tcp:127.0.0.1:%d=unix:%s", rt.ProxyPort, filepath.Join(l.RunDirInner, "net", "proxy.sock")))
	}
	if !landlockBackend && p.Net.Mode != "host" {
		ports := append([]int(nil), p.Net.Local...)
		sort.Ints(ports)
		for _, port := range ports {
			s.Bridges = append(s.Bridges, fmt.Sprintf("tcp:127.0.0.1:%d=unix:%s", port, filepath.Join(l.RunDirInner, "net", fmt.Sprintf("local-%d.sock", port))))
		}
	}
	return s
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

// Prepare erzeugt die Startbeschreibung für Linux.
func Prepare(p *policy.Policy, rt *backend.Runtime, f Facts) (*backend.Launch, error) {
	landlockBackend := p.Linux.Backend == "landlock"
	l := NewLayout(p, rt)
	if landlockBackend {
		l.RunDirInner, l.ExeInner, l.SpecInner, l.InnerTmp, l.Cwd = rt.RunDir, rt.SdbxExe, filepath.Join(rt.RunDir, "init.json"), rt.SdbxTmp, rt.Cwd
	}
	spec := BuildInitSpec(p, rt, l, landlockBackend, f.Cgroup)
	data, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(rt.RunDir, "init.json"), data, 0o600); err != nil {
		return nil, err
	}
	if landlockBackend {
		return &backend.Launch{Path: rt.SdbxExe, Args: []string{rt.SdbxExe, "__init", filepath.Join(rt.RunDir, "init.json")}, Env: rt.Env, Dir: rt.Cwd}, nil
	}
	// Mountpunkt für das Binary
	if err := os.WriteFile(filepath.Join(rt.RunDir, "sdbx"), nil, 0o700); err != nil {
		return nil, err
	}
	bw, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("bwrap nicht gefunden (sdbx doctor)")
	}
	args, notes := BuildArgs(p, rt, f, l)
	return &backend.Launch{Path: bw, Args: append([]string{bw}, args...), Env: rt.Env, Notes: notes}, nil
}

// InnerTmp liefert TMPDIR innerhalb der Sandbox.
func InnerTmp(p *policy.Policy, rt *backend.Runtime) string {
	if p.Linux.Backend == "landlock" {
		return rt.SdbxTmp
	}
	return NewLayout(p, rt).InnerTmp
}
