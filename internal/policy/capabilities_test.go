package policy

import (
	"strings"
	"testing"
)

// issues fasst die Ergebnisse von EnforcementIssues als "F:…" (Fehler, Start verweigert) bzw. "W:…" zusammen.
func issues(p *Policy, c Caps) string {
	var out []string
	for _, i := range EnforcementIssues(p, c) {
		k := "W:"
		if i.Error {
			k = "F:"
		}
		out = append(out, k+strings.SplitN(i.Msg, ":", 2)[0])
	}
	return strings.Join(out, ",")
}

// Nicht durchsetzbare Kontrollen verhindern den Start; degraded macht sie zu Warnungen,
// außer wenn der Sandbox-Mechanismus selbst fehlt.
func TestEnforcementIssues(t *testing.T) {
	mac := Caps{Platform: "darwin", HaveSandboxExec: true}
	lin := Caps{Platform: "linux", HaveBwrap: true, LandlockABI: 3}
	pol := func(platform string, mod func(*Policy)) *Policy {
		p := &Policy{Platform: platform, Net: NetPolicy{Mode: "proxy"}, Linux: LinuxPolicy{Backend: "bwrap", Landlock: "auto", Seccomp: "default"}}
		if mod != nil {
			mod(p)
		}
		return p
	}
	degraded := func(p *Policy) { p.Degraded = true }
	cases := []struct {
		name string
		p    *Policy
		c    Caps
		want string
	}{
		{"macOS normal", pol("darwin", nil), mac, ""},
		{"macOS ohne sandbox-exec", pol("darwin", degraded), Caps{Platform: "darwin"}, "F:Sandbox-Mechanismus"},
		{"macOS max_memory", pol("darwin", func(p *Policy) { p.Limits.MaxMemory = 1 << 30 }), mac, "F:limits.max_memory"},
		{"macOS max_memory degraded", pol("darwin", func(p *Policy) { p.Limits.MaxMemory = 1 << 30; p.Degraded = true }), mac, "W:limits.max_memory"},
		{"Linux normal", pol("linux", nil), lin, ""},
		{"Linux ohne bwrap", pol("linux", degraded), Caps{Platform: "linux"}, "F:Sandbox-Mechanismus"},
		{"Linux landlock required ohne Kernel", pol("linux", func(p *Policy) { p.Linux.Landlock = "required" }), Caps{Platform: "linux", HaveBwrap: true}, "F:Landlock"},
		{"Linux max_memory ohne cgroup", pol("linux", func(p *Policy) { p.Limits.MaxMemory = 1 << 30 }), lin, "F:limits.max_memory"},
		{"Linux max_memory mit cgroup", pol("linux", func(p *Policy) { p.Limits.MaxMemory = 1 << 30 }), Caps{Platform: "linux", HaveBwrap: true, Cgroup: true}, ""},
		{"Plattform unbekannt", pol("windows", degraded), Caps{Platform: "windows"}, "F:Plattform"},
		{"Landlock-Backend ohne degraded", pol("linux", func(p *Policy) { p.Linux.Backend = "landlock" }), lin,
			"F:linux.backend,F:Geschützte Pfade,F:Unix-Sockets,F:Netzwerk"},
		{"Landlock-Backend degraded, ABI 4", pol("linux", func(p *Policy) { p.Linux.Backend = "landlock"; p.Degraded = true; p.IsolatePids = true }),
			Caps{Platform: "linux", LandlockABI: 4}, "W:Geschützte Pfade,W:process.isolate_pids,W:Unix-Sockets"},
		{"Landlock-Backend ohne Landlock", pol("linux", func(p *Policy) { p.Linux.Backend = "landlock"; p.Degraded = true; p.Net.Mode = "none" }),
			Caps{Platform: "linux"}, "F:Sandbox-Mechanismus,W:Geschützte Pfade,W:Unix-Sockets"},
	}
	for _, c := range cases {
		if got := issues(c.p, c.c); got != c.want {
			t.Errorf("%s: %q, erwartet %q", c.name, got, c.want)
		}
	}
}
