package policy

import "fmt"

// Status beschreibt, wie gut eine Kontrolle auf der Plattform durchgesetzt wird.
type Status int

const (
	Enforced Status = iota
	Warn
	Unenforceable
)

func (s Status) String() string {
	return [...]string{"durchgesetzt", "eingeschränkt", "nicht durchsetzbar"}[s]
}

// Caps sind die erkannten Plattformfähigkeiten.
type Caps struct {
	Platform        string
	HaveBwrap       bool
	HaveSandboxExec bool
	LandlockABI     int
	Cgroup          bool // cgroup-v2-Delegation über systemd-run --user nutzbar
}

// Control ist eine Zeile der Matrix.
type Control struct {
	Name   string
	Status Status
	Detail string
}

// Matrix bewertet alle relevanten Kontrollen einer Policy.
func Matrix(p *Policy, c Caps) []Control {
	var out []Control
	add := func(name string, s Status, detail string, a ...any) {
		out = append(out, Control{Name: name, Status: s, Detail: fmt.Sprintf(detail, a...)})
	}
	hasGlob := false
	for _, r := range p.Rules {
		hasGlob = hasGlob || r.Glob != ""
	}
	switch c.Platform {
	case "darwin":
		if c.HaveSandboxExec {
			add("Sandbox-Mechanismus", Enforced, "Seatbelt (sandbox-exec)")
		} else {
			add("Sandbox-Mechanismus", Unenforceable, "/usr/bin/sandbox-exec fehlt")
		}
		add("Dateisystem", Enforced, "Seatbelt prüft aufgelöste Pfade, auch für neue Dateien")
		add("Netzwerk", Enforced, "nur Proxy und freigegebene lokale Ports erreichbar")
		add("Unix-Sockets", Enforced, "pfadgenau, auch für neue Sockets")
		add("Terminal-Injection (TIOCSTI)", Enforced, "ioctl-command-Filter")
		add("Mach-Services", Enforced, "%d freigegeben", len(p.MachServices))
		if p.Limits.MaxMemory > 0 {
			add("limits.max_memory", Unenforceable, "macOS erzwingt keine Speichergrenze")
		}
		if p.Limits.MaxProcesses > 0 {
			add("limits.max_processes", Warn, "RLIMIT_NPROC zählt alle Prozesse des Nutzers")
		}
		if len(p.Linux.Devices) > 0 {
			add("linux.devices", Warn, "unter macOS ohne Wirkung")
		}
	case "linux":
		if p.Linux.Backend == "landlock" {
			if !p.Degraded {
				add("linux.backend: landlock", Unenforceable, "eingeschränkter Modus erfordert degraded: true bzw. --degraded")
			}
			if c.LandlockABI < 1 {
				add("Sandbox-Mechanismus", Unenforceable, "Kernel ohne Landlock (linux.backend: landlock)")
			} else {
				add("Sandbox-Mechanismus", Enforced, "Landlock ABI %d ohne Namespaces", c.LandlockABI)
			}
			add("Dateisystem-Sperren", Warn, "Deny innerhalb lesbarer Bäume nur für beim Start existierende Einträge emuliert")
			add("Geschützte Pfade", Unenforceable, "readonly und geschützte Pfade (.git/hooks, ~/.local/bin …) in Schreibbereichen bleiben beschreibbar; Landlock kann Freigaben nicht einschränken")
			if p.IsolatePids {
				add("process.isolate_pids", Unenforceable, "ohne Namespaces nicht möglich")
			}
			add("Unix-Sockets", Unenforceable, "ohne Mount-Namespace nicht maskierbar")
			switch p.Net.Mode {
			case "proxy":
				if c.LandlockABI >= 4 {
					add("Netzwerk", Enforced, "Landlock-TCP-Regeln plus seccomp")
				} else {
					add("Netzwerk", Unenforceable, "Landlock-Netzwerkregeln brauchen ABI 4 (Kernel 6.7)")
				}
			case "none":
				add("Netzwerk", Enforced, "seccomp verbietet Internet-Sockets")
			}
		} else {
			if c.HaveBwrap {
				add("Sandbox-Mechanismus", Enforced, "bubblewrap mit Namespaces")
			} else {
				add("Sandbox-Mechanismus", Unenforceable, "bwrap fehlt (sdbx doctor)")
			}
			add("Dateisystem", Enforced, "Mount-Namespace")
			if hasGlob {
				add("Glob-Regeln", Warn, "gelten nur für beim Start existierende Pfade")
			}
			add("Netzwerk", Enforced, "eigener Netzwerk-Namespace, Proxy über Bridge")
			add("Unix-Sockets", Warn, "beim Start vorhandene Sockets maskiert; später entstehende außerhalb von Workspace und privatem /tmp sind erreichbar")
			if p.Linux.Landlock == "required" && c.LandlockABI < 1 {
				add("Landlock", Unenforceable, "linux.landlock: required, aber Kernel ohne Landlock")
			} else if c.LandlockABI >= 1 && p.Linux.Landlock != "off" {
				add("Landlock", Enforced, "ABI %d als zusätzliche Schicht", c.LandlockABI)
			}
		}
		if p.Linux.Seccomp != "off" {
			add("seccomp", Enforced, "Profil %s", p.Linux.Seccomp)
			add("Terminal-Injection (TIOCSTI)", Enforced, "seccomp")
		} else {
			add("seccomp", Warn, "abgeschaltet")
		}
		if p.Limits.MaxMemory > 0 {
			if c.Cgroup {
				add("limits.max_memory", Enforced, "cgroup v2")
			} else {
				add("limits.max_memory", Unenforceable, "keine cgroup-v2-Delegation (systemd-run --user)")
			}
		}
		if p.Limits.MaxProcesses > 0 {
			if c.Cgroup {
				add("limits.max_processes", Enforced, "cgroup v2 pids.max")
			} else {
				add("limits.max_processes", Warn, "nur RLIMIT_NPROC (zählt alle Prozesse des Nutzers)")
			}
		}
	default:
		add("Plattform", Unenforceable, "%s wird nicht unterstützt", c.Platform)
	}
	return out
}

// EnforcementIssues wandelt nicht durchsetzbare Kontrollen in Fehler um (bzw. Warnungen
// bei degraded). Eingeschränkte Kontrollen zeigt sdbx check in der Matrix.
func EnforcementIssues(p *Policy, c Caps) []Issue {
	var out []Issue
	for _, ctl := range Matrix(p, c) {
		switch ctl.Status {
		case Unenforceable:
			out = append(out, Issue{Error: !p.Degraded || ctl.Name == "Sandbox-Mechanismus" || ctl.Name == "Plattform",
				Msg: fmt.Sprintf("%s: %s", ctl.Name, ctl.Detail)})
		}
	}
	return out
}
