package linux

// InitSpec wird vom Supervisor geschrieben und von "sdbx __init" in der Sandbox gelesen.
type InitSpec struct {
	Argv       []string      `json:"argv"`
	Rlimits    []Rlimit      `json:"rlimits,omitempty"`
	Landlock   *LandlockSpec `json:"landlock,omitempty"`
	Seccomp    *SeccompSpec  `json:"seccomp,omitempty"`
	Bridges    []string      `json:"bridges,omitempty"` // Weiterleitungen für __bridge
	BridgeExe  string        `json:"bridge_exe,omitempty"`
	NoNewPrivs bool          `json:"no_new_privs"`
}

// Rlimit ist ein Ressourcenlimit.
type Rlimit struct {
	Name     string `json:"name"`
	Resource int    `json:"resource"`
	Value    uint64 `json:"value"`
}

// LandlockSpec beschreibt die Landlock-Regeln (Pfade aus Sicht der Sandbox).
type LandlockSpec struct {
	Mode          string   `json:"mode"` // auto | required
	Read          []string `json:"read,omitempty"`
	Write         []string `json:"write,omitempty"`
	ReadWriteFile []string `json:"read_write_file,omitempty"`
	RestrictNet   bool     `json:"restrict_net,omitempty"`
	ConnectPorts  []int    `json:"connect_ports,omitempty"`
	Scope         bool     `json:"scope,omitempty"`
}

// Ressourcen-Nummern unter Linux (asm-generic/resource.h).
const (
	RlimitCPU    = 0
	RlimitFsize  = 1
	RlimitNofile = 7
	RlimitNproc  = 6
)
