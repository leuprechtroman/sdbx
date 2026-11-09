// Package config lädt, validiert und vereinigt sdbx-Konfigurationsdateien.
package config

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Origin beschreibt, woher eine Regel stammt.
type Origin struct {
	Source string // Dateipfad, "builtin", "preset:node", "integration:clausona", "cli"
	Line   int
	Dir    string // Basis für relative Pfade und ${CONFIG_DIR}; leer = Workspace
}

func (o Origin) String() string {
	if o.Line > 0 {
		return fmt.Sprintf("%s:%d", o.Source, o.Line)
	}
	return o.Source
}

// Item ist ein Listeneintrag mit Herkunft.
type Item struct {
	Value  string
	Origin Origin
}

// List ist eine Liste von Zeichenketten, deren Einträge ihre Zeilennummer behalten.
type List []Item

func (l *List) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		*l = nil
		return nil
	}
	if n.Kind != yaml.SequenceNode {
		return &FieldError{Line: n.Line, Msg: "Liste erwartet"}
	}
	out := make(List, 0, len(n.Content))
	for _, c := range n.Content {
		if c.Kind != yaml.ScalarNode {
			return &FieldError{Line: c.Line, Msg: "Listeneintrag muss ein einfacher Wert sein"}
		}
		out = append(out, Item{Value: c.Value, Origin: Origin{Line: c.Line}})
	}
	*l = out
	return nil
}

// Values gibt nur die Werte zurück.
func (l List) Values() []string {
	out := make([]string, len(l))
	for i, it := range l {
		out[i] = it.Value
	}
	return out
}

// Items erzeugt eine Liste aus Werten mit gemeinsamer Herkunft.
func Items(o Origin, values ...string) List {
	out := make(List, len(values))
	for i, v := range values {
		out[i] = Item{Value: v, Origin: o}
	}
	return out
}

// IntList ist eine Liste von Ports.
type IntList []int

func (l *IntList) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.SequenceNode {
		return &FieldError{Line: n.Line, Msg: "Liste von Ports erwartet"}
	}
	for _, c := range n.Content {
		v, err := strconv.Atoi(c.Value)
		if err != nil || v < 1 || v > 65535 {
			return &FieldError{Line: c.Line, Msg: fmt.Sprintf("ungültiger Port %q", c.Value)}
		}
		*l = append(*l, v)
	}
	return nil
}

// Duration akzeptiert Go-Dauern ("30m", "2h") und 0.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseDuration(n.Value)
	if err != nil {
		return &FieldError{Line: n.Line, Msg: err.Error()}
	}
	d.Duration = v
	return nil
}

// ParseDuration parst eine Dauer; "0" und "" bedeuten unbegrenzt.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	v, err := time.ParseDuration(s)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("ungültige Dauer %q (Beispiele: 30s, 10m, 2h)", s)
	}
	return v, nil
}

// Size ist eine Bytegröße wie "4G" oder "512M".
type Size struct{ Bytes int64 }

func (s *Size) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseSize(n.Value)
	if err != nil {
		return &FieldError{Line: n.Line, Msg: err.Error()}
	}
	s.Bytes = v
	return nil
}

// ParseSize parst Größenangaben mit optionalem Suffix K, M, G, T (Basis 1024).
func ParseSize(in string) (int64, error) {
	s := strings.TrimSpace(strings.ToUpper(in))
	if s == "" || s == "0" {
		return 0, nil
	}
	mult := int64(1)
	s = strings.TrimSuffix(s, "B")
	switch {
	case strings.HasSuffix(s, "K"):
		mult, s = 1<<10, strings.TrimSuffix(s, "K")
	case strings.HasSuffix(s, "M"):
		mult, s = 1<<20, strings.TrimSuffix(s, "M")
	case strings.HasSuffix(s, "G"):
		mult, s = 1<<30, strings.TrimSuffix(s, "G")
	case strings.HasSuffix(s, "T"):
		mult, s = 1<<40, strings.TrimSuffix(s, "T")
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 || v > math.MaxInt64/mult {
		return 0, fmt.Errorf("ungültige Größe %q (Beispiele: 512M, 4G)", in)
	}
	return v * mult, nil
}

// File ist eine einzelne Konfigurationsdatei bzw. ein Fragment.
type File struct {
	Version      *int          `yaml:"version"`
	Include      List          `yaml:"include"`
	Project      *string       `yaml:"project"` // nur in ~/.config/sdbx/projects/: Workspace-Pfad für die Zuordnung
	Workspace    *string       `yaml:"workspace"`
	Filesystem   *Filesystem   `yaml:"filesystem"`
	Network      *Network      `yaml:"network"`
	Sockets      *Sockets      `yaml:"sockets"`
	Env          *Env          `yaml:"env"`
	Process      *Process      `yaml:"process"`
	Limits       *Limits       `yaml:"limits"`
	MacOS        *MacOS        `yaml:"macos"`
	Linux        *Linux        `yaml:"linux"`
	Integrations *Integrations `yaml:"integrations"`
	Audit        *Audit        `yaml:"audit"`
	Degraded     *bool         `yaml:"degraded"`
}

type Filesystem struct {
	Default       *string `yaml:"default"`
	Read          List    `yaml:"read"`
	Write         List    `yaml:"write"`
	Deny          List    `yaml:"deny"`
	Readonly      List    `yaml:"readonly"`
	Exempt        List    `yaml:"exempt"`
	Unprotect     List    `yaml:"unprotect"`
	CreateMissing *bool   `yaml:"create_missing"`
}

type Network struct {
	Mode         *string `yaml:"mode"`
	Default      *string `yaml:"default"`
	Allow        List    `yaml:"allow"`
	Deny         List    `yaml:"deny"`
	Ports        IntList `yaml:"ports"`
	AllowPrivate *bool   `yaml:"allow_private"`
	Local        IntList `yaml:"local"`
	SSH          *bool   `yaml:"ssh"`
}

// UnmarshalYAML erlaubt die Kurzform "network: none".
func (n *Network) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		v := node.Value
		n.Mode = &v
		return nil
	}
	type plain Network
	return node.Decode((*plain)(n))
}

type Sockets struct {
	Allow List `yaml:"allow"`
}

type Env struct {
	Mode        *string           `yaml:"mode"`
	Passthrough List              `yaml:"passthrough"`
	Deny        List              `yaml:"deny"`
	Set         map[string]string `yaml:"set"`
}

type Process struct {
	IsolatePids *bool `yaml:"isolate_pids"`
	AllowPtrace *bool `yaml:"allow_ptrace"`
	PrivateTmp  *bool `yaml:"private_tmp"`
}

type Limits struct {
	Timeout      *Duration `yaml:"timeout"`
	KillGrace    *Duration `yaml:"kill_grace"`
	MaxProcesses *int      `yaml:"max_processes"`
	MaxMemory    *Size     `yaml:"max_memory"`
	MaxFileSize  *Size     `yaml:"max_file_size"`
	MaxOpenFiles *int      `yaml:"max_open_files"`
	CPUTime      *Duration `yaml:"cpu_time"`
}

type MacOS struct {
	MachServices List `yaml:"mach_services"`
}

type Linux struct {
	Backend  *string `yaml:"backend"`
	Landlock *string `yaml:"landlock"`
	Seccomp  *string `yaml:"seccomp"`
	Devices  List    `yaml:"devices"`
}

type Integrations struct {
	Clausona *Clausona `yaml:"clausona"`
}

// Profiles ist "active", "all" oder eine Liste von Profilnamen.
type Profiles struct {
	Kind string // active | all | list
	List []string
}

func (p *Profiles) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Value != "active" && n.Value != "all" {
			return &FieldError{Line: n.Line, Msg: fmt.Sprintf("profiles: %q ist weder active, all noch eine Liste", n.Value)}
		}
		p.Kind = n.Value
	case yaml.SequenceNode:
		p.Kind = "list"
		for _, c := range n.Content {
			p.List = append(p.List, c.Value)
		}
	default:
		return &FieldError{Line: n.Line, Msg: "profiles: active, all oder Liste erwartet"}
	}
	return nil
}

// ParseProfiles parst die CLI-Schreibweise ("active", "all", "a,b").
func ParseProfiles(s string) Profiles {
	switch s {
	case "active", "all":
		return Profiles{Kind: s}
	}
	var l []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			l = append(l, p)
		}
	}
	return Profiles{Kind: "list", List: l}
}

type Clausona struct {
	Mode     *string   `yaml:"mode"`
	Profiles *Profiles `yaml:"profiles"`
	GuardMCP *string   `yaml:"guard_mcp"`
	IDE      *bool     `yaml:"ide"`
	Daemons  *string   `yaml:"daemons"`
	Profile  *string   `yaml:"profile"`
}

// UnmarshalYAML erlaubt die Kurzform "clausona: ro".
func (c *Clausona) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode {
		v := node.Value
		c.Mode = &v
		return nil
	}
	type plain Clausona
	return node.Decode((*plain)(c))
}

type Audit struct {
	File    *string `yaml:"file"`
	Format  *string `yaml:"format"`
	Summary *bool   `yaml:"summary"`
}

// FieldError ist ein Fehler mit Zeilenangabe.
type FieldError struct {
	File string
	Line int
	Msg  string
}

func (e *FieldError) Error() string {
	switch {
	case e.File != "" && e.Line > 0:
		return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg)
	case e.File != "":
		return fmt.Sprintf("%s: %s", e.File, e.Msg)
	case e.Line > 0:
		return fmt.Sprintf("Zeile %d: %s", e.Line, e.Msg)
	}
	return e.Msg
}

// Ptr gibt einen Zeiger auf v zurück.
func Ptr[T any](v T) *T { return &v }
