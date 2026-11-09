package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"

	"sdbx/internal/presets"
)

// ProjectFileNames sind veraltete Namen im Workspace; sie werden nur noch gewarnt, nicht geladen.
var ProjectFileNames = []string{"sdbx.yaml", ".sdbx.yaml"}

// MaxIncludeDepth begrenzt verschachtelte Includes.
const MaxIncludeDepth = 8

// Fragment ist eine geladene Quelle (Datei, Preset, Integration, CLI).
type Fragment struct {
	File   *File
	Source string // Anzeigename
	Dir    string // Basis für relative Pfade und ${CONFIG_DIR}
	IsFile bool   // stammt aus einer Datei auf der Platte
}

// Loaded enthält alle Fragmente in Anwendungsreihenfolge, getrennt nach Quelle.
type Loaded struct {
	Global      []Fragment // Includes der globalen Datei, dann die globale Datei
	Project     []Fragment // Includes der Projektdatei, dann die Projektdatei
	ProjectFile string     // leer, wenn keine gefunden
	GlobalFile  string     // leer, wenn keine vorhanden
	Workspace   string     // aufgelöster Workspace (Git-Wurzel bzw. StartDir)
	Files       []string   // alle geladenen Dateien (geschützte Pfade)
	Warnings    []string   // z. B. ignorierte Workspace-sdbx.yaml
}

// LoadOptions steuert die Dateisuche.
type LoadOptions struct {
	ConfigPath  string // --config
	NoGlobal    bool
	StartDir    string // Verzeichnis, ab dem gesucht wird
	Home        string
	GlobalPath  string // überschreibt den Pfad der globalen Datei (Tests)
	ProjectsDir string // überschreibt ~/.config/sdbx/projects (Tests)
}

// ConfigHome liefert das Basisverzeichnis für die Nutzerkonfiguration
// ($XDG_CONFIG_HOME oder <home>/.config). XDG_CONFIG_HOME gilt prozessweit und
// unabhängig vom home-Argument – Tests mit gefälschtem Home müssen es selbst
// auf <home>/.config setzen (siehe IsolateConfigHome).
func ConfigHome(home string) string {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return x
	}
	return filepath.Join(home, ".config")
}

// GlobalConfigPath liefert den Pfad der globalen Nutzerkonfiguration.
func GlobalConfigPath(home string) string {
	return filepath.Join(ConfigHome(home), "sdbx", "config.yaml")
}

// ProjectsDir liefert das Verzeichnis der Projekt-Overrides.
func ProjectsDir(home string) string {
	return filepath.Join(ConfigHome(home), "sdbx", "projects")
}

// FindWorkspace liefert die Git-Wurzel unter start, sonst start selbst.
func FindWorkspace(start, home string) string {
	start = filepath.Clean(start)
	dir := start
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		if home != "" && (dir == filepath.Clean(home) || dir == filepath.Dir(dir)) {
			return start
		}
		if dir == filepath.Dir(dir) {
			return start
		}
		dir = filepath.Dir(dir)
	}
}

// FindLegacyProjectFile sucht eine veraltete sdbx.yaml im Workspace (nur Warnung).
func FindLegacyProjectFile(start, home string) string {
	dir := filepath.Clean(start)
	for {
		for _, n := range ProjectFileNames {
			p := filepath.Join(dir, n)
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
				return p
			}
		}
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return ""
		}
		if home != "" && (dir == filepath.Clean(home) || dir == filepath.Dir(dir)) {
			return ""
		}
		if dir == filepath.Dir(dir) {
			return ""
		}
		dir = filepath.Dir(dir)
	}
}

// FindProjectFile bleibt als Alias für Tests und Aufrufer, die noch den alten Namen nutzen.
// Liefert weiterhin den Legacy-Pfad; Load lädt ihn nicht mehr.
func FindProjectFile(start, home string) string {
	return FindLegacyProjectFile(start, home)
}

// ProjectOf liest das project:-Feld einer Override-Datei als aufgelösten absoluten Pfad.
// Dateien ohne project: (etwa Include-Fragmente) liefern "".
func ProjectOf(path, home string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	f, err := Parse(data, path, filepath.Dir(path))
	if err != nil {
		return "", err
	}
	if f.Project == nil || strings.TrimSpace(*f.Project) == "" {
		return "", nil
	}
	p := ExpandHomeIn(*f.Project, home)
	if !filepath.IsAbs(p) {
		p = filepath.Join(home, p)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		abs = r
	}
	return filepath.Clean(abs), nil
}

// FindProjectOverride sucht unter projectsDir die Datei, deren project: dem Workspace entspricht.
func FindProjectOverride(projectsDir, workspace, home string) (string, error) {
	ents, err := os.ReadDir(projectsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	want := filepath.Clean(workspace)
	if r, err := filepath.EvalSymlinks(want); err == nil {
		want = r
	}
	var matches []string
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(projectsDir, name)
		got, err := ProjectOf(path, home)
		if err != nil {
			return "", err
		}
		if got != "" && got == want {
			matches = append(matches, path)
		}
	}
	switch len(matches) {
	case 0:
		return "", nil
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("mehrere Projekt-Overrides für %s: %s", want, strings.Join(matches, ", "))
	}
}

// ProjectSlug liefert einen Dateinamen-Stamm aus dem Workspace-Pfad.
func ProjectSlug(workspace string) string {
	base := filepath.Base(filepath.Clean(workspace))
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = "project"
	}
	var b strings.Builder
	for _, r := range base {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if s == "" {
		s = "project"
	}
	return s
}

// Load lädt globale Konfiguration und optionalen Projekt-Override samt Includes.
func Load(opt LoadOptions) (*Loaded, error) {
	l := &Loaded{Workspace: FindWorkspace(opt.StartDir, opt.Home)}
	if !opt.NoGlobal {
		gp := opt.GlobalPath
		if gp == "" {
			gp = GlobalConfigPath(opt.Home)
		}
		if _, err := os.Stat(gp); err == nil {
			frags, files, err := loadWithIncludes(gp, "", nil, 0, map[string]bool{})
			if err != nil {
				return nil, err
			}
			l.Global, l.GlobalFile = frags, gp
			l.Files = append(l.Files, files...)
		}
	}

	pf := opt.ConfigPath
	baseDir := "" // Dir für relative Pfade in der Projektdatei
	if pf != "" {
		if !filepath.IsAbs(pf) {
			pf = filepath.Join(opt.StartDir, pf)
		}
		if _, err := os.Stat(pf); err != nil {
			return nil, fmt.Errorf("Konfigurationsdatei %s nicht lesbar: %w", pf, err)
		}
		// Liegt --config unter dem Workspace und heißt wie die Legacy-Datei: Warnung.
		if legacyName(pf) && under(l.Workspace, pf) {
			l.Warnings = append(l.Warnings, fmt.Sprintf("%s liegt im Workspace – Konfiguration dort ist beschreibbar; besser ~/.config/sdbx/projects/", pf))
		}
		baseDir = l.Workspace
		if match, err := ProjectOf(pf, opt.Home); err == nil && match != "" {
			l.Workspace = match
			baseDir = match
		}
	} else {
		pdir := opt.ProjectsDir
		if pdir == "" {
			pdir = ProjectsDir(opt.Home)
		}
		var err error
		pf, err = FindProjectOverride(pdir, l.Workspace, opt.Home)
		if err != nil {
			return nil, err
		}
		baseDir = l.Workspace
		if legacy := FindLegacyProjectFile(opt.StartDir, opt.Home); legacy != "" {
			l.Warnings = append(l.Warnings, fmt.Sprintf("%s wird ignoriert – Projektregeln liegen unter %s", legacy, pdir))
		}
	}
	if pf != "" {
		frags, files, err := loadWithIncludes(pf, baseDir, nil, 0, map[string]bool{})
		if err != nil {
			return nil, err
		}
		l.Project, l.ProjectFile = frags, pf
		l.Files = append(l.Files, files...)
	}
	return l, nil
}

func legacyName(path string) bool {
	base := filepath.Base(path)
	for _, n := range ProjectFileNames {
		if base == n {
			return true
		}
	}
	return false
}

func under(root, path string) bool {
	r := filepath.Clean(root)
	p := filepath.Clean(path)
	return p == r || strings.HasPrefix(p, r+string(filepath.Separator))
}

// loadWithIncludes lädt eine Datei und davor ihre Includes (rekursiv).
// pathBase ist die Basis für relative Pfade in Listeneinträgen (Workspace bei Projekt-Overrides);
// leer = Verzeichnis der Datei.
func loadWithIncludes(path, pathBase string, stack []string, depth int, loaded map[string]bool) ([]Fragment, []string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, nil, err
	}
	for _, s := range stack {
		if s == abs {
			return nil, nil, fmt.Errorf("Include-Zyklus: %s", strings.Join(append(stack, abs), " → "))
		}
	}
	if depth > MaxIncludeDepth {
		return nil, nil, fmt.Errorf("%s: Includes zu tief verschachtelt (maximal %d)", abs, MaxIncludeDepth)
	}
	if loaded[abs] {
		return nil, nil, nil
	}
	loaded[abs] = true
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", abs, err)
	}
	fileDir := filepath.Dir(abs)
	dir := pathBase
	if dir == "" {
		dir = fileDir
	}
	f, err := Parse(data, abs, dir)
	if err != nil {
		return nil, nil, err
	}
	var frags []Fragment
	files := []string{abs}
	for _, inc := range f.Include {
		name := inc.Value
		if isPresetName(name) {
			pf, err := LoadPreset(name)
			if err != nil {
				return nil, nil, &FieldError{File: abs, Line: inc.Origin.Line, Msg: err.Error()}
			}
			if !loaded["preset:"+name] {
				loaded["preset:"+name] = true
				frags = append(frags, pf)
			}
			continue
		}
		p := ExpandHomeOnly(name)
		if !filepath.IsAbs(p) {
			p = filepath.Join(fileDir, p)
		}
		sub, subFiles, err := loadWithIncludes(p, pathBase, append(stack, abs), depth+1, loaded)
		if err != nil {
			var fe *FieldError
			if errors.As(err, &fe) {
				return nil, nil, err
			}
			return nil, nil, &FieldError{File: abs, Line: inc.Origin.Line, Msg: err.Error()}
		}
		frags = append(frags, sub...)
		files = append(files, subFiles...)
	}
	frags = append(frags, Fragment{File: f, Source: abs, Dir: dir, IsFile: true})
	return frags, files, nil
}

func isPresetName(s string) bool {
	return s != "" && !strings.ContainsAny(s, `/\.~`)
}

// LoadPreset lädt ein eingebautes Preset.
func LoadPreset(name string) (Fragment, error) {
	data, ok := presets.Get(name)
	if !ok {
		return Fragment{}, fmt.Errorf("unbekanntes Preset %q (verfügbar: %s)", name, strings.Join(presets.Names(), ", "))
	}
	src := "preset:" + name
	f, err := Parse(data, src, "")
	if err != nil {
		return Fragment{}, err
	}
	if len(f.Include) > 0 {
		return Fragment{}, fmt.Errorf("Preset %s darf keine Includes enthalten", name)
	}
	return Fragment{File: f, Source: src}, nil
}

// Parse dekodiert eine Konfigurationsdatei streng und setzt die Herkunft aller Listeneinträge.
func Parse(data []byte, source, dir string) (*File, error) {
	var root yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&root); err != nil {
		if err.Error() == "EOF" {
			return nil, &FieldError{File: source, Msg: "Datei ist leer (mindestens \"version: 1\" angeben)"}
		}
		return nil, &FieldError{File: source, Msg: "YAML-Fehler: " + strings.TrimPrefix(err.Error(), "yaml: ")}
	}
	if err := checkKnown(&root, reflect.TypeOf(File{}), ""); err != nil {
		return nil, withFile(err, source)
	}
	var f File
	if err := root.Decode(&f); err != nil {
		var fe *FieldError
		if errors.As(err, &fe) {
			return nil, withFile(fe, source)
		}
		return nil, &FieldError{File: source, Msg: strings.TrimPrefix(err.Error(), "yaml: ")}
	}
	if f.Version == nil {
		return nil, &FieldError{File: source, Msg: "\"version: 1\" fehlt"}
	}
	if *f.Version != 1 {
		return nil, &FieldError{File: source, Msg: fmt.Sprintf("version %d wird nicht unterstützt (erwartet: 1)", *f.Version)}
	}
	Stamp(&f, Origin{Source: source}, dir)
	if err := Validate(&f); err != nil {
		return nil, withFile(err, source)
	}
	return &f, nil
}

func withFile(err error, file string) error {
	var fe *FieldError
	if errors.As(err, &fe) {
		c := *fe
		c.File = file
		return &c
	}
	return &FieldError{File: file, Msg: err.Error()}
}

// Stamp setzt Quelle und Basisverzeichnis für alle Listeneinträge eines Fragments.
func Stamp(f *File, o Origin, dir string) {
	stampValue(reflect.ValueOf(f).Elem(), o, dir)
}

var listType = reflect.TypeOf(List{})

func stampValue(v reflect.Value, o Origin, dir string) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			stampValue(v.Elem(), o, dir)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				stampValue(v.Field(i), o, dir)
			}
		}
	case reflect.Slice:
		if v.Type() == listType {
			for i := 0; i < v.Len(); i++ {
				it := v.Index(i).Addr().Interface().(*Item)
				line := it.Origin.Line
				if line == 0 {
					line = o.Line
				}
				it.Origin = Origin{Source: o.Source, Line: line, Dir: dir}
			}
		}
	}
}

// ExpandHomeOnly ersetzt ein führendes ~ durch $HOME.
func ExpandHomeOnly(p string) string {
	h, _ := os.UserHomeDir()
	return ExpandHomeIn(p, h)
}

// ExpandHomeIn ersetzt ein führendes ~ durch home.
func ExpandHomeIn(p, home string) string {
	if home != "" && (p == "~" || strings.HasPrefix(p, "~/")) {
		return home + p[1:]
	}
	return p
}
