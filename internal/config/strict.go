package config

import (
	"fmt"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

// Typen, die auch als Skalar geschrieben werden dürfen.
var shorthandTypes = map[reflect.Type]bool{
	reflect.TypeOf(Network{}):  true,
	reflect.TypeOf(Clausona{}): true,
}

// Typen mit eigener Validierung im Unmarshaler.
var leafTypes = map[reflect.Type]bool{
	reflect.TypeOf(List{}):     true,
	reflect.TypeOf(IntList{}):  true,
	reflect.TypeOf(Duration{}): true,
	reflect.TypeOf(Size{}):     true,
	reflect.TypeOf(Profiles{}): true,
}

// checkKnown prüft, dass jede Mapping-Taste einem Feld des Zieltyps entspricht.
// yaml.v3 gibt KnownFields nicht an eigene Unmarshaler weiter, daher diese Prüfung.
func checkKnown(n *yaml.Node, t reflect.Type, path string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		return checkKnown(n.Content[0], t, path)
	}
	if n.Kind == yaml.AliasNode {
		return &FieldError{Line: n.Line, Msg: "YAML-Aliase werden nicht unterstützt"}
	}
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		return nil
	}
	if leafTypes[t] {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind == yaml.ScalarNode && shorthandTypes[t] {
			return nil
		}
		if n.Kind != yaml.MappingNode {
			return &FieldError{Line: n.Line, Msg: fmt.Sprintf("%s: Abschnitt erwartet", displayPath(path))}
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
			if tag == "" || tag == "-" {
				continue
			}
			fields[tag] = f.Type
		}
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			ft, ok := fields[k.Value]
			if !ok {
				return &FieldError{Line: k.Line, Msg: fmt.Sprintf("unbekannter Schlüssel %q%s", k.Value, inPath(path))}
			}
			if seen[k.Value] {
				return &FieldError{Line: k.Line, Msg: fmt.Sprintf("Schlüssel %q doppelt%s", k.Value, inPath(path))}
			}
			seen[k.Value] = true
			if err := checkKnown(v, ft, joinPath(path, k.Value)); err != nil {
				return err
			}
		}
	case reflect.Map:
		if n.Kind != yaml.MappingNode {
			return &FieldError{Line: n.Line, Msg: fmt.Sprintf("%s: Zuordnung erwartet", displayPath(path))}
		}
		for i := 1; i < len(n.Content); i += 2 {
			if n.Content[i].Kind != yaml.ScalarNode {
				return &FieldError{Line: n.Content[i].Line, Msg: fmt.Sprintf("%s: nur einfache Werte erlaubt", displayPath(path))}
			}
		}
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			return &FieldError{Line: n.Line, Msg: fmt.Sprintf("%s: Liste erwartet", displayPath(path))}
		}
	default:
		if n.Kind != yaml.ScalarNode {
			return &FieldError{Line: n.Line, Msg: fmt.Sprintf("%s: einfacher Wert erwartet", displayPath(path))}
		}
	}
	return nil
}

func joinPath(a, b string) string {
	if a == "" {
		return b
	}
	return a + "." + b
}

func inPath(p string) string {
	if p == "" {
		return ""
	}
	return " in " + p
}

func displayPath(p string) string {
	if p == "" {
		return "Wurzel"
	}
	return p
}
