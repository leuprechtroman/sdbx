// Package envfilter baut die Umgebung des Zielprozesses (Spec 7.2).
package envfilter

import (
	"path"
	"sort"
	"strings"

	"sdbx/internal/policy"
)

func match(pattern, name string) bool {
	ok, _ := path.Match(strings.ToUpper(pattern), strings.ToUpper(name))
	return ok
}

func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if match(p, name) {
			return true
		}
	}
	return false
}

func exactIn(list []string, name string) bool {
	for _, p := range list {
		if !strings.ContainsAny(p, "*?[") && strings.EqualFold(p, name) {
			return true
		}
	}
	return false
}

// Result enthält die Umgebung und entfernte Variablen (für das Audit-Log).
type Result struct {
	Env     []string
	Removed []string
	Lifted  []string // eingebaute Sperren, die durch exakte passthrough-Einträge aufgehoben wurden
}

// Build filtert host nach der Policy und setzt danach forced (überschreibt alles).
func Build(host []string, p policy.EnvPolicy, forced map[string]string) Result {
	var r Result
	vals := map[string]string{}
	for _, kv := range host {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		keep := p.Mode == "inherit" || matchAny(policy.BaseEnvAllowlist, k) || matchAny(p.Passthrough, k)
		if !keep {
			r.Removed = append(r.Removed, k)
			continue
		}
		if matchAny(p.Deny, k) {
			r.Removed = append(r.Removed, k)
			continue
		}
		if matchAny(policy.BaseEnvDeny, k) {
			if exactIn(p.Passthrough, k) {
				r.Lifted = append(r.Lifted, k)
			} else {
				r.Removed = append(r.Removed, k)
				continue
			}
		}
		vals[k] = v
	}
	for k, v := range p.Set {
		vals[k] = v
	}
	for k, v := range forced {
		vals[k] = v
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		r.Env = append(r.Env, k+"="+vals[k])
	}
	sort.Strings(r.Removed)
	return r
}

// Lookup liefert den Wert einer Variablen aus einer Umgebungsliste.
func Lookup(env []string, key string) (string, bool) {
	for i := len(env) - 1; i >= 0; i-- {
		k, v, _ := strings.Cut(env[i], "=")
		if k == key {
			return v, true
		}
	}
	return "", false
}
