package envfilter

import (
	"strings"
	"testing"

	"sdbx/internal/policy"
)

var host = []string{
	"PATH=/usr/bin", "HOME=/h", "LC_ALL=de_DE.UTF-8", "AWS_SECRET_ACCESS_KEY=x", "GITHUB_TOKEN=t",
	"MY_API_KEY=k", "GOPATH=/go", "RANDOM_VAR=1", "SSH_AUTH_SOCK=/s", "ANTHROPIC_API_KEY=sk", "SECRET_THING=s",
	"DISPLAY=:0", "npm_config_cache=/c",
}

func TestAllowlist(t *testing.T) {
	r := Build(host, policy.EnvPolicy{Mode: "allowlist", Passthrough: []string{"GOPATH"}}, map[string]string{"SDBX": "1"})
	got := strings.Join(r.Env, " ")
	for _, want := range []string{"PATH=/usr/bin", "HOME=/h", "LC_ALL=de_DE.UTF-8", "GOPATH=/go", "SDBX=1"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s fehlt: %s", want, got)
		}
	}
	for _, bad := range []string{"AWS_", "GITHUB_TOKEN", "RANDOM_VAR", "SSH_AUTH_SOCK", "ANTHROPIC_API_KEY", "DISPLAY"} {
		if strings.Contains(got, bad) {
			t.Errorf("%s darf nicht durchgereicht werden: %s", bad, got)
		}
	}
}

func TestInheritStillDeniesSecrets(t *testing.T) {
	r := Build(host, policy.EnvPolicy{Mode: "inherit", Deny: []string{"SECRET_*"}}, nil)
	got := strings.Join(r.Env, " ")
	if !strings.Contains(got, "RANDOM_VAR=1") || !strings.Contains(got, "npm_config_cache") {
		t.Errorf("inherit übernimmt nicht alles: %s", got)
	}
	for _, bad := range []string{"AWS_SECRET", "GITHUB_TOKEN", "MY_API_KEY", "SECRET_THING", "DISPLAY", "SSH_AUTH_SOCK"} {
		if strings.Contains(got, bad) {
			t.Errorf("%s muss auch bei inherit entfernt werden", bad)
		}
	}
}

func TestExactPassthroughLiftsBuiltinDeny(t *testing.T) {
	r := Build(host, policy.EnvPolicy{Mode: "allowlist", Passthrough: []string{"ANTHROPIC_API_KEY", "*_TOKEN"}}, nil)
	got := strings.Join(r.Env, " ")
	if !strings.Contains(got, "ANTHROPIC_API_KEY=sk") {
		t.Error("exakter passthrough muss eingebaute Sperre aufheben")
	}
	if strings.Contains(got, "GITHUB_TOKEN") {
		t.Error("Glob-passthrough darf eingebaute Sperre nicht aufheben")
	}
	if len(r.Lifted) != 1 || r.Lifted[0] != "ANTHROPIC_API_KEY" {
		t.Errorf("Lifted: %v", r.Lifted)
	}
}

func TestSetAndForced(t *testing.T) {
	r := Build(host, policy.EnvPolicy{Mode: "allowlist", Set: map[string]string{"CI": "true", "HOME": "/override"}},
		map[string]string{"HOME": "/forced"})
	got := strings.Join(r.Env, " ")
	if !strings.Contains(got, "CI=true") || !strings.Contains(got, "HOME=/forced") {
		t.Errorf("set/forced: %s", got)
	}
	if v, _ := Lookup(r.Env, "HOME"); v != "/forced" {
		t.Errorf("Lookup: %s", v)
	}
}
