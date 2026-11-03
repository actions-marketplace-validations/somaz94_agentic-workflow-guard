// Package registry holds the agent action catalog, embedded from agents.yaml.
package registry

import (
	_ "embed" // agents.yaml
	"fmt"
	"regexp"
	"strings"

	"go.yaml.in/yaml/v3"
)

//go:embed agents.yaml
var agentsYAML []byte

// Power is what an agent can do once its prompt is under an attacker's control.
type Power int

const (
	// Limited agents return text, or run with read-only access.
	Limited Power = iota
	// Scoped agents hold tools behind an allowlist or an approval step.
	Scoped
	// Broad agents can run arbitrary commands.
	Broad
)

// Match is one input pattern.
type Match struct {
	Input   string `yaml:"input"`
	Pattern string `yaml:"pattern"`
	re      *regexp.Regexp
}

// Matches reports whether the value matches.
func (m Match) Matches(v string) bool { return m.re.MatchString(v) }

// Agent describes one agent action.
type Agent struct {
	ID                string   `yaml:"id"`
	Uses              []string `yaml:"uses"`
	ActorCheck        bool     `yaml:"actor_check"`
	PowerName         string   `yaml:"power"`
	WildcardInputs    []string `yaml:"wildcard_inputs"`
	BotWildcardInputs []string `yaml:"bot_wildcard_inputs"`
	FullOutputInputs  []string `yaml:"full_output_inputs"`
	ToolInputs        []string `yaml:"tool_inputs"`
	SettingsInput     string   `yaml:"settings_input"`
	LimitedWhen       []Match  `yaml:"limited_when"`
	BroadWhen         []Match  `yaml:"broad_when"`
	BroadWhenEnv      []Match  `yaml:"broad_when_env"`
}

// DefaultPower is the agent's capability before its inputs are read.
func (a *Agent) DefaultPower() Power {
	switch a.PowerName {
	case "limited":
		return Limited
	case "broad":
		return Broad
	}
	return Scoped
}

// Registry is the loaded catalog.
type Registry struct {
	Agents        []*Agent
	Untrusted     *regexp.Regexp
	ExecCommands  map[string]bool
	Authorization *regexp.Regexp
	Secret        *regexp.Regexp
}

// Load parses the embedded catalog.
func Load() (*Registry, error) {
	return parse(agentsYAML)
}

func parse(data []byte) (*Registry, error) {
	var raw struct {
		Agents    []*Agent `yaml:"agents"`
		Untrusted []string `yaml:"untrusted_contexts"`
		Exec      []string `yaml:"exec_equivalent_commands"`
		Authz     string   `yaml:"authorization_pattern"`
		Secret    string   `yaml:"secret_pattern"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse registry: %w", err)
	}
	r := &Registry{Agents: raw.Agents, ExecCommands: map[string]bool{}}
	for _, c := range raw.Exec {
		r.ExecCommands[c] = true
	}
	var err error
	if r.Untrusted, err = regexp.Compile(`\$\{\{(?:[^}]|\}[^}])*?\b(` + strings.Join(raw.Untrusted, "|") + `)\b(?:[^}]|\}[^}])*?\}\}`); err != nil {
		return nil, fmt.Errorf("untrusted_contexts: %w", err)
	}
	if r.Authorization, err = regexp.Compile(raw.Authz); err != nil {
		return nil, fmt.Errorf("authorization_pattern: %w", err)
	}
	if r.Secret, err = regexp.Compile(raw.Secret); err != nil {
		return nil, fmt.Errorf("secret_pattern: %w", err)
	}
	for _, a := range r.Agents {
		for _, set := range [][]Match{a.LimitedWhen, a.BroadWhen, a.BroadWhenEnv} {
			for i := range set {
				re, err := regexp.Compile("(?i)" + set[i].Pattern)
				if err != nil {
					return nil, fmt.Errorf("agent %s input %s: %w", a.ID, set[i].Input, err)
				}
				set[i].re = re
			}
		}
	}
	return r, nil
}

// Find returns the agent behind a `uses:` value, ignoring its ref and subpath.
func (r *Registry) Find(uses string) *Agent {
	base, _, _ := strings.Cut(uses, "@")
	parts := strings.Split(base, "/")
	if len(parts) < 2 {
		return nil
	}
	name := strings.ToLower(parts[0] + "/" + parts[1])
	for _, a := range r.Agents {
		for _, u := range a.Uses {
			if u == name {
				return a
			}
		}
	}
	return nil
}
