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

// RunInput is the input a `run:` agent's script is read through.
const RunInput = "run"

// Agent describes one agent action or command-line agent.
type Agent struct {
	ID                 string   `yaml:"id"`
	Uses               []string `yaml:"uses"`
	RunPattern         string   `yaml:"run_pattern"`
	run                *regexp.Regexp
	ActorCheck         bool     `yaml:"actor_check"`
	PowerName          string   `yaml:"power"`
	WildcardInputs     []string `yaml:"wildcard_inputs"`
	BotWildcardInputs  []string `yaml:"bot_wildcard_inputs"`
	FullOutputInputs   []string `yaml:"full_output_inputs"`
	ToolInputs         []string `yaml:"tool_inputs"`
	SettingsInput      string   `yaml:"settings_input"`
	AllowlistInput     string   `yaml:"allowlist_input"`
	AllowSettingsInput string   `yaml:"allow_settings_input"`
	ReadOnlyTools      []string `yaml:"read_only_tools"`
	LimitedWhen        []Match  `yaml:"limited_when"`
	ScopedWhen         []Match  `yaml:"scoped_when"`
	BroadWhen          []Match  `yaml:"broad_when"`
	BroadWhenEnv       []Match  `yaml:"broad_when_env"`
	ScopedWhenEnv      []Match  `yaml:"scoped_when_env"`
	LimitedWhenEnv     []Match  `yaml:"limited_when_env"`
	LimitingDeny       []string `yaml:"limiting_deny"`
	ConfigFiles        []string `yaml:"config_files"`
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
	Agents []*Agent
	// Untrusted matches a whole context path holding attacker-written text.
	Untrusted      *regexp.Regexp
	ExecCommands   map[string]bool
	Authorization  *regexp.Regexp
	Secret         *regexp.Regexp
	UntrustedFetch *regexp.Regexp
	GateOutput     *regexp.Regexp
	ScalarOutput   *regexp.Regexp
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
		Fetch     string   `yaml:"untrusted_fetch_pattern"`
		Gate      string   `yaml:"gate_output_pattern"`
		Scalar    string   `yaml:"scalar_output_pattern"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse registry: %w", err)
	}
	r := &Registry{Agents: raw.Agents, ExecCommands: map[string]bool{}}
	for _, c := range raw.Exec {
		r.ExecCommands[c] = true
	}
	var err error
	if r.Untrusted, err = regexp.Compile(`^(` + strings.Join(raw.Untrusted, "|") + `)$`); err != nil {
		return nil, fmt.Errorf("untrusted_contexts: %w", err)
	}
	if r.Authorization, err = regexp.Compile(raw.Authz); err != nil {
		return nil, fmt.Errorf("authorization_pattern: %w", err)
	}
	if r.Secret, err = regexp.Compile(raw.Secret); err != nil {
		return nil, fmt.Errorf("secret_pattern: %w", err)
	}
	if r.UntrustedFetch, err = regexp.Compile(raw.Fetch); err != nil {
		return nil, fmt.Errorf("untrusted_fetch_pattern: %w", err)
	}
	if r.GateOutput, err = regexp.Compile(raw.Gate); err != nil {
		return nil, fmt.Errorf("gate_output_pattern: %w", err)
	}
	if r.ScalarOutput, err = regexp.Compile(raw.Scalar); err != nil {
		return nil, fmt.Errorf("scalar_output_pattern: %w", err)
	}
	for _, a := range r.Agents {
		if a.RunPattern != "" {
			if a.run, err = regexp.Compile(commandStart + `(?:` + a.RunPattern + `)`); err != nil {
				return nil, fmt.Errorf("agent %s run_pattern: %w", a.ID, err)
			}
		}
		for _, set := range [][]Match{a.LimitedWhen, a.ScopedWhen, a.BroadWhen, a.BroadWhenEnv, a.ScopedWhenEnv, a.LimitedWhenEnv} {
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

// commandStart anchors a run_pattern where a shell starts a command, so a mention
// in an `echo` or a prompt is not an agent. It also skips the wrappers people put
// in front of one.
const commandStart = `(?im)(?:^|[|;&(]|\b(?:if|then|else|do|while|until)\s|!\s)\s*(?:[A-Za-z_]\w*=\S*\s+)*(?:(?:timeout|time|exec|nohup|sudo|env)\s+(?:-\S+\s+)*(?:\d+[smh]?\s+)?)*`

// shellNoise holds what would hide a command or fake one: comments and the
// backslash that continues it on the next line.
var shellNoise = strings.NewReplacer("\\\n", " ")

// FindRun returns the agent a `run:` script starts, nil when none.
func (r *Registry) FindRun(script string) *Agent {
	if script == "" {
		return nil
	}
	var kept []string
	for _, line := range strings.Split(shellNoise.Replace(script), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			kept = append(kept, line)
		}
	}
	text := strings.Join(kept, "\n")
	for _, a := range r.Agents {
		if a.run != nil && a.run.MatchString(text) {
			return a
		}
	}
	return nil
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
