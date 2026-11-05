// Package registry holds the agent action catalog, embedded from agents.yaml.
package registry

import (
	_ "embed" // agents.yaml
	"encoding/json"
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

var lineComment = regexp.MustCompile(`(?m)^\s*//.*$`)

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
	ConfigKey          string   `yaml:"config_key"`
	ConfigPattern      string   `yaml:"config_pattern"`
	config             *regexp.Regexp
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
	ExecArguments  *regexp.Regexp
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
		ExecArgs  string   `yaml:"exec_argument_pattern"`
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
	if r.ExecArguments, err = regexp.Compile(raw.ExecArgs); err != nil {
		return nil, fmt.Errorf("exec_argument_pattern: %w", err)
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
		if a.ConfigPattern != "" {
			if a.config, err = regexp.Compile(a.ConfigPattern); err != nil {
				return nil, fmt.Errorf("agent %s config_pattern: %w", a.ID, err)
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
const commandStart = `(?im)(?:^|[|;&(\x60]|\b(?:if|then|else|do|while|until)\s|!\s)\s*` + shellAssign + `*(?:(?:[\w./-]*/)?(?:timeout|time|exec|nohup|sudo|env)\s+(?:-\S+\s+(?:[a-z]\w*\s+)?)*(?:\d+[smh]?\s+)?` + shellAssign + `*)*(?:(?:ba|z)?sh\s+-\w*c\s+["']?)?(?:[\w$.{}~/-]*/)?`

const shellAssign = `(?:[A-Za-z_]\w*=(?:"[^"]*"|'[^']*'|\S*)\s+)`

// shellNoise is the backslash that continues a command on the next line.
var shellNoise = strings.NewReplacer("\\\n", " ")

// hereDoc matches a here-document's opening, whose body runs to a line holding its word.
var hereDoc = regexp.MustCompile(`^<<(-?)[ \t]*(?:'([^'\n]+)'|"([^"\n]+)"|\\?([\w.-]+))`)

// WithoutComments blanks shell comments, on their own line or after a command. A `#`
// in a string or a here-document is text, so it follows both. Newlines stay, so a
// continuation before a comment cannot swallow the command after it.
func WithoutComments(script string) string {
	var b strings.Builder
	b.Grow(len(script))
	var quote byte
	var nested []byte // the quote to return to at each open `(`
	var bodies []string
	wordStart := true
	for i := 0; i < len(script); i++ {
		c := script[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\' && i+1 < len(script):
			i++
			b.WriteByte(c)
			b.WriteByte(script[i])
			wordStart = wordStart && script[i] == '\n'
			continue
		case c == '$' && strings.HasPrefix(script[i:], "$("):
			nested = append(nested, quote)
			quote = 0
			i++
			b.WriteString("$(")
			wordStart = true
			continue
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '(':
			nested = append(nested, 0)
		case c == ')' && len(nested) > 0:
			quote = nested[len(nested)-1]
			nested = nested[:len(nested)-1]
		case c == '#' && wordStart:
			end := strings.IndexByte(script[i:], '\n')
			if end < 0 {
				return b.String()
			}
			i += end - 1
			continue
		case strings.HasPrefix(script[i:], "<<<"):
			i += 2
			b.WriteString("<<<")
			wordStart = true
			continue
		case c == '<':
			if m := hereDoc.FindStringSubmatch(script[i:]); m != nil {
				bodies = append(bodies, m[1]+m[2]+m[3]+m[4])
				i += len(m[0]) - 1
				b.WriteString(m[0])
				wordStart = false
				continue
			}
		case c == '\n' && len(bodies) > 0:
			b.WriteByte(c)
			i = copyHereDocs(&b, script, i+1, bodies) - 1
			bodies = nil
			wordStart = true
			continue
		}
		b.WriteByte(c)
		wordStart = quote == 0 && strings.IndexByte(" \t\n;&|()", c) >= 0
	}
	return b.String()
}

// copyHereDocs writes each body through its terminator and returns where it ended.
// Its `#` lines go: `bash <<EOF` runs them as comments, and to any other reader of
// the body they are no command either. A word opens `-` when tabs may lead its end.
func copyHereDocs(b *strings.Builder, script string, pos int, words []string) int {
	for _, word := range words {
		word, tabs := strings.CutPrefix(word, "-")
		for pos < len(script) {
			end := strings.IndexByte(script[pos:], '\n')
			next := len(script)
			if end >= 0 {
				next = pos + end + 1
			}
			line := script[pos:next]
			pos = next
			text := strings.TrimSuffix(line, "\n")
			if tabs {
				text = strings.TrimLeft(text, "\t")
			}
			if text == word {
				b.WriteString(line)
				break
			}
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				line = line[len(strings.TrimSuffix(line, "\n")):]
			}
			b.WriteString(line)
		}
	}
	return pos
}

// WithoutCommentLines blanks only lines that are wholly a comment.
func WithoutCommentLines(script string) string {
	lines := strings.Split(script, "\n")
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			lines[i] = ""
		}
	}
	return strings.Join(lines, "\n")
}

// NarrowedBy reports whether a committed config restricts what the agent can run.
// Only the top-level key applies: the same words under another key, or in a comment,
// say nothing about this run, and a file that does not parse restricts nothing.
func (a *Agent) NarrowedBy(data []byte) bool {
	if a.config == nil {
		return false
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(lineComment.ReplaceAll(data, nil), &doc) != nil {
		return false
	}
	return a.config.Match(doc[a.ConfigKey])
}

// FindRuns returns every agent a `run:` script starts. One script can start several
// with different powers, and the worst of them decides.
func (r *Registry) FindRuns(script string) []*Agent {
	if script == "" {
		return nil
	}
	// Comments first: the shell ends one at its newline, even after a backslash. A
	// script built to fool the quote tracking must not hide an agent, so the plainer
	// reading counts too.
	text := shellNoise.Replace(WithoutComments(script))
	plain := shellNoise.Replace(WithoutCommentLines(script))
	var out []*Agent
	for _, a := range r.Agents {
		if a.run != nil && (a.run.MatchString(text) || plain != text && a.run.MatchString(plain)) {
			out = append(out, a)
		}
	}
	return out
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
