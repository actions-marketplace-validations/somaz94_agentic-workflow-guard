// Package registry holds the agent action catalog, embedded from agents.yaml.
package registry

import (
	_ "embed" // agents.yaml
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
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
	for _, p := range []struct {
		key, src string
		dst      **regexp.Regexp
	}{
		{"untrusted_contexts", `^(` + strings.Join(raw.Untrusted, "|") + `)$`, &r.Untrusted},
		{"exec_argument_pattern", raw.ExecArgs, &r.ExecArguments},
		{"authorization_pattern", raw.Authz, &r.Authorization},
		{"secret_pattern", raw.Secret, &r.Secret},
		{"untrusted_fetch_pattern", raw.Fetch, &r.UntrustedFetch},
		{"gate_output_pattern", raw.Gate, &r.GateOutput},
		{"scalar_output_pattern", raw.Scalar, &r.ScalarOutput},
	} {
		if *p.dst, err = regexp.Compile(p.src); err != nil {
			return nil, fmt.Errorf("%s: %w", p.key, err)
		}
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

// wordComment is a `#` at a word start through its line end, whatever the quotes.
var wordComment = regexp.MustCompile(`(?m)(^|[ \t;&|()\x60])#.*$`)

// shellNoise is the backslash that continues a command on the next line.
var shellNoise = strings.NewReplacer("\\\n", " ")

// WithoutComments blanks shell comments, on their own line or after a command. A `#`
// in a string, an expansion, arithmetic or a here-document is text, so it follows
// each of them. Newlines stay, so a continuation before a comment cannot swallow the
// command after it.
func WithoutComments(script string) string {
	var b strings.Builder
	b.Grow(len(script))
	var quote byte
	var open []shellFrame
	var bodies []hereBody
	wordStart := true
	enter := func(closer byte, arith bool) {
		open = append(open, shellFrame{quote, closer, arith})
		quote = 0
	}
	leave := func() {
		quote = open[len(open)-1].quote
		open = open[:len(open)-1]
	}
	top := func() shellFrame {
		if len(open) == 0 {
			return shellFrame{}
		}
		return open[len(open)-1]
	}
	for i := 0; i < len(script); i++ {
		c := script[i]
		rest := script[i:]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case quote == ansiQuote:
			if c == '\\' && i+1 < len(script) {
				i++
				b.WriteByte(c)
				c = script[i]
			} else if c == '\'' {
				quote = 0
			}
		case c == '\\' && i+1 < len(script):
			i++
			b.WriteByte(c)
			b.WriteByte(script[i])
			wordStart = wordStart && script[i] == '\n'
			continue
		case strings.HasPrefix(rest, "${{") && templateLen(rest) > 0:
			// The runner fills this in before any shell reads it.
			n := templateLen(rest)
			i += n - 1
			b.WriteString(rest[:n])
			wordStart = false
			continue
		case strings.HasPrefix(rest, "$(("):
			enter(')', true)
			enter(')', true)
			i += 2
			b.WriteString("$((")
			wordStart = false
			continue
		case strings.HasPrefix(rest, "$("):
			enter(')', false)
			i++
			b.WriteString("$(")
			wordStart = true
			continue
		case strings.HasPrefix(rest, "${"):
			enter('}', top().arith)
			i++
			b.WriteString("${")
			wordStart = false
			continue
		case quote == 0 && strings.HasPrefix(rest, "$'"):
			quote = ansiQuote
			i++
			b.WriteString("$'")
			wordStart = false
			continue
		case c == '`':
			if top().closer == '`' {
				leave()
				b.WriteByte(c)
				wordStart = false
				continue
			}
			enter('`', false)
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '}' && top().closer == '}':
			leave()
		case c == '\'' && top().closer == '}' && top().quote == '"':
			// Inside `"${x:-'}"` the quote is a plain character.
		case c == '\'' || c == '"':
			quote = c
		case c == '(' && top().closer != '}':
			enter(')', top().arith || wordStart && strings.HasPrefix(rest, "(("))
		case c == ')' && top().closer == ')':
			leave()
		case c == '#' && wordStart && top().closer != '}':
			stops := "\n"
			if top().closer == '`' {
				stops = "\n`"
			}
			end := strings.IndexAny(rest, stops)
			if end < 0 {
				return b.String()
			}
			i += end - 1
			continue
		case strings.HasPrefix(rest, "<<<"):
			i += 2
			b.WriteString("<<<")
			wordStart = true
			continue
		case c == '<' && !top().arith && top().closer != '}' && strings.HasPrefix(rest, "<<") && !inSubscript(script[:i]):
			if body, n := parseHereDoc(rest); n > 0 {
				bodies = append(bodies, body)
				i += n - 1
				b.WriteString(rest[:n])
				wordStart = false
				continue
			}
		case c == '\n' && len(bodies) > 0:
			b.WriteByte(c)
			i = copyHereDocs(&b, script, i+1, bodies, top().closer == ')') - 1
			bodies = nil
			wordStart = true
			continue
		}
		b.WriteByte(c)
		wordStart = quote == 0 && strings.IndexByte(" \t\n;&|()`", c) >= 0
	}
	return b.String()
}

// ansiQuote is the state inside `$'...'`, where a backslash can escape the quote.
const ansiQuote = '$'

// shellFrame is one open `(`, `$(`, `${` or backtick, and the quote to return to.
type shellFrame struct {
	quote, closer byte
	arith         bool // a `<<` in it shifts bits
}

// templateLen is the length of the `${{ }}` at the start of s, 0 when it never ends.
func templateLen(s string) int {
	inString := false
	for i := 3; i+1 < len(s); i++ {
		if s[i] == '\'' {
			inString = !inString
		} else if !inString && s[i] == '}' && s[i+1] == '}' {
			return i + 2
		}
	}
	return 0
}

// inSubscript reports a `[` still open just before the end of s, as in `a[1<<2]=3` or
// `$[1<<2]`, where `<<` shifts bits. Only a short stretch is read, so a script of
// shifts stays linear.
func inSubscript(s string) bool {
	s = s[max(len(s)-64, 0):]
	open := strings.LastIndexByte(s, '[')
	return open > strings.LastIndexByte(s, ']') && open > strings.LastIndexByte(s, '\n')
}

// hereBody is what ends a here-document, and whether tabs may lead it.
type hereBody struct {
	word string
	tabs bool
}

// parseHereDoc reads the `<<` at the start of s. Its word loses its quotes, as the
// shell's does, so `<<E"O"F` ends at EOF. It returns how much it read, 0 for no word.
func parseHereDoc(s string) (hereBody, int) {
	i := 2
	var body hereBody
	if i < len(s) && s[i] == '-' {
		body.tabs = true
		i++
	}
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	var word strings.Builder
	start := i
	for ; i < len(s) && strings.IndexByte(" \t\n;&|()<>", s[i]) < 0; i++ {
		switch s[i] {
		case '\'', '"':
			end := strings.IndexByte(s[i+1:], s[i])
			if end < 0 || strings.IndexByte(s[i+1:i+1+end], '\n') >= 0 {
				return hereBody{}, 0
			}
			word.WriteString(s[i+1 : i+1+end])
			i += end + 1
		case '\\':
			if i+1 < len(s) {
				i++
			}
			word.WriteByte(s[i])
		default:
			word.WriteByte(s[i])
		}
	}
	if i == start {
		return hereBody{}, 0
	}
	body.word = word.String()
	return body, i
}

// copyHereDocs writes each body through its terminator and returns where it ended.
// Its `#` lines go: `bash <<EOF` runs them as comments, and to any other reader of
// the body they are no command either.
func copyHereDocs(b *strings.Builder, script string, pos int, bodies []hereBody, inSubst bool) int {
	for _, body := range bodies {
		for pos < len(script) {
			end := strings.IndexByte(script[pos:], '\n')
			next := len(script)
			if end >= 0 {
				next = pos + end + 1
			}
			line := script[pos:next]
			pos = next
			text := strings.TrimSuffix(line, "\n")
			if body.tabs {
				text = strings.TrimLeft(text, "\t")
			}
			if text == body.word {
				b.WriteString(line)
				break
			}
			// `$(cat <<EOF` can close on `EOF)`, which ends both.
			if inSubst && strings.HasPrefix(text, body.word+")") {
				keep := len(strings.TrimSuffix(line, "\n")) - len(text) + len(body.word)
				b.WriteString(line[:keep])
				return next - len(line) + keep
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
	// A comment the tracking missed can end in a backslash and join the next command
	// to itself, so one reading cuts every comment a shell could see.
	cut := shellNoise.Replace(wordComment.ReplaceAllString(script, "$1"))
	var out []*Agent
	for _, a := range r.Agents {
		if a.run != nil && (a.run.MatchString(text) || plain != text && a.run.MatchString(plain) || cut != text && a.run.MatchString(cut)) {
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
		if slices.Contains(a.Uses, name) {
			return a
		}
	}
	return nil
}
