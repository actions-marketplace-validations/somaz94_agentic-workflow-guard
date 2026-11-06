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
func WithoutComments(script string) string { return withoutComments(script, true, true) }

// CommentReadings lexes script every way a lexer cannot settle. A `<<` under an open `[`
// is a shift in `a[1<<2]=3` and a here-document in `echo a[ <<EOF`. Inside `$(`, a body
// line `EOF)` ends the body in bash 3.2 and is plain body text in bash 5.
func CommentReadings(script string) []string {
	var out []string
	for _, shifts := range []bool{true, false} {
		for _, midLine := range []bool{true, false} {
			out = append(out, withoutComments(script, shifts, midLine))
		}
	}
	return out
}

func withoutComments(script string, shifts, midLine bool) string {
	var b strings.Builder
	b.Grow(len(script))
	var quote byte
	var open []shellFrame
	var bodies []hereBody
	wordStart, unclosed, bracket := true, false, false
	substs := 0 // open frames with subst set, counted so a newline does not walk the stack
	enter := func(f shellFrame) {
		f.quote = quote
		open = append(open, f)
		quote = 0
		if f.subst {
			substs++
		}
	}
	leave := func() {
		f := open[len(open)-1]
		quote = f.quote
		open = open[:len(open)-1]
		if f.subst {
			substs--
		}
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
		switch c {
		case '[':
			bracket = quote == 0 && (opensSubscript(script[:i]) || wordStart && top().array)
		case ']', '\n':
			bracket = false
		}
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
		case !unclosed && strings.HasPrefix(rest, "${{"):
			// The runner fills this in before any shell reads it. An empty value leaves
			// the next `#` at a word start, so wordStart stays.
			n := templateLen(rest)
			if n == 0 {
				// The runner refuses the file, and scanning again from each `${{` is quadratic.
				unclosed = true
				i--
				continue
			}
			i += n - 1
			b.WriteString(rest[:n])
			continue
		case strings.HasPrefix(rest, "$(("):
			enter(shellFrame{closer: ')', arith: true})
			enter(shellFrame{closer: ')', arith: true})
			i += 2
			b.WriteString("$((")
			wordStart = false
			continue
		case strings.HasPrefix(rest, "$("):
			enter(shellFrame{closer: ')', subst: true})
			i++
			b.WriteString("$(")
			wordStart = true
			continue
		case strings.HasPrefix(rest, "${"):
			enter(shellFrame{closer: '}', arith: top().arith})
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
			enter(shellFrame{closer: '`'})
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
			enter(shellFrame{
				closer: ')',
				arith:  top().arith || wordStart && strings.HasPrefix(rest, "(("),
				subst:  i > 0 && (script[i-1] == '<' || script[i-1] == '>'),
				array:  i > 0 && script[i-1] == '=',
			})
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
		case c == '<' && !top().arith && top().closer != '}' && strings.HasPrefix(rest, "<<") && !(shifts && bracket):
			if body, n := parseHereDoc(rest); n > 0 {
				bodies = append(bodies, body)
				i += n - 1
				b.WriteString(rest[:n])
				wordStart = false
				continue
			}
		case c == '\n' && len(bodies) > 0:
			b.WriteByte(c)
			i = copyHereDocs(&b, script, i+1, bodies, top().closer, midLine && substs > 0) - 1
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
	subst         bool // `$(`, `<(` or `>(`, whose `)` can end a here-document
	array         bool // `=(`, where a `[` at a word start opens a subscript
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

// opensSubscript reports a `[` after `$` or after a name that starts a word. One in a
// string or after other text, as in `tr -d '[' <<EOF`, leaves a `<<` a here-document.
func opensSubscript(s string) bool {
	if strings.HasSuffix(s, "$") {
		return true
	}
	name := strings.TrimRight(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
	if len(name) == len(s) || s[len(name)] >= '0' && s[len(name)] <= '9' {
		return false
	}
	return name == "" || strings.IndexByte(" \t\n;&|(`", name[len(name)-1]) >= 0
}

// hereBody is what ends a here-document, and whether tabs may lead it.
type hereBody struct {
	word   string
	tabs   bool
	quoted bool // no backslash joins its lines
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
			body.quoted = true
			end := strings.IndexByte(s[i+1:], s[i])
			if end < 0 || strings.IndexByte(s[i+1:i+1+end], '\n') >= 0 {
				return hereBody{}, 0
			}
			word.WriteString(s[i+1 : i+1+end])
			i += end + 1
		case '\\':
			body.quoted = true
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
// the body they are no command either. Inside `$(`, a line opening with the word ends
// the body if a `)` follows anywhere on it, what follows the word is shell again, and
// the bodies still pending are never read, as in bash 3.2.
// Inside backticks the shell cuts the string first, so the closing backtick ends it.
func copyHereDocs(b *strings.Builder, script string, pos int, bodies []hereBody, closer byte, inSubst bool) int {
	for _, body := range bodies {
		for pos < len(script) {
			start := pos
			next := len(script)
			if end := strings.IndexByte(script[pos:], '\n'); end >= 0 {
				next = pos + end + 1
			}
			// An unquoted body joins a line ending in a backslash to the next.
			for !body.quoted && next < len(script) && strings.HasSuffix(script[pos:next], "\\\n") && oddBackslashes(script[pos:next-1]) {
				if end := strings.IndexByte(script[next:], '\n'); end >= 0 {
					next += end + 1
				} else {
					next = len(script)
				}
			}
			line := script[pos:next]
			pos = next
			if closer == '`' {
				if j := unescapedBacktick(line); j >= 0 {
					b.WriteString(line[:j])
					return start + j
				}
			}
			text := strings.TrimSuffix(line, "\n")
			if !body.quoted {
				text = strings.ReplaceAll(text, "\\\n", "")
			}
			if body.tabs {
				text = strings.TrimLeft(text, "\t")
			}
			if text == body.word {
				b.WriteString(line)
				break
			}
			if inSubst && strings.HasPrefix(text, body.word) && strings.IndexByte(text[len(body.word):], ')') >= 0 {
				keep := lineOffset(line, len(body.word), body)
				b.WriteString(line[:keep])
				if text[len(body.word)] != ')' {
					b.WriteByte('\n')
				}
				// Reading the pending bodies from here would rescan the line once per body.
				return start + keep
			}
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				line = strings.Repeat("\n", strings.Count(line, "\n"))
			}
			b.WriteString(line)
		}
	}
	return pos
}

// lineOffset maps n bytes of a body line, read with its joins and leading tabs dropped,
// back to an offset in the raw line.
func lineOffset(line string, n int, body hereBody) int {
	i, leading := 0, body.tabs
	for n > 0 && i < len(line) {
		switch {
		case !body.quoted && strings.HasPrefix(line[i:], "\\\n"):
			i += 2
		case leading && line[i] == '\t':
			i++
		default:
			leading = false
			i++
			n--
		}
	}
	return i
}

func oddBackslashes(s string) bool {
	return (len(s)-len(strings.TrimRight(s, "\\")))%2 == 1
}

func unescapedBacktick(s string) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '`':
			return i
		}
	}
	return -1
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
	// A comment the tracking missed can end in a backslash and join the next command
	// to itself, so one reading cuts every comment a shell could see.
	var texts []string
	for _, t := range append(CommentReadings(script), WithoutCommentLines(script), wordComment.ReplaceAllString(script, "$1")) {
		if t = shellNoise.Replace(t); !slices.Contains(texts, t) {
			texts = append(texts, t)
		}
	}
	var out []*Agent
	for _, a := range r.Agents {
		if a.run != nil && slices.ContainsFunc(texts, a.run.MatchString) {
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
