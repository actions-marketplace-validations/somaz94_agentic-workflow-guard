// Package expr parses the GitHub Actions expression language used in `if:`.
package expr

import (
	"fmt"
	"strconv"
	"strings"
)

// Node is a parsed expression.
type Node interface{}

// LitKind is the type of a Literal.
type LitKind int

// Literal kinds.
const (
	LitNull LitKind = iota
	LitBool
	LitNumber
	LitString
)

// Literal is a constant.
type Literal struct {
	Kind LitKind
	Text string
}

// Ref is a context path such as github.event.issue.title. A `*` segment is a
// filter and an index with a non-literal key becomes a `*` segment too. A
// property of a function result has Base set and a path starting with `*`.
type Ref struct {
	Path []string
	Base Node
}

// Unary is `!x`.
type Unary struct {
	X Node
}

// Binary is a comparison or logical operator.
type Binary struct {
	Op   string
	L, R Node
}

// Call is a function call. Name is lower case.
type Call struct {
	Name string
	Args []Node
}

// Flows returns the context paths whose text can reach the value of n. A
// comparison or a test yields a boolean whatever it reads, and `a && b` yields
// b unless a is empty, so neither carries the text it looks at.
func Flows(n Node) [][]string {
	switch x := n.(type) {
	case *Ref:
		if x.Base != nil {
			return Flows(x.Base)
		}
		return [][]string{x.Path}
	case *Binary:
		switch x.Op {
		case "||":
			return append(Flows(x.L), Flows(x.R)...)
		case "&&":
			return Flows(x.R)
		}
	case *Call:
		switch x.Name {
		case "contains", "startswith", "endswith", "always", "success", "failure", "cancelled", "hashfiles":
			return nil
		}
		var out [][]string
		for _, a := range x.Args {
			out = append(out, Flows(a)...)
		}
		return out
	}
	return nil
}

// Unwrap returns the expression inside a value that is exactly one `${{ }}`,
// or the value itself when it holds none. ok is false when `${{ }}` is mixed
// with other text: GitHub renders that to a non-empty string, always truthy.
func Unwrap(src string) (inner string, ok bool) {
	s := strings.TrimSpace(src)
	if !strings.Contains(s, "${{") {
		return s, true
	}
	if !strings.HasPrefix(s, "${{") {
		return "", false
	}
	body := s[3:]
	inString := false
	for i := range len(body) {
		switch {
		case body[i] == '\'':
			inString = !inString
		case inString:
		case strings.HasPrefix(body[i:], "${{"):
			return "", false
		case strings.HasPrefix(body[i:], "}}"):
			// The first `}}` outside a string ends the template, as it does for the runner.
			if i != len(body)-2 {
				return "", false
			}
			return strings.TrimSpace(body[:i]), true
		}
	}
	return "", false
}

// maxLength is the runner's own limit, which also bounds how deep the recursive
// parser and everything walking its result can go on a hostile value.
const maxLength = 21000

// Parse parses one expression, without its `${{ }}` wrapper.
func Parse(src string) (Node, error) {
	if len(src) > maxLength {
		return nil, fmt.Errorf("expression is longer than %d characters", maxLength)
	}
	toks, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{toks: toks}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("unexpected %q at offset %d", p.peek().text, p.peek().pos)
	}
	return n, nil
}

type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokString
	tokNumber
	tokOp
)

type token struct {
	kind tokKind
	text string
	pos  int
}

func lex(s string) ([]token, error) {
	var out []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '\'':
			var b strings.Builder
			j := i + 1
			closed := false
			for j < len(s) {
				if s[j] == '\'' {
					if j+1 < len(s) && s[j+1] == '\'' {
						b.WriteByte('\'')
						j += 2
						continue
					}
					closed = true
					break
				}
				b.WriteByte(s[j])
				j++
			}
			if !closed {
				return nil, fmt.Errorf("unterminated string at offset %d", i)
			}
			out = append(out, token{tokString, b.String(), i})
			i = j + 1
		case c >= '0' && c <= '9' || c == '-' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9':
			j := i + 1
			for j < len(s) && (s[j] >= '0' && s[j] <= '9' || s[j] >= 'a' && s[j] <= 'f' || s[j] >= 'A' && s[j] <= 'F' || s[j] == '.' || s[j] == 'x' || s[j] == 'X') {
				j++
			}
			if !validNumber(s[i:j]) {
				return nil, fmt.Errorf("bad number %q at offset %d", s[i:j], i)
			}
			out = append(out, token{tokNumber, s[i:j], i})
			i = j
		case isIdentStart(c):
			j := i + 1
			for j < len(s) && isIdentPart(s[j]) {
				j++
			}
			out = append(out, token{tokIdent, s[i:j], i})
			i = j
		default:
			if i+1 < len(s) {
				two := s[i : i+2]
				if two == "&&" || two == "||" || two == "==" || two == "!=" || two == "<=" || two == ">=" {
					out = append(out, token{tokOp, two, i})
					i += 2
					continue
				}
			}
			if strings.IndexByte("!<>().,[]*", c) < 0 {
				return nil, fmt.Errorf("unexpected character %q at offset %d", c, i)
			}
			out = append(out, token{tokOp, string(c), i})
			i++
		}
	}
	return append(out, token{tokEOF, "", len(s)}), nil
}

// validNumber accepts what the runner does: decimals, exponents and `0x` hex.
func validNumber(s string) bool {
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return true
	}
	_, err := strconv.ParseInt(s, 0, 64)
	return err == nil
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || c >= '0' && c <= '9' || c == '-'
}

type parser struct {
	toks []token
	pos  int
}

func (p *parser) peek() token { return p.toks[p.pos] }

func (p *parser) next() token {
	t := p.toks[p.pos]
	if t.kind != tokEOF {
		p.pos++
	}
	return t
}

func (p *parser) accept(op string) bool {
	if t := p.peek(); t.kind == tokOp && t.text == op {
		p.pos++
		return true
	}
	return false
}

func (p *parser) expect(op string) error {
	if !p.accept(op) {
		return fmt.Errorf("expected %q at offset %d", op, p.peek().pos)
	}
	return nil
}

func (p *parser) or() (Node, error) {
	return p.leftAssoc(p.and, "||")
}

func (p *parser) and() (Node, error) {
	return p.leftAssoc(p.equality, "&&")
}

func (p *parser) equality() (Node, error) {
	return p.leftAssoc(p.relational, "==", "!=")
}

func (p *parser) relational() (Node, error) {
	return p.leftAssoc(p.unary, "<", "<=", ">", ">=")
}

func (p *parser) leftAssoc(sub func() (Node, error), ops ...string) (Node, error) {
	l, err := sub()
	if err != nil {
		return nil, err
	}
	for {
		matched := ""
		for _, op := range ops {
			if p.accept(op) {
				matched = op
				break
			}
		}
		if matched == "" {
			return l, nil
		}
		r, err := sub()
		if err != nil {
			return nil, err
		}
		l = &Binary{Op: matched, L: l, R: r}
	}
}

func (p *parser) unary() (Node, error) {
	if p.accept("!") {
		x, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &Unary{X: x}, nil
	}
	return p.postfix()
}

func (p *parser) postfix() (Node, error) {
	n, err := p.primary()
	if err != nil {
		return nil, err
	}
	for {
		switch {
		case p.accept("."):
			seg, err := p.segment()
			if err != nil {
				return nil, err
			}
			n = appendRef(n, seg)
		case p.accept("["):
			inner, err := p.or()
			if err != nil {
				return nil, err
			}
			if err := p.expect("]"); err != nil {
				return nil, err
			}
			seg := "*"
			if lit, ok := inner.(*Literal); ok && lit.Kind == LitString {
				seg = lit.Text
			}
			n = appendRef(n, seg)
		default:
			return n, nil
		}
	}
}

func (p *parser) segment() (string, error) {
	if p.accept("*") {
		return "*", nil
	}
	t := p.next()
	if t.kind != tokIdent {
		return "", fmt.Errorf("expected property name at offset %d", t.pos)
	}
	return t.text, nil
}

// appendRef extends a context path; a property of anything else, such as a
// function result, stays an opaque path under `*`.
func appendRef(n Node, seg string) Node {
	if r, ok := n.(*Ref); ok {
		return &Ref{Path: append(r.Path, strings.ToLower(seg)), Base: r.Base}
	}
	return &Ref{Path: []string{"*", strings.ToLower(seg)}, Base: n}
}

func (p *parser) primary() (Node, error) {
	t := p.next()
	switch t.kind {
	case tokString:
		return &Literal{Kind: LitString, Text: t.text}, nil
	case tokNumber:
		return &Literal{Kind: LitNumber, Text: t.text}, nil
	case tokIdent:
		switch strings.ToLower(t.text) {
		case "true", "false":
			return &Literal{Kind: LitBool, Text: strings.ToLower(t.text)}, nil
		case "null":
			return &Literal{Kind: LitNull}, nil
		}
		if p.accept("(") {
			return p.call(strings.ToLower(t.text))
		}
		return &Ref{Path: []string{strings.ToLower(t.text)}}, nil
	case tokOp:
		if t.text == "(" {
			n, err := p.or()
			if err != nil {
				return nil, err
			}
			if err := p.expect(")"); err != nil {
				return nil, err
			}
			return n, nil
		}
	}
	return nil, fmt.Errorf("unexpected %q at offset %d", t.text, t.pos)
}

func (p *parser) call(name string) (Node, error) {
	c := &Call{Name: name}
	if p.accept(")") {
		return c, nil
	}
	for {
		arg, err := p.or()
		if err != nil {
			return nil, err
		}
		c.Args = append(c.Args, arg)
		if p.accept(")") {
			return c, nil
		}
		if err := p.expect(","); err != nil {
			return nil, err
		}
	}
}
