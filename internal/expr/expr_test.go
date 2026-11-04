package expr

import (
	"reflect"
	"strings"
	"testing"
)

func TestUnwrap(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"a == b", "a == b", true},
		{"  ${{ a == b }} ", "a == b", true},
		{"${{ a }} && ${{ b }}", "", false},
		{"${{ a }} && b", "", false},
		{"a && ${{ b }}", "", false},
	}
	for _, c := range cases {
		got, ok := Unwrap(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("Unwrap(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestParseShapes(t *testing.T) {
	cases := []struct {
		src  string
		want Node
	}{
		{"true", &Literal{Kind: LitBool, Text: "true"}},
		{"NULL", &Literal{Kind: LitNull}},
		{"1.5", &Literal{Kind: LitNumber, Text: "1.5"}},
		{"-2", &Literal{Kind: LitNumber, Text: "-2"}},
		{"'it''s'", &Literal{Kind: LitString, Text: "it's"}},
		{"GitHub.Event.Issue", &Ref{Path: []string{"github", "event", "issue"}}},
		{"a.*.name", &Ref{Path: []string{"a", "*", "name"}}},
		{"a['B'].c", &Ref{Path: []string{"a", "b", "c"}}},
		{"a[b]", &Ref{Path: []string{"a", "*"}}},
		{"f().x", &Ref{Path: []string{"*", "x"}, Base: &Call{Name: "f"}}},
		{"!a", &Unary{X: &Ref{Path: []string{"a"}}}},
		{"always()", &Call{Name: "always"}},
		{"Contains(a, 'b')", &Call{Name: "contains", Args: []Node{&Ref{Path: []string{"a"}}, &Literal{Kind: LitString, Text: "b"}}}},
	}
	for _, c := range cases {
		got, err := Parse(c.src)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.src, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Parse(%q) = %#v; want %#v", c.src, got, c.want)
		}
	}
}

func TestParsePrecedence(t *testing.T) {
	n, err := Parse("a || b && c == 'd'")
	if err != nil {
		t.Fatal(err)
	}
	or, ok := n.(*Binary)
	if !ok || or.Op != "||" {
		t.Fatalf("top = %#v; want ||", n)
	}
	and, ok := or.R.(*Binary)
	if !ok || and.Op != "&&" {
		t.Fatalf("right = %#v; want &&", or.R)
	}
	if eq, ok := and.R.(*Binary); !ok || eq.Op != "==" {
		t.Fatalf("right of && = %#v; want ==", and.R)
	}
	if n, err := Parse("(a || b) && !(c < 1) && d >= 2 && e <= 3 && f > 4 && g != 5"); err != nil || n == nil {
		t.Fatalf("parens and comparisons: %v", err)
	}
}

func TestParseErrors(t *testing.T) {
	for _, src := range []string{"", "'open", "a ==", "(a", "a b", "f(a", "f(a b)", "a.", "a.'b'", "a[", "a['b'", "1.2.3", "a # b", "!", "x && ", "(!)", "a[!]", "!!"} {
		if _, err := Parse(src); err == nil {
			t.Errorf("Parse(%q) succeeded; want error", src)
		}
	}
}

func TestFlows(t *testing.T) {
	cases := map[string][]string{
		"a.b":                     {"a.b"},
		"'x'":                     nil,
		"!a":                      nil,
		"a == b":                  nil,
		"a && b":                  {"b"},
		"a || b":                  {"a", "b"},
		"a && b || c":             {"b", "c"},
		"contains(a, 'x')":        nil,
		"startsWith(a, b)":        nil,
		"endsWith(a, b)":          nil,
		"always()":                nil,
		"hashFiles(a)":            nil,
		"format('{0} {1}', a, b)": {"a", "b"},
		"toJSON(a)":               {"a"},
		"fromJSON(a).b":           {"a"},
		"join(a.*.b, ',')":        {"a.*.b"},
	}
	for src, want := range cases {
		n, err := Parse(src)
		if err != nil {
			t.Fatalf("Parse(%q): %v", src, err)
		}
		var got []string
		for _, p := range Flows(n) {
			got = append(got, strings.Join(p, "."))
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Flows(%q) = %v; want %v", src, got, want)
		}
	}
}

func TestParseRefusesAnOverlongExpression(t *testing.T) {
	if _, err := Parse(strings.Repeat("(", maxLength+1)); err == nil {
		t.Error("overlong expression accepted")
	}
	if _, err := Parse(strings.Repeat("(", maxLength)); err == nil {
		t.Error("unbalanced expression accepted")
	}
}
