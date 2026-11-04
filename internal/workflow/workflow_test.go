package workflow

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const sample = `name: t
on:
  issues:
    types: [opened, edited]
  issue_comment:
  push:
    branches: [main]
permissions:
  contents: read
env:
  TOP: a
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
  agent:
    needs: gate
    if: github.actor == 'a'
    permissions:
      issues: write
      contents: read
    env:
      J: b
    steps:
      - uses: actions/checkout@v7
        with:
          ref: main
      - name: not-a-scalar
        id: the-id
        uses: o/a@v1
        if: always()
        with:
          nested: {a: b}
          plain: 'x'
        env:
          S: c
      - scalar-step
  called:
    needs: [gate, agent]
    uses: ./.github/workflows/x.yml
  odd: nope
`

func TestParse(t *testing.T) {
	w, err := Parse([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(w.Triggers["issues"], []string{"opened", "edited"}) {
		t.Errorf("issues types = %v", w.Triggers["issues"])
	}
	if _, ok := w.Triggers["issue_comment"]; !ok {
		t.Error("issue_comment missing")
	}
	if w.Permissions.Set != true || len(w.Permissions.Writes) != 0 {
		t.Errorf("top permissions = %+v", w.Permissions)
	}
	if w.Env["TOP"].Value != "a" {
		t.Errorf("env = %+v", w.Env)
	}
	if len(w.Jobs) != 3 {
		t.Fatalf("jobs = %d; want 3, the scalar job dropped", len(w.Jobs))
	}
	a := w.JobByName("agent")
	if a == nil || a.If != "github.actor == 'a'" || !reflect.DeepEqual(a.Needs, []string{"gate"}) {
		t.Fatalf("agent = %+v", a)
	}
	if !reflect.DeepEqual(a.Permissions.Writes, []string{"issues"}) || a.Env["J"].Value != "b" {
		t.Errorf("agent permissions/env = %+v %+v", a.Permissions, a.Env)
	}
	if len(a.Steps) != 2 {
		t.Fatalf("steps = %d; want 2, the scalar step dropped", len(a.Steps))
	}
	s := a.Steps[1]
	if s.ID != "the-id" || s.Name != "not-a-scalar" || s.Uses != "o/a@v1" || s.If != "always()" || s.Line != 29 || s.Env["S"].Value != "c" {
		t.Errorf("step = %+v", s)
	}
	if s.With["plain"].Line != 35 || s.With["nested"].Value == "" {
		t.Errorf("with = %+v", s.With)
	}
	if w.JobByName("missing") != nil {
		t.Error("JobByName must return nil for a missing job")
	}
	if c := w.JobByName("called"); len(c.Needs) != 2 || len(c.Steps) != 0 {
		t.Errorf("called = %+v", c)
	}
}

func TestTriggerForms(t *testing.T) {
	cases := map[string][]string{
		"on: issues\njobs: {}\n":         {"issues"},
		"on: [issues, push]\njobs: {}\n": {"issues", "push"},
		"jobs: {}\n":                     {},
	}
	for src, want := range cases {
		w, err := Parse([]byte(src))
		if err != nil {
			t.Fatalf("%q: %v", src, err)
		}
		if len(w.Triggers) != len(want) {
			t.Errorf("%q triggers = %v", src, w.Triggers)
		}
		for _, e := range want {
			if _, ok := w.Triggers[e]; !ok {
				t.Errorf("%q missing %s", src, e)
			}
		}
	}
}

func TestPermissionForms(t *testing.T) {
	cases := []struct {
		src  string
		want Permissions
	}{
		{"on: push\n", Permissions{}},
		{"on: push\npermissions: write-all\n", Permissions{Set: true, Writes: []string{"*"}}},
		{"on: push\npermissions: read-all\n", Permissions{Set: true}},
		{"on: push\npermissions: {}\n", Permissions{Set: true}},
		{"on: push\npermissions: {issues: write, actions: write, contents: read}\n", Permissions{Set: true, Writes: []string{"actions", "issues"}}},
	}
	for _, c := range cases {
		w, err := Parse([]byte(c.src))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(w.Permissions, c.want) {
			t.Errorf("%q = %+v; want %+v", c.src, w.Permissions, c.want)
		}
	}
}

func TestParseAliases(t *testing.T) {
	src := `on: push
x-env: &e
  A: b
env: *e
jobs:
  j:
    needs: [1, a]
    steps:
      - uses: a/b@v1
`
	w, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if w.Env["A"].Value != "b" {
		t.Errorf("alias not followed: %+v", w.Env)
	}
}

func TestParseOddShapes(t *testing.T) {
	src := "on: push\npermissions: [a]\nenv: x\njobs:\n  a:\n    needs: {x: y}\n    if: [a]\n    steps: nope\n"
	w, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	a := w.JobByName("a")
	if a == nil || a.If != "" || a.Needs != nil || a.Steps != nil || w.Env != nil {
		t.Errorf("odd shapes = %+v / %+v", a, w)
	}
	w, err = Parse([]byte("on: push\njobs: nope\n"))
	if err != nil || len(w.Jobs) != 0 {
		t.Errorf("scalar jobs = %+v, %v", w, err)
	}
}

func TestParseErrors(t *testing.T) {
	for _, src := range []string{"a: [", "- list", "just text", ""} {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("Parse(%q) succeeded; want error", src)
		}
	}
}

func TestParseReusableJob(t *testing.T) {
	w, err := Parse([]byte("on:\n  workflow_call:\n    inputs:\n      text: {type: string, default: hi}\n      bare: {type: string}\njobs:\n  a:\n    uses: ./.github/workflows/x.yml\n    with:\n      k: v\n    outputs:\n      o: ${{ steps.s.outputs.o }}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if w.CallInputs["text"].Value != "hi" || w.CallInputs["bare"].Value != "" {
		t.Errorf("call inputs = %+v", w.CallInputs)
	}
	j := w.JobByName("A")
	if j == nil || j.Uses != "./.github/workflows/x.yml" || j.With["k"].Value != "v" || j.Outputs["o"].Value == "" {
		t.Errorf("job = %+v", j)
	}
}

func TestParseAction(t *testing.T) {
	a, err := ParseAction([]byte("inputs:\n  p: {default: d}\nruns:\n  using: composite\n  steps:\n    - run: echo\n"))
	if err != nil {
		t.Fatal(err)
	}
	if a.Inputs["p"].Value != "d" || len(a.Steps) != 1 {
		t.Errorf("action = %+v", a)
	}
	if a, err = ParseAction([]byte("runs:\n  using: docker\n")); err != nil || len(a.Steps) != 0 {
		t.Errorf("docker action = %+v, %v", a, err)
	}
	for _, src := range []string{"a: [", "- list"} {
		if _, err := ParseAction([]byte(src)); err == nil {
			t.Errorf("ParseAction(%q) succeeded", src)
		}
	}
}

func TestAliasExpansionIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("x: &big {a: \"" + strings.Repeat("a", 500_000) + "\"}\nenv:\n")
	for i := 0; i < 50; i++ {
		fmt.Fprintf(&b, "  k%d: *big\n", i)
	}
	if _, err := Parse([]byte(b.String())); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Parse err = %v", err)
	}
	if _, err := ParseAction([]byte(b.String())); !errors.Is(err, ErrTooLarge) {
		t.Errorf("ParseAction err = %v", err)
	}
	if _, err := Parse([]byte("a: &a\n  b: *a\non: push\n")); err != nil {
		t.Errorf("self-referencing anchor: %v", err)
	}
	if _, err := Parse([]byte("x: &e {K: v}\nenv: *e\non: push\njobs: {}\n")); err != nil {
		t.Errorf("ordinary anchor: %v", err)
	}
}
