package workflow

import (
	"reflect"
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
