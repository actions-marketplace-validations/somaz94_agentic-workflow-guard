package registry

import "testing"

func TestLoadAndFind(t *testing.T) {
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"anthropics/claude-code-action@v1":        "claude",
		"Anthropics/Claude-Code-Action/sub@abc":   "claude",
		"openai/codex-action@v1":                  "codex",
		"google-github-actions/run-gemini-cli@v0": "gemini",
		"google-gemini/gemini-cli-action@v0":      "gemini",
		"actions/ai-inference@v2":                 "inference",
		"github/ai-inference@v1":                  "inference",
	}
	for uses, id := range cases {
		a := r.Find(uses)
		if a == nil || a.ID != id {
			t.Errorf("Find(%q) = %+v; want %s", uses, a, id)
		}
	}
	for _, uses := range []string{"actions/checkout@v7", "./local", "docker://x", ""} {
		if r.Find(uses) != nil {
			t.Errorf("Find(%q) matched", uses)
		}
	}
}

func TestPowerDefaults(t *testing.T) {
	cases := map[string]Power{"limited": Limited, "broad": Broad, "scoped": Scoped, "": Scoped}
	for name, want := range cases {
		if got := (&Agent{PowerName: name}).DefaultPower(); got != want {
			t.Errorf("%q = %v; want %v", name, got, want)
		}
	}
}

func TestUntrustedPattern(t *testing.T) {
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		"Title: ${{ github.event.issue.title }}",
		"${{github.event.comment.body}}",
		"${{ format('{0}', github.event.pull_request.body) }}",
		"${{ github.head_ref }}",
	} {
		if !r.Untrusted.MatchString(s) {
			t.Errorf("%q should be untrusted", s)
		}
	}
	for _, s := range []string{
		"${{ github.event.issue.number }}",
		"github.event.issue.title without a template",
		"${{ github.event.pull_request.head.sha }}",
	} {
		if r.Untrusted.MatchString(s) {
			t.Errorf("%q should not be untrusted", s)
		}
	}
}

func TestParseErrors(t *testing.T) {
	cases := []string{
		"agents: nope",
		"untrusted_contexts: ['(']",
		"authorization_pattern: '('",
		"secret_pattern: '('",
		"agents: [{id: a, broad_when: [{input: b, pattern: '('}]}]",
	}
	for _, src := range cases {
		if _, err := parse([]byte(src)); err == nil {
			t.Errorf("parse(%q) succeeded; want error", src)
		}
	}
}

func TestMatch(t *testing.T) {
	r, err := parse([]byte("agents: [{id: a, broad_when: [{input: b, pattern: '^X$'}]}]"))
	if err != nil {
		t.Fatal(err)
	}
	m := r.Agents[0].BroadWhen[0]
	if !m.Matches("x") || m.Matches("xy") {
		t.Error("match should be case-insensitive and honor anchors")
	}
}
