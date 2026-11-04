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

func TestFindRun(t *testing.T) {
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		`claude -p "$PROMPT"`:                                 "claude-cli",
		"claude --model x --print hello":                      "claude-cli",
		"claude \\\n  --model x \\\n  -p hello":               "claude-cli",
		"npx -y @anthropic-ai/claude-code@2 -p hi":            "claude-cli",
		`out=$(claude -p "x")`:                                "claude-cli",
		"cat f | claude -p":                                   "claude-cli",
		"if claude -p x; then echo; fi":                       "claude-cli",
		"FOO=bar claude -p x":                                 "claude-cli",
		"timeout 100s qwen -p x":                              "gemini-cli",
		"gemini --yolo --prompt x":                            "gemini-cli",
		"npx @google/gemini-cli -p x":                         "gemini-cli",
		"codex exec x":                                        "codex-cli",
		"cat d | codex --ask-for-approval never exec \\\n  -": "codex-cli",
		`copilot -p "$(cat p.md)"`:                            "copilot-cli",
		"opencode run x":                                      "opencode-cli",
		"$HOME/.local/bin/claude -p x":                        "claude-cli",
		"env FOO=bar claude -p x":                             "claude-cli",
		"sudo -u x claude -p y":                               "claude-cli",
		"/usr/bin/env claude -p x":                            "claude-cli",
		`FOO="a b" claude -p x`:                               "claude-cli",
		"out=`claude -p x`":                                   "claude-cli",
		"./claude -p x":                                       "claude-cli",
		`bash -c "claude -p x"`:                               "claude-cli",
		"sh -lc 'codex exec x'":                               "codex-cli",
		"aider --model m --message x":                         "aider-cli",
	}
	for script, id := range cases {
		a := r.FindRuns(script)
		if len(a) != 1 || a[0].ID != id {
			t.Errorf("FindRuns(%q) = %+v; want %s", script, a, id)
		}
	}
	for _, script := range []string{
		"",
		"claude --version",
		"codex --version",
		"npm install -g @anthropic-ai/claude-code",
		`echo "claude -p x"`,
		"# claude -p x",
		"python3 -m unittest discover -s tests/claude -p 'test_codex_build.py'",
		"aider --version",
		"./claude-wrapper -p x",
	} {
		if a := r.FindRuns(script); a != nil {
			t.Errorf("FindRuns(%q) = %v; want none", script, a)
		}
	}
}

func TestFindRunsReturnsEveryAgent(t *testing.T) {
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	got := r.FindRuns("codex exec x\nopencode run y\n")
	if len(got) != 2 {
		t.Errorf("got %v", got)
	}
}

func TestNarrowedBy(t *testing.T) {
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var open *Agent
	for _, a := range r.Agents {
		if a.ID == "opencode-cli" {
			open = a
		}
	}
	for src, want := range map[string]bool{
		`{}`:                                false,
		`{"permission": {"bash": "allow"}}`: false,
		`{"permission": {"bash": "deny"}}`:  true,
		`{"permission": "ask"}`:             true,
		`{"permission": {"bash": {"*": "deny", "gh *": "allow"}}}`:                     true,
		`{"agent": {"plan": {"permission": {"bash": "deny"}}}, "permission": "allow"}`: false,
		"// note\n{\"permission\": \"deny\"}":                                          true,
		"{\n  // \"permission\": \"deny\"\n}":                                          false,
		`not json`:                                                                     false,
	} {
		if got := open.NarrowedBy([]byte(src)); got != want {
			t.Errorf("NarrowedBy(%s) = %v", src, got)
		}
	}
	if (&Agent{}).NarrowedBy([]byte(`{}`)) {
		t.Error("an agent with no pattern is never narrowed")
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
		"github",
		"github.event",
		"github.event.issue",
		"github.event.issue.title",
		"github.event.comment.body",
		"github.event.pull_request.body",
		"github.event.workflow_run.display_title",
		"github.event.workflow_run.head_commit.committer.name",
		"github.event.pull_request.head.repo.description",
		"github.head_ref",
	} {
		if !r.Untrusted.MatchString(s) {
			t.Errorf("%q should be untrusted", s)
		}
	}
	for _, s := range []string{
		"github.event.issue.number",
		"github.event.pull_request.head.sha",
		"github.event.issue.title.extra",
		"xgithub.event",
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
		"untrusted_fetch_pattern: '('",
		"gate_output_pattern: '('",
		"scalar_output_pattern: '('",
		"exec_argument_pattern: '('",
		"agents: [{id: a, broad_when: [{input: b, pattern: '('}]}]",
		"agents: [{id: a, run_pattern: '('}]",
		"agents: [{id: a, config_pattern: '('}]",
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
