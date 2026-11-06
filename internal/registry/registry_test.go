package registry

import (
	"slices"
	"strings"
	"testing"
	"time"
)

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

func TestWithoutComments(t *testing.T) {
	for in, want := range map[string]string{
		"# a\nb":                                   "\nb",
		"echo hi # note \\\nb":                     "echo hi \nb",
		"a;# c\nb":                                 "a;\nb",
		"a \\\n# c\nb":                             "a \\\n\nb",
		"x\\\n#y":                                  "x\\\n#y",
		"echo a#b $# ${#x} \\# y":                  "echo a#b $# ${#x} \\# y",
		"echo 'a # b' # c":                         "echo 'a # b' ",
		`echo "a # b" # c`:                         `echo "a # b" `,
		`echo "a \" # b" # c`:                      `echo "a \" # b" `,
		"echo '\n# x' ; b # c":                     "echo '\n# x' ; b ",
		`"$(echo "a # b")" # c`:                    `"$(echo "a # b")" `,
		"(a # b\nc) # d":                           "(a \nc) ",
		"cat <<<x # c\nb":                          "cat <<<x \nb",
		"cat <<EOF\nit's # t\n# c\nEOF\nb # d":     "cat <<EOF\nit's # t\n\nEOF\nb ",
		"cat <<-'E'\n\tx # t\n\tE\nb # d":          "cat <<-'E'\n\tx # t\n\tE\nb ",
		"cat <<A <<B # c\n1\nA\n2\nB\nb # d":       "cat <<A <<B \n1\nA\n2\nB\nb ",
		"cat <<EOF\nnever closed # t":              "cat <<EOF\nnever closed # t",
		"y=$((1<<2)) # c\nb # d":                   "y=$((1<<2)) \nb ",
		"((a<<2)) # c\nb # d":                      "((a<<2)) \nb ",
		"echo $(( 16#ff )) # c":                    "echo $(( 16#ff )) ",
		"a[1<<2]=3 # c\nb # d":                     "a[1<<2]=3 \nb ",
		"y=$[1<<2] # c\nb # d":                     "y=$[1<<2] \nb ",
		"x=\"${y%% (*}\" # c\nb # d":               "x=\"${y%% (*}\" \nb ",
		"y=$(( $(a # c\n) + 1 )) # d":              "y=$(( $(a \n) + 1 )) ",
		"`a`#b # c":                                "`a`#b ",
		"x=$(cat <<EOF\nit's # t\nEOF) # c\nb # d": "x=$(cat <<EOF\nit's # t\nEOF) \nb ",
		`y="${{ contains(x, '"') }}" # c`:          `y="${{ contains(x, '"') }}" `,
		"${{ never closed # c":                     "${{ never closed # c",
		": ${x:-<<E} # c\nb # d":                   ": ${x:-<<E} \nb ",
		": ${x:- # } # c":                          ": ${x:- # } ",
		`"${x:-'}" # c`:                            `"${x:-'}" `,
		`"${x:-"a # b"}" # c`:                      `"${x:-"a # b"}" `,
		": $'it\\'s # x' # c":                      ": $'it\\'s # x' ",
		"x=`echo a # b`; c # d":                    "x=`echo a `; c ",
		`"` + "`echo \"a # b\"`" + `" # c`:         `"` + "`echo \"a # b\"`" + `" `,
		"cat <<E\"O\"F\nit's\nEOF\nb # d":          "cat <<E\"O\"F\nit's\nEOF\nb ",
		"cat <<$X\nit's\n$X\nb # d":                "cat <<$X\nit's\n$X\nb ",
		"cat <<'-x'\nit's\n-x\nb # d":              "cat <<'-x'\nit's\n-x\nb ",
		"cat << \\E\nit's\nE\nb # d":               "cat << \\E\nit's\nE\nb ",
		"cat <<'open\nb # d":                       "cat <<'open\nb # d",
		"cat <<\nb # d":                            "cat <<\nb ",
		"tr -d '[' <<EOF\nit's\nEOF\nb # d":        "tr -d '[' <<EOF\nit's\nEOF\nb ",
		"x=$(cat <<EOF\nEOFX) # c\nb # d":          "x=$(cat <<EOF\nEOF\nX) \nb ",
		"(cat <<E\nE)\nit's\nE\n) # c":             "(cat <<E\nE)\nit's\nE\n) ",
		"x=`cat <<E\nhi\nE`; b # d":                "x=`cat <<E\nhi\nE`; b ",
		"a ${{ b }}# c":                            "a ${{ b }}",
		"cat <<E\nabc\\\nE\nit's\nE\nb # d":        "cat <<E\nabc\\\nE\nit's\nE\nb ",
		"cat <<EOF\nEO\\\nF\nb # d":                "cat <<EOF\nEO\\\nF\nb ",
		"cat <<'E'\nabc\\\nE\nb # d":               "cat <<'E'\nabc\\\nE\nb ",
		"a # never ends":                           "a ",
		"cat <(cat <<E\nE) # c\nb # d":             "cat <(cat <<E\nE) \nb ",
		"x=$(true)\ncat <<E\nE) # t\nE\nb # d":     "x=$(true)\ncat <<E\nE) # t\nE\nb ",
		"cat <(true)\ncat <<E\nE) # t\nE\nb # d":   "cat <(true)\ncat <<E\nE) # t\nE\nb ",
		"x=$(cat <<A <<B\n1\nA) # c\nb # d":        "x=$(cat <<A <<B\n1\nA) \nb ",
	} {
		if got := WithoutComments(in); got != want {
			t.Errorf("WithoutComments(%q) = %q; want %q", in, got, want)
		}
	}
}

func FuzzWithoutComments(f *testing.F) {
	for _, s := range []string{"a # b", "<<A\nx\nA\n# c", "\"$(a '", "x\\", "<<-'B' <<<c\n", "(#)\n)"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, got := range CommentReadings(s) {
			if strings.Count(got, "\n") < strings.Count(s, "\n") {
				t.Errorf("CommentReadings(%q) has %q, which lost a line", s, got)
			}
			if len(got) > 2*len(s) {
				t.Errorf("CommentReadings(%q) has %q, which grew", s, got)
			}
		}
	})
}

func TestCommentReadings(t *testing.T) {
	for in, want := range map[string]string{
		"echo [ <<E\nit's\nE\nb # d":             "echo [ <<E\nit's\nE\nb ",
		"a=([1<<1]=y) # c\nb # d":                "a=([1<<1]=y) \nb ",
		"x=$(cat <<A\nA)\nit's\nA\n) # c\nb # d": "x=$(cat <<A\nA)\nit's\nA\n) \nb ",
	} {
		if got := CommentReadings(in); !slices.Contains(got, want) {
			t.Errorf("CommentReadings(%q) = %q; want one to be %q", in, got, want)
		}
	}
}

func TestCommentReadingsStayLinear(t *testing.T) {
	for name, script := range map[string]string{
		"unclosed templates":        strings.Repeat("${{ ", 1<<18),
		"here-documents under nest": strings.Repeat("( ", 1<<18) + strings.Repeat("cat <<a\na\n", 1<<16),
		"bodies ending mid-line":    "x=$(cat " + strings.Repeat("<<a ", 1<<17) + "\n" + strings.Repeat("a", 1<<19) + ")",
	} {
		start := time.Now()
		CommentReadings(script)
		if took := time.Since(start); took > 5*time.Second {
			t.Errorf("%s took %s", name, took)
		}
	}
}

func TestFindRunsSeesPastAComment(t *testing.T) {
	r, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, script := range []string{
		"# note \\\nclaude -p x",
		"echo a \\\n  # note\nclaude -p x",
		"echo hi # note \\\nclaude -p x",
		"echo '\n# ' ; claude -p x",
		`: "$(echo "a # b")" ; claude -p x`,
		"echo \"`echo \"a # b\"`\" ; claude -p x",
		"cat <<EOF\nit's\nEOF\necho hi # note \\\nclaude -p x",
		"bash <<'EOF'\n# note \\\nclaude -p x\nEOF",
		"echo \"[\" && cat <<EOF\nit's\nEOF\n: '\n# '; claude -p x",
		"x=$(cat <<EOF\nEOF claude -p x)",
		"(cat <<EOF\nEOF)\nit's\nEOF\n)\necho hi # note \\\nclaude -p x",
		"cat <<E\nabc\\\nE\nit's\nE\necho hi # note \\\nclaude -p x",
		`: "$(case a in a) echo "b # c";; esac)"; claude -p x`,
		"name=\"${x%% (*}\"\necho hi # note \\\nclaude -p x",
		"((echo a # (\n) | cat)\necho hi # note \\\nclaude -p x",
		"y=$(( $(echo a # note \\\nclaude -p x\n) + 1 ))",
		"x=$(cat <<EOF\nit's\nEOF)\necho hi # note \\\nclaude -p x",
		"a=([1<<1]=y)\necho \"a\n#b\"; claude -p x",
		"a=(x [1<<1]=y)\necho \"a\n#b\"; claude -p x",
		"a[1<<1]=y\necho [ <<EOF\n\"\nEOF\necho \"a\n#b\"; claude -p x",
		"x=$(cat <<A <<B\n1\nA)\n\"\nA\nB\n)\necho \"a\n#b\"; claude -p x",
		"x=$(cat <<A\nA)\n\"\nA\n)\necho \"a\n#b\"; claude -p x",
		"y=\"$(cat <<A\nA)x\\\n\"\necho \"a\n#b\"; claude -p x",
		"y=\"$(cat <<-A\n\tA\\\n)x\\\n\"\necho \"a\n#b\"; claude -p x",
	} {
		if a := r.FindRuns(script); len(a) != 1 || a[0].ID != "claude-cli" {
			t.Errorf("FindRuns(%q) = %+v; want claude-cli", script, a)
		}
	}
	if a := r.FindRuns("# claude -p x \\\n  --version"); a != nil {
		t.Errorf("a comment ran an agent: %+v", a)
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
