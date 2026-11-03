package audit

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/somaz94/agentic-workflow-guard/internal/registry"
	"github.com/somaz94/agentic-workflow-guard/internal/workflow"
)

func reg(t *testing.T) *registry.Registry {
	t.Helper()
	r, err := registry.Load()
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func run(t *testing.T, src string) []string {
	t.Helper()
	wf, err := workflow.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range Workflow(reg(t), "wf.yml", wf) {
		got = append(got, f.Severity.String()+" "+f.Rule)
	}
	sort.Strings(got)
	return got
}

const header = "on:\n  issues:\n  issue_comment:\n  pull_request_target:\npermissions:\n  contents: read\n  issues: write\njobs:\n  a:\n"

func TestWorkflowCases(t *testing.T) {
	cases := []struct {
		name, src string
		want      []string
	}{
		{"not an agent", header + "    steps:\n      - uses: actions/checkout@v7\n", nil},
		{"claude default is protected by its actor check", header + "    steps:\n      - uses: anthropics/claude-code-action@v1\n", nil},
		{"wildcard actor", header + "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n",
			[]string{"high open-invocation"}},
		{"wildcard actor among names", header + "    steps:\n      - uses: openai/codex-action@v1\n        with:\n          allow-users: 'alice, *'\n",
			[]string{"high open-invocation"}},
		{"named actors are fine", header + "    steps:\n      - uses: openai/codex-action@v1\n        with:\n          allow-users: alice\n", nil},
		{"wildcard behind a real gate", header + "    if: github.event.comment.author_association == 'OWNER'\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n", nil},
		{"wildcard with exec tool",
			header + "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n          claude_args: --allowedTools Bash(find:*)\n",
			[]string{"high broad-tools", "high open-invocation"}},
		{"gate on only one branch does not count",
			header + "    if: github.event_name == 'issues' || github.event.comment.author_association == 'OWNER'\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n",
			[]string{"high open-invocation"}},
		{"prior contributor is still reachable, and says so",
			"on:\n  pull_request_target:\njobs:\n  a:\n    if: contains(fromJSON('[\"OWNER\",\"CONTRIBUTOR\"]'), github.event.pull_request.author_association)\n    permissions: {}\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.pull_request.title }}\n",
			[]string{"low untrusted-input"}},
		{"wildcard with a read-only token",
			"on: issues\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: openai/codex-action@v1\n        with:\n          allow-users: '*'\n",
			[]string{"medium open-invocation"}},
		{"wildcard with only read-only tools",
			header + "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n          claude_args: --model x --allowedTools \"Read,Grep\" --max-turns 3\n",
			[]string{"medium open-invocation"}},
		{"unquoted read-only tools",
			header + "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n          claude_args: --allowedTools Read --max-turns 3\n",
			[]string{"medium open-invocation"}},
		{"a write tool is not read-only",
			header + "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n          claude_args: --allowedTools \"Read,Write\"\n",
			[]string{"high open-invocation"}},
		{"empty allowlist is not read-only",
			header + "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n          claude_args: --allowedTools \"\"\n",
			[]string{"high open-invocation"}},
		{"read and comment gh commands count as read-only",
			header + "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n          claude_args: --allowedTools \"Bash(gh pr view:*),Bash(gh pr diff:*),Bash(gh pr comment:*),Read\" --max-turns 3\n",
			[]string{"medium open-invocation"}},
		{"gh pr review can approve, so it does not",
			header + "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n          claude_args: --allowed-tools \"Bash(gh pr view:*),Bash(gh pr review:*)\"\n",
			[]string{"high open-invocation"}},
		{"fork-safe conditional checkout is fine",
			"on: pull_request_target\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        with:\n          ref: ${{ github.event.pull_request.head.repo.full_name == github.repository && github.event.pull_request.head.sha || github.event.pull_request.base.sha }}\n      - uses: actions/ai-inference@v2\n", nil},
		{"read-only tools through settings",
			header + "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n          settings: '{\"permissions\": {\"allow\": [\"Read\", \"Grep\"], \"deny\": [\"Bash\"]}}'\n",
			[]string{"medium open-invocation"}},
		{"a write tool through settings is not read-only",
			header + "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n          settings: '{\"permissions\": {\"allow\": [\"Read\", \"Write\"]}}'\n",
			[]string{"high open-invocation"}},
		{"read-only arguments do not excuse wider settings",
			header + "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n          claude_args: --allowedTools Read\n          settings: '{\"permissions\": {\"allow\": [\"Write\"]}}'\n",
			[]string{"high open-invocation"}},
		{"settings without an allowlist keep the default",
			header + "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n          settings: '{}'\n",
			[]string{"high open-invocation"}},
		{"fetching pull request refs is not a checkout",
			"on: pull_request_target\npermissions: {}\njobs:\n  a:\n    steps:\n      - run: git fetch origin refs/pull/1/head\n      - uses: actions/ai-inference@v2\n", nil},
		{"fetching and switching to them is",
			"on: pull_request_target\npermissions: {}\njobs:\n  a:\n    steps:\n      - run: git fetch origin pull/1/head && git checkout FETCH_HEAD\n      - uses: actions/ai-inference@v2\n",
			[]string{"medium untrusted-checkout"}},
		{"private-only branch is no way in",
			header + "    if: github.event.repository.private == true || github.event.comment.author_association == 'OWNER'\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.issue.body }}\n", nil},
		{"flow-control step output does not lower severity",
			"on: pull_request_target\njobs:\n  a:\n    steps:\n      - id: changed\n        run: echo\n      - if: steps.changed.outputs.count != '0'\n        uses: openai/codex-action@v1\n        with:\n          allow-users: '*'\n          sandbox: danger-full-access\n",
			[]string{"high broad-tools", "high open-invocation"}},
		{"unnamed step output stays unverified",
			"on: issues\npermissions: {}\njobs:\n  a:\n    steps:\n      - if: steps.elsewhere.outputs.count != '0'\n        uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.issue.body }}\n",
			[]string{"low untrusted-input"}},
		{"gate-named step output stays unverified",
			"on: pull_request_target\njobs:\n  a:\n    steps:\n      - id: check\n        run: echo\n      - if: steps.check.outputs.allowed == 'true'\n        uses: openai/codex-action@v1\n        with:\n          allow-users: '*'\n",
			[]string{"medium open-invocation"}},
		{"flow-control job output does not lower severity",
			"on: issues\njobs:\n  build:\n    steps:\n      - run: echo\n  a:\n    needs: build\n    if: needs.build.outputs.count != '0'\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          gemini_args: --yes\n",
			[]string{"high broad-tools", "high open-invocation"}},
		{"job output whose job authorizes stays unverified",
			"on: issues\npermissions: {}\njobs:\n  build:\n    steps:\n      - run: gh api repos/o/r/collaborators/x/permission\n  a:\n    needs: build\n    if: needs.build.outputs.count != '0'\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.issue.body }}\n",
			[]string{"low untrusted-input"}},
		{"job output of a job that is not there stays unverified",
			"on: issues\npermissions: {}\njobs:\n  a:\n    if: needs.ghost.outputs.count != '0'\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.issue.body }}\n",
			[]string{"low untrusted-input"}},
		{"text through a prior step's output",
			"on: issues\npermissions: {}\njobs:\n  a:\n    steps:\n      - id: issue\n        env:\n          T: ${{ github.event.issue.title }}\n        run: echo\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: 'Title: ${{ steps.issue.outputs.title }}'\n",
			[]string{"low untrusted-input"}},
		{"text through a github-script step",
			"on: issues\npermissions: {}\njobs:\n  a:\n    steps:\n      - id: issue\n        uses: actions/github-script@v8\n        with:\n          script: core.setOutput('b', context.payload.issue.body)\n      - uses: actions/ai-inference@v2\n        with:\n          input: ${{ steps.issue.outputs.b }}\n",
			[]string{"low untrusted-input"}},
		{"text through a written prompt file",
			"on: pull_request_target\npermissions: {}\njobs:\n  a:\n    steps:\n      - run: gh pr diff 1 > prompt.txt\n      - uses: actions/ai-inference@v2\n        with:\n          prompt-file: prompt.txt\n",
			[]string{"low untrusted-input"}},
		{"text through a temp file named in file_input",
			"on: issues\npermissions: {}\njobs:\n  a:\n    steps:\n      - env:\n          B: ${{ github.event.issue.body }}\n        run: printf '%s' \"$B\" > \"${RUNNER_TEMP}/t/body.txt\"\n      - uses: actions/ai-inference@v2\n        with:\n          prompt-file: .github/p.prompt.yml\n          file_input: |\n            body: ${{ runner.temp }}/t/body.txt\n",
			[]string{"low untrusted-input"}},
		{"a committed prompt file is fine",
			"on: issues\npermissions: {}\njobs:\n  a:\n    steps:\n      - id: other\n        run: gh issue view 1\n      - uses: actions/ai-inference@v2\n        with:\n          prompt-file: .github/p.yml\n", nil},
		{"output of an unrelated step is fine",
			"on: issues\npermissions: {}\njobs:\n  a:\n    steps:\n      - id: fetch\n        run: gh issue view 1\n      - id: other\n        run: echo\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ steps.other.outputs.x }}\n", nil},
		{"fetched text on an unreachable run",
			"on: issues\npermissions: {}\njobs:\n  a:\n    if: github.actor == 'alice'\n    steps:\n      - id: issue\n        run: gh issue view 1\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ steps.issue.outputs.b }}\n", nil},
		{"inference github mcp is scoped, not arbitrary commands",
			"on: issues\njobs:\n  a:\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          enable-github-mcp: true\n          prompt: hello\n",
			[]string{"medium open-invocation"}},
		{"inference copilot allow all",
			"on: issues\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          copilot-allow-tools: '*'\n",
			[]string{"high broad-tools", "high open-invocation"}},
		{"bot wildcard", header + "    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_bots: '*'\n", []string{"medium open-invocation"}},
		{"bot wildcard behind a gate", header + "    if: github.event_name == 'push'\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_bots: '*'\n", nil},
		{"inference with no untrusted input stays quiet", header + "    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: hello\n", nil},
		{"inference with issue text, no tools, write token",
			header + "    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: 'T: ${{ github.event.issue.title }}'\n",
			[]string{"medium untrusted-input"}},
		{"inference read-only token",
			"on: issues\npermissions:\n  contents: read\njobs:\n  a:\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.issue.body }}\n",
			[]string{"low untrusted-input"}},
		{"inference job permissions win over top",
			"on: issues\npermissions:\n  contents: write\njobs:\n  a:\n    permissions: read-all\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.issue.body }}\n",
			[]string{"low untrusted-input"}},
		{"unset permissions count as write",
			"on: issues\njobs:\n  a:\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.issue.body }}\n",
			[]string{"medium untrusted-input"}},
		{"field the event cannot carry",
			"on: issues\njobs:\n  a:\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.comment.body }}\n", nil},
		{"input through step env",
			"on: issues\njobs:\n  a:\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        env:\n          T: ${{ github.event.issue.title }}\n",
			[]string{"high untrusted-input"}},
		{"input through job env",
			"on: issues\njobs:\n  a:\n    env:\n      T: ${{ github.event.issue.title }}\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n",
			[]string{"high untrusted-input"}},
		{"input through workflow env",
			"on: issues\nenv:\n  T: ${{ github.event.issue.title }}\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n",
			[]string{"medium untrusted-input"}},
		{"head ref on the event that has it",
			"on: pull_request_target\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.head_ref }}\n",
			[]string{"low untrusted-input"}},
		{"head ref on an event without it",
			"on: issues\njobs:\n  a:\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.head_ref }}\n", nil},
		{"gemini with no input can still read through tools",
			"on: issues\njobs:\n  a:\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          prompt: /triage\n",
			[]string{"medium open-invocation"}},
		{"gemini auto approve",
			"on: issues\njobs:\n  a:\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          gemini_args: --yes\n",
			[]string{"high broad-tools", "high open-invocation"}},
		{"gemini auto approve through env",
			"on: issues\njobs:\n  a:\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        env:\n          GEMINI_CLI_AUTO_APPROVE: 'true'\n",
			[]string{"high broad-tools", "high open-invocation"}},
		{"gemini echo only is limited even with templated settings and auto approve",
			"on: issues\njobs:\n  a:\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          gemini_args: --yes\n          settings: |\n            {\"debug\": ${{ fromJSON(env.D || false) }}, \"coreTools\": [\"run_shell_command(echo)\"]}\n        env:\n          T: ${{ github.event.issue.title }}\n",
			[]string{"medium untrusted-input"}},
		{"gemini echo through tools.core",
			"on: issues\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          settings: '{\"tools\": {\"core\": [\"run_shell_command(echo)\"]}}'\n", nil},
		{"gemini other tool is not limited",
			"on: issues\njobs:\n  a:\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          settings: '{\"tools\": {\"core\": [\"run_shell_command(gh api)\"]}}'\n",
			[]string{"medium open-invocation"}},
		{"gemini mcp server is not limited",
			"on: issues\njobs:\n  a:\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          settings: '{\"coreTools\": [\"run_shell_command(echo)\"], \"mcpServers\": {\"g\": {}}}'\n",
			[]string{"medium open-invocation"}},
		{"gemini settings without tools",
			"on: issues\njobs:\n  a:\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          settings: '{}'\n",
			[]string{"medium open-invocation"}},
		{"gemini broken settings",
			"on: issues\njobs:\n  a:\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          settings: '{'\n",
			[]string{"medium open-invocation"}},
		{"codex read-only sandbox lowers a wildcard",
			"on: pull_request_target\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: openai/codex-action@v1\n        with:\n          allow-users: '*'\n          sandbox: read-only\n",
			[]string{"low open-invocation"}},
		{"codex read-only with write token",
			"on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: openai/codex-action@v1\n        with:\n          allow-users: '*'\n          permission-profile: ':read-only'\n",
			[]string{"medium open-invocation"}},
		{"gated broad agent is a low hardening note",
			"on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: openai/codex-action@v1\n        with:\n          sandbox: danger-full-access\n",
			[]string{"low broad-tools"}},
		{"untrusted checkout",
			"on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - uses: google-github-actions/run-gemini-cli@v0\n",
			[]string{"high untrusted-checkout", "medium open-invocation"}},
		{"checkout of a limited agent",
			"on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        with:\n          repository: ${{ github.event.pull_request.head.repo.full_name }}\n          ref: ${{ github.head_ref }}\n      - uses: actions/ai-inference@v2\n",
			[]string{"medium untrusted-checkout"}},
		{"fetch in a run step",
			"on: issue_comment\npermissions: {}\njobs:\n  a:\n    steps:\n      - run: gh pr checkout 1\n      - uses: actions/ai-inference@v2\n",
			[]string{"medium untrusted-checkout"}},
		{"base checkout is fine",
			"on: pull_request_target\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v7\n        with:\n          ref: ${{ github.event.pull_request.base.sha }}\n      - uses: actions/ai-inference@v2\n", nil},
		{"fork-safe trigger is out of scope",
			"on: pull_request\njobs:\n  a:\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.pull_request.title }}\n", nil},
		{"labeled only never fires for an outsider",
			"on:\n  issues:\n    types: [labeled]\njobs:\n  a:\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.issue.body }}\n", nil},
		{"step gate",
			"on: issues\njobs:\n  a:\n    steps:\n      - if: github.actor == 'alice'\n        uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.issue.body }}\n", nil},
		{"output of a gate job lowers severity once",
			"on: issues\njobs:\n  gate:\n    steps:\n      - run: echo\n  a:\n    needs: gate\n    if: needs.gate.outputs.ok == 'true'\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n        with:\n          gemini_args: --yes\n          prompt: ${{ github.event.issue.body }}\n",
			[]string{"medium broad-tools", "medium untrusted-input"}},
		{"needed job that is gated skips this one",
			"on: issues\njobs:\n  gate:\n    if: github.event.issue.author_association == 'OWNER'\n    steps:\n      - run: echo\n  a:\n    needs: [gate, missing]\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.issue.body }}\n", nil},
		{"always() ignores the needed job's gate",
			"on: issues\njobs:\n  gate:\n    if: github.event.issue.author_association == 'OWNER'\n    steps:\n      - run: echo\n  a:\n    needs: gate\n    if: always()\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.issue.body }}\n",
			[]string{"medium untrusted-input"}},
		{"authorization step in a needed job",
			"on: issues\njobs:\n  gate:\n    steps:\n      - run: gh api repos/o/r/collaborators/x/permission\n  a:\n    needs: gate\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.issue.body }}\n",
			[]string{"low untrusted-input"}},
		{"authorization step before the agent",
			"on: issues\njobs:\n  a:\n    steps:\n      - uses: x/check-user-permission@v1\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.issue.body }}\n",
			[]string{"low untrusted-input"}},
		{"cyclic needs terminates",
			"on: issues\njobs:\n  x:\n    needs: y\n    steps:\n      - run: echo\n  y:\n    needs: x\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.issue.body }}\n",
			[]string{"medium untrusted-input"}},
		{"full output",
			"on: push\njobs:\n  a:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          show_full_output: 'true'\n",
			[]string{"low full-output"}},
		{"no secret trigger", "on: push\njobs:\n  a:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := run(t, c.src); !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %v; want %v", got, c.want)
			}
		})
	}
}

func TestMessages(t *testing.T) {
	src := "on: pull_request_target\npermissions: {}\njobs:\n  a:\n    if: github.event.pull_request.author_association == 'CONTRIBUTOR'\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.pull_request.title }}\n"
	wf, _ := workflow.Parse([]byte(src))
	f := Workflow(reg(t), "wf.yml", wf)
	if len(f) != 1 || !strings.Contains(f[0].Message, "previously merged commit") || f[0].Line != 9 || f[0].File != "wf.yml" {
		t.Errorf("finding = %+v", f)
	}
	src = "on: issues\njobs:\n  gate:\n    steps:\n      - run: echo\n  a:\n    needs: gate\n    if: needs.gate.outputs.ok == 'true'\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n"
	wf, _ = workflow.Parse([]byte(src))
	f = Workflow(reg(t), "wf.yml", wf)
	if len(f) != 1 || !strings.Contains(f[0].Message, "run-time check") || f[0].Severity != Low {
		t.Errorf("unverified finding = %+v", f)
	}
}

func TestOutsiderPathOutranksContributorPath(t *testing.T) {
	src := "on:\n  issues:\n  pull_request_target:\npermissions: {}\njobs:\n  a:\n    if: github.event_name == 'issues' || github.event.pull_request.author_association == 'CONTRIBUTOR'\n    steps:\n      - uses: google-github-actions/run-gemini-cli@v0\n"
	for i := 0; i < 20; i++ { // Triggers is a map, so the order varies between runs.
		wf, _ := workflow.Parse([]byte(src))
		f := Workflow(reg(t), "wf.yml", wf)
		if len(f) != 1 || !strings.Contains(f[0].Message, "any GitHub user") {
			t.Fatalf("finding = %+v", f)
		}
	}
}

func TestExecTools(t *testing.T) {
	r := reg(t)
	cases := []struct {
		in   string
		want []string
	}{
		{`--allowedTools "Bash(gh issue comment:*),Read"`, nil},
		{`--allowedTools "Bash(git log:*),Bash(grep:*)"`, nil},
		{`--allowedTools Bash(find:*)`, []string{"Bash(find:*)"}},
		{`--allowedTools "Bash(uv *),Read"`, []string{"Bash(uv *)"}},
		{`--allowedTools Bash(*)`, []string{"Bash(*)"}},
		{`--allowedTools Bash()`, []string{"Bash()"}},
		{`--allowedTools "Read,Bash"`, []string{"Bash"}},
		{`--disallowedTools Bash`, nil},
		{`--disallowed-tools "Bash(find:*)" --model x`, nil},
		{`{"allow": ["Read"], "deny": ["Bash(find:*)", "Bash"]}`, nil},
		{``, nil},
	}
	for _, c := range cases {
		if got := ExecTools(r, c.in); !reflect.DeepEqual(got, c.want) {
			t.Errorf("ExecTools(%q) = %v; want %v", c.in, got, c.want)
		}
	}
}

func TestSeverityString(t *testing.T) {
	if High.String() != "high" || Medium.String() != "medium" || Low.String() != "low" {
		t.Error("severity names changed")
	}
	if lower(High) != Medium || lower(Low) != Low {
		t.Error("lower must stop at Low")
	}
}

func TestPowerUnknownDefaults(t *testing.T) {
	r := reg(t)
	got := Power(r, r.Find("anthropics/claude-code-action@v1"), workflow.Step{With: map[string]workflow.Input{"claude_args": {Value: "--dangerously-skip-permissions"}}})
	if got != registry.Broad {
		t.Errorf("power = %v", got)
	}
}
