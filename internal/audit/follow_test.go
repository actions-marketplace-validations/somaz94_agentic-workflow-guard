package audit

import (
	"errors"
	"io/fs"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/somaz94/agentic-workflow-guard/internal/workflow"
)

func follow(t *testing.T, files map[string]string, main string) ([]Finding, []string) {
	t.Helper()
	src := func(rel string) ([]byte, error) {
		if s, ok := files[rel]; ok {
			return []byte(s), nil
		}
		return nil, fs.ErrNotExist
	}
	wf, err := workflow.Parse([]byte(files[main]))
	if err != nil {
		t.Fatal(err)
	}
	var warnings []string
	got := newAuditor(reg(t), src, main, wf, nil, func(m string) { warnings = append(warnings, m) }).run()
	return got, warnings
}

func summarize(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Severity.String()+" "+f.Rule+" "+f.File)
	}
	sort.Strings(out)
	return out
}

const (
	mainWF  = ".github/workflows/main.yml"
	agentWF = ".github/workflows/agent.yml"
	wideAgt = "on: workflow_call\njobs:\n  r:\n    steps:\n      - uses: openai/codex-action@v1\n        with:\n          allow-users: '*'\n"
)

func TestFollowReusable(t *testing.T) {
	cases := []struct {
		name          string
		caller, agent string
		want          []string
	}{
		{"runs with the caller's trigger",
			"on: issue_comment\npermissions: {}\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n", wideAgt,
			[]string{"medium open-invocation " + agentWF}},
		{"the caller's write token raises severity",
			"on: issue_comment\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n", wideAgt,
			[]string{"high open-invocation " + agentWF}},
		{"the called job can narrow the token",
			"on: issue_comment\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n",
			strings.Replace(wideAgt, "  r:\n", "  r:\n    permissions: {}\n", 1),
			[]string{"medium open-invocation " + agentWF}},
		{"the called job cannot widen the token",
			"on: issue_comment\npermissions: {}\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n",
			strings.Replace(wideAgt, "  r:\n", "  r:\n    permissions: write-all\n", 1),
			[]string{"medium open-invocation " + agentWF}},
		{"a gate on the calling job holds",
			"on: issue_comment\njobs:\n  a:\n    if: github.event.comment.author_association == 'OWNER'\n    uses: ./.github/workflows/agent.yml\n", wideAgt, nil},
		{"a gated job the caller needs holds",
			"on: issue_comment\njobs:\n  g:\n    if: github.event.comment.author_association == 'OWNER'\n    steps:\n      - run: echo\n  a:\n    needs: g\n    uses: ./.github/workflows/agent.yml\n", wideAgt, nil},
		{"a trigger with no secrets is not exposure",
			"on: pull_request\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n", wideAgt, nil},
		{"attacker text through an input",
			"on: issues\npermissions: {}\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n    with:\n      text: ${{ github.event.issue.body }}\n",
			"on:\n  workflow_call:\n    inputs:\n      text: {type: string}\njobs:\n  r:\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ inputs.text }}\n",
			[]string{"low untrusted-input " + agentWF}},
		{"attacker text through an input default",
			"on: issues\npermissions: {}\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n",
			"on:\n  workflow_call:\n    inputs:\n      text: {type: string, default: '${{ github.event.issue.body }}'}\njobs:\n  r:\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ inputs.text }}\n",
			[]string{"low untrusted-input " + agentWF}},
		{"an identifier input is not text",
			"on: issues\npermissions: {}\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n    with:\n      base_ref: ${{ github.event.issue.body }}\n",
			"on: workflow_call\njobs:\n  r:\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ inputs.base_ref }}\n", nil},
		{"a fixed input is fine",
			"on: issues\npermissions: {}\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n    with:\n      text: hello\n",
			"on: workflow_call\njobs:\n  r:\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ inputs.text }} ${{ inputs.other }}\n", nil},
		{"a gate-named input stays unverified",
			"on: issues\npermissions: {}\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n    with:\n      allowed: ${{ github.event.issue.number }}\n",
			"on: workflow_call\njobs:\n  r:\n    if: inputs.allowed == 'true'\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.issue.body }}\n",
			[]string{"low untrusted-input " + agentWF}},
		{"a flow-control input does not lower severity",
			"on: issues\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n",
			"on: workflow_call\njobs:\n  r:\n    if: inputs.mode == 'full'\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ github.event.issue.body }}\n",
			[]string{"medium untrusted-input " + agentWF}},
		{"a call to itself terminates",
			"on: issues\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n",
			"on: workflow_call\njobs:\n  r:\n    uses: ./.github/workflows/agent.yml\n", nil},
		{"another repository is not followed",
			"on: issues\njobs:\n  a:\n    uses: o/r/.github/workflows/agent.yml@v1\n", wideAgt, nil},
		{"a path out of the repository is not followed",
			"on: issues\njobs:\n  a:\n    uses: ./../other/agent.yml\n", wideAgt, nil},
		{"a missing file is quiet",
			"on: issues\njobs:\n  a:\n    uses: ./.github/workflows/none.yml\n", wideAgt, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, warnings := follow(t, map[string]string{mainWF: c.caller, agentWF: c.agent}, mainWF)
			if s := summarize(got); !reflect.DeepEqual(s, c.want) {
				t.Errorf("got %v; want %v", s, c.want)
			}
			if len(warnings) != 0 {
				t.Errorf("warnings = %v", warnings)
			}
		})
	}
}

func TestFollowNamesTheCaller(t *testing.T) {
	got, _ := follow(t, map[string]string{
		mainWF:  "on: issue_comment\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n",
		agentWF: wideAgt,
	}, mainWF)
	if len(got) != 1 || !strings.Contains(got[0].Message, "called from "+mainWF) || got[0].Line == 0 {
		t.Errorf("findings = %+v", got)
	}
}

func TestFollowNested(t *testing.T) {
	got, _ := follow(t, map[string]string{
		mainWF:                      "on: issue_comment\npermissions: {}\njobs:\n  a:\n    uses: ./.github/workflows/mid.yml\n",
		".github/workflows/mid.yml": "on: workflow_call\njobs:\n  m:\n    uses: ./.github/workflows/agent.yml\n",
		agentWF:                     wideAgt,
	}, mainWF)
	if s := summarize(got); !reflect.DeepEqual(s, []string{"medium open-invocation " + agentWF}) {
		t.Errorf("got %v", s)
	}
}

func TestFollowInputCycle(t *testing.T) {
	got, _ := follow(t, map[string]string{
		mainWF:  "on: issues\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n",
		agentWF: "on:\n  workflow_call:\n    inputs:\n      x: {default: '${{ inputs.x }}'}\njobs:\n  r:\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ inputs.x }}\n",
	}, mainWF)
	if len(got) != 0 {
		t.Errorf("findings = %+v", got)
	}
}

func TestFollowWholeInputs(t *testing.T) {
	got, _ := follow(t, map[string]string{
		mainWF:  "on: issues\npermissions: {}\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n    with:\n      n: ${{ github.event.issue.body }}\n      issue_id: ${{ github.event.issue.body }}\n",
		agentWF: "on: workflow_call\njobs:\n  r:\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ toJSON(inputs) }}\n",
	}, mainWF)
	if s := summarize(got); !reflect.DeepEqual(s, []string{"low untrusted-input " + agentWF}) {
		t.Errorf("got %v", s)
	}
	got, _ = follow(t, map[string]string{mainWF: "on: issues\njobs:\n  a:\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ toJSON(inputs) }}\n"}, mainWF)
	if len(got) != 0 {
		t.Errorf("no caller: %+v", got)
	}
}

func TestCompositeWholeInputs(t *testing.T) {
	got, _ := follow(t, map[string]string{
		mainWF:           "on: issues\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: ./act\n        with:\n          t: ${{ github.event.issue.body }}\n",
		"act/action.yml": "runs:\n  using: composite\n  steps:\n    - uses: actions/ai-inference@v2\n      with:\n        prompt: ${{ toJSON(inputs) }}\n",
	}, mainWF)
	if s := summarize(got); !reflect.DeepEqual(s, []string{"low untrusted-input act/action.yml"}) {
		t.Errorf("got %v", s)
	}
}

func TestFollowDepthLimit(t *testing.T) {
	files := map[string]string{mainWF: "on: issue_comment\njobs:\n  a:\n    uses: ./.github/workflows/w0.yml\n"}
	name := func(i int) string { return ".github/workflows/w" + string(rune('0'+i)) + ".yml" }
	for i := 0; i < maxDepth+2; i++ {
		files[name(i)] = "on: workflow_call\njobs:\n  n:\n    uses: ./" + name(i+1) + "\n"
	}
	if got, _ := follow(t, files, mainWF); len(got) != 0 {
		t.Errorf("got %v", got)
	}
}

func TestFollowWarnings(t *testing.T) {
	_, w := follow(t, map[string]string{
		mainWF:  "on: issues\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n",
		agentWF: "a: [",
	}, mainWF)
	if len(w) != 1 || !strings.Contains(w[0], agentWF) {
		t.Errorf("warnings = %v", w)
	}
	src := func(string) ([]byte, error) { return nil, errors.New("boom") }
	wf, _ := workflow.Parse([]byte("on: issues\njobs:\n  a:\n    uses: ./.github/workflows/agent.yml\n"))
	var got []string
	newAuditor(reg(t), src, mainWF, wf, nil, func(m string) { got = append(got, m) }).run()
	if len(got) != 1 || !strings.Contains(got[0], "boom") {
		t.Errorf("warnings = %v", got)
	}
}

func TestComposite(t *testing.T) {
	const action = ".github/actions/agent/action.yml"
	wide := "runs:\n  using: composite\n  steps:\n    - uses: openai/codex-action@v1\n      with:\n        allow-users: '*'\n"
	viaInput := "inputs:\n  text: {default: fixed}\nruns:\n  using: composite\n  steps:\n    - uses: actions/ai-inference@v2\n      with:\n        prompt: ${{ inputs.text }}\n"
	head := "on: issue_comment\npermissions: {}\njobs:\n  a:\n"
	cases := []struct {
		name, wf, act string
		want          []string
	}{
		{"an agent inside is reported at its own file", head + "    steps:\n      - uses: ./.github/actions/agent\n", wide,
			[]string{"medium open-invocation " + action}},
		{"a gate on the calling step holds", head + "    steps:\n      - if: github.event.comment.author_association == 'OWNER'\n        uses: ./.github/actions/agent\n", wide, nil},
		{"text through an input", head + "    steps:\n      - uses: ./.github/actions/agent\n        with:\n          text: ${{ github.event.comment.body }}\n", viaInput,
			[]string{"low untrusted-input " + action}},
		{"a default holding nothing is fine", head + "    steps:\n      - uses: ./.github/actions/agent\n", viaInput, nil},
		{"text fetched by a step inside",
			head + "    steps:\n      - uses: ./.github/actions/agent\n",
			"runs:\n  using: composite\n  steps:\n    - id: s\n      run: gh issue view 1\n      shell: bash\n    - uses: actions/ai-inference@v2\n      with:\n        prompt: ${{ steps.s.outputs.b }}\n",
			[]string{"low untrusted-input " + action}},
		{"a step id outside the action is out of scope",
			head + "    steps:\n      - id: s\n        run: gh issue view 1\n      - uses: ./.github/actions/agent\n",
			"runs:\n  using: composite\n  steps:\n    - uses: actions/ai-inference@v2\n      with:\n        prompt: ${{ steps.s.outputs.b }}\n", nil},
		{"an output of the action carries what it fetched",
			head + "    steps:\n      - id: act\n        uses: ./.github/actions/agent\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ steps.act.outputs.b }}\n",
			"runs:\n  using: composite\n  steps:\n    - run: gh issue view 1\n      shell: bash\n",
			[]string{"low untrusted-input .github/workflows/main.yml"}},
		{"a head checkout inside counts",
			"on: pull_request_target\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: ./.github/actions/agent\n      - uses: actions/ai-inference@v2\n",
			"runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v7\n      with:\n        ref: ${{ github.event.pull_request.head.sha }}\n",
			[]string{"medium untrusted-checkout .github/workflows/main.yml"}},
		{"a docker action has no steps", head + "    steps:\n      - uses: ./.github/actions/agent\n", "runs:\n  using: docker\n  image: Dockerfile\n", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, w := follow(t, map[string]string{mainWF: c.wf, action: c.act}, mainWF)
			if s := summarize(got); !reflect.DeepEqual(s, c.want) {
				t.Errorf("got %v; want %v", s, c.want)
			}
			if len(w) != 0 {
				t.Errorf("warnings = %v", w)
			}
		})
	}
}

func TestCompositeSeesItsCallerEnv(t *testing.T) {
	const act = "act/action.yml"
	cases := []struct {
		name, env, body string
		want            []string
	}{
		{"referenced", "T: ${{ github.event.issue.title }}", "uses: actions/ai-inference@v2\n      with:\n        prompt: ${{ env.T }}", []string{"low untrusted-input " + act}},
		{"inherited by a command", "T: ${{ github.event.issue.title }}", "run: claude -p \"$T\"\n      shell: bash", []string{"medium untrusted-input " + act}},
		{"a setting that widens the agent", "GEMINI_CLI_AUTO_APPROVE: 'true'", "uses: google-github-actions/run-gemini-cli@v0", []string{"high broad-tools " + act, "high open-invocation " + act}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _ := follow(t, map[string]string{
				mainWF: "on: issues\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: ./act\n        env:\n          " + c.env + "\n",
				act:    "runs:\n  using: composite\n  steps:\n    - " + c.body + "\n",
			}, mainWF)
			if s := summarize(got); !reflect.DeepEqual(s, c.want) {
				t.Errorf("got %v; want %v", s, c.want)
			}
		})
	}
}

func TestCompositeLineStaysInItsOwnFile(t *testing.T) {
	got, _ := follow(t, map[string]string{
		mainWF:           "on: issues\npermissions: {}\nenv:\n  # padding\n  T: ${{ github.event.issue.title }}\njobs:\n  a:\n    steps:\n      - uses: ./act\n",
		"act/action.yml": "runs:\n  using: composite\n  steps:\n    - uses: actions/ai-inference@v2\n",
	}, mainWF)
	if len(got) != 1 || got[0].File != "act/action.yml" || got[0].Line != 4 {
		t.Errorf("findings = %+v", got)
	}
}

func TestCallingStepIfReadsItsOwnScope(t *testing.T) {
	got, _ := follow(t, map[string]string{
		mainWF:           "on: issue_comment\njobs:\n  a:\n    steps:\n      - id: flag\n        run: echo\n      - if: steps.flag.outputs.on == 'true'\n        uses: ./act\n",
		"act/action.yml": "runs:\n  using: composite\n  steps:\n    - uses: openai/codex-action@v1\n      with:\n        allow-users: '*'\n",
	}, mainWF)
	if len(got) != 1 || got[0].Severity != High || strings.Contains(got[0].Message, "run-time check") {
		t.Errorf("findings = %+v", got)
	}
}

func TestCompositeNamesTheWorkflow(t *testing.T) {
	got, _ := follow(t, map[string]string{
		mainWF:           "on: issue_comment\njobs:\n  a:\n    steps:\n      - uses: ./act\n",
		"act/action.yml": "runs:\n  using: composite\n  steps:\n    - uses: openai/codex-action@v1\n      with:\n        allow-users: '*'\n",
	}, mainWF)
	if len(got) != 1 || got[0].File != "act/action.yml" || !strings.Contains(got[0].Message, "in "+mainWF) {
		t.Errorf("findings = %+v", got)
	}
}

func TestCompositeNestedInputAndYamlName(t *testing.T) {
	got, _ := follow(t, map[string]string{
		mainWF:              "on: issue_comment\npermissions: {}\njobs:\n  a:\n    steps:\n      - uses: ./outer\n        with:\n          t: ${{ github.event.comment.body }}\n",
		"outer/action.yaml": "runs:\n  using: composite\n  steps:\n    - uses: ./inner\n      with:\n        t: ${{ inputs.t }}\n",
		"inner/action.yml":  "runs:\n  using: composite\n  steps:\n    - uses: actions/ai-inference@v2\n      with:\n        prompt: ${{ inputs.t }}\n",
	}, mainWF)
	if s := summarize(got); !reflect.DeepEqual(s, []string{"low untrusted-input inner/action.yml"}) {
		t.Errorf("got %v", s)
	}
}

func TestCompositeRecursionAndBadFile(t *testing.T) {
	got, w := follow(t, map[string]string{
		mainWF:            "on: issues\njobs:\n  a:\n    steps:\n      - uses: ./loop\n      - uses: ./bad\n",
		"loop/action.yml": "runs:\n  using: composite\n  steps:\n    - uses: ./loop\n",
		"bad/action.yml":  "a: [",
	}, mainWF)
	if len(got) != 0 {
		t.Errorf("findings = %v", got)
	}
	if len(w) != 1 || !strings.Contains(w[0], "bad/action.yml") {
		t.Errorf("warnings = %v", w)
	}
}

func TestCommittedConfigNarrowsAWideDefault(t *testing.T) {
	const wf = "on: issues\npermissions: {}\njobs:\n  a:\n    steps:\n      - run: opencode run triage\n"
	got, _ := follow(t, map[string]string{mainWF: wf}, mainWF)
	if s := summarize(got); len(s) != 2 {
		t.Errorf("without a config: %v", s)
	}
	got, _ = follow(t, map[string]string{mainWF: wf, "opencode.json": "{}"}, mainWF)
	if s := summarize(got); !reflect.DeepEqual(s, []string{"medium open-invocation " + mainWF}) {
		t.Errorf("with a config: %v", s)
	}
	const auto = "on: issues\npermissions: {}\njobs:\n  a:\n    steps:\n      - run: opencode run --auto triage\n"
	got, _ = follow(t, map[string]string{mainWF: auto, "opencode.json": "{}"}, mainWF)
	if s := summarize(got); len(s) != 2 {
		t.Errorf("auto mode overrides a config: %v", s)
	}
}
