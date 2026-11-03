// Package audit applies the rules to workflows and agent config files.
package audit

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/somaz94/agentic-workflow-guard/internal/reach"
	"github.com/somaz94/agentic-workflow-guard/internal/registry"
	"github.com/somaz94/agentic-workflow-guard/internal/workflow"
)

// Severity orders findings. Higher is worse.
type Severity int

// Severities.
const (
	Low Severity = iota + 1
	Medium
	High
)

func (s Severity) String() string {
	switch s {
	case High:
		return "high"
	case Medium:
		return "medium"
	}
	return "low"
}

// Finding is one result.
type Finding struct {
	Rule     string
	Severity Severity
	File     string
	Line     int
	Message  string
}

var (
	statusOverride = regexp.MustCompile(`(?i)\b(always|failure|cancelled)\s*\(`)
	headCheckout   = regexp.MustCompile(`github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/|steps\.[\w-]+\.outputs\.[\w-]*(sha|head|ref)`)
	sameRepoRef    = regexp.MustCompile(`head\.repo\.full_name\s*==\s*github\.repository\s*&&`)
	prCheckout     = regexp.MustCompile(`gh pr checkout`)
	prFetch        = regexp.MustCompile(`refs/pull/|pull/[^ ]*/(head|merge)`)
	gitCheckout    = regexp.MustCompile(`git\s+(checkout|switch|worktree\s+add|reset\s+--hard)`)
	contextObject  = regexp.MustCompile(`github\.event\.(issue|comment|discussion|pull_request|workflow_run)\.`)
	bashTool       = regexp.MustCompile(`\bBash\(([^)]*)\)`)
	bareBash       = regexp.MustCompile(`(^|[\s,"'=])Bash($|[\s,"'])`)
	templateExpr   = regexp.MustCompile(`\$\{\{.*?\}\}`)
	fileToken      = regexp.MustCompile(`[\w./-]+\.[A-Za-z]\w*`)
	stepOutput     = regexp.MustCompile(`steps\.([\w-]+)\.outputs\.[\w-]+`)
	allowedArg     = regexp.MustCompile(`(?i)--allowed-?tools[ =]("[^"]*"|'[^']*'|[^ -][^ ]*(?: [^ -][^ ]*)*)`)
	deniedArg      = regexp.MustCompile(`(?i)--disallowed-?tools[ =]("[^"]*"|'[^']*'|\S+)|"(deny|disallowedTools)"\s*:\s*\[[^\]]*\]`)
)

type auditor struct {
	reg  *registry.Registry
	file string
	wf   *workflow.Workflow
}

// Workflow audits one parsed workflow file.
func Workflow(reg *registry.Registry, file string, wf *workflow.Workflow) []Finding {
	a := &auditor{reg: reg, file: file, wf: wf}
	var out []Finding
	for _, job := range wf.Jobs {
		for i := range job.Steps {
			if agent := reg.Find(job.Steps[i].Uses); agent != nil {
				out = append(out, a.step(job, i, agent)...)
			}
		}
	}
	return out
}

// exposure is how far each actor gets through the gates alone, before the
// action's own actor check.
type exposure struct {
	state       reach.State
	contributor bool
	events      []string
}

func (a *auditor) exposure(job *workflow.Job, idx int) exposure {
	var out exposure
	for event, types := range a.wf.Triggers {
		if !reach.SecretEvents(event) {
			continue
		}
		actions := reach.Actions(event, types)
		if len(actions) == 0 {
			continue
		}
		ctx := reach.Context{Event: event, Actions: actions, IsGate: a.gateOutput(job, idx)}
		s := a.stepState(job, idx, ctx)
		contributor := false
		if s == reach.None {
			ctx.Actor = reach.PriorContributor
			if s = a.stepState(job, idx, ctx); s != reach.None {
				contributor = true
			}
		}
		if s == reach.None {
			continue
		}
		out.events = append(out.events, event)
		// An outsider's path outranks one that needs a merged commit.
		if s > out.state || (s == out.state && out.contributor && !contributor) {
			out.state, out.contributor = s, contributor
		}
	}
	return out
}

// gateOutput decides whether a referenced output can carry an authorization
// result, from the output's name or from what produced it.
func (a *auditor) gateOutput(job *workflow.Job, idx int) func([]string) bool {
	return func(ref []string) bool {
		if len(ref) < 2 {
			return true
		}
		if a.reg.GateOutput.MatchString(ref[len(ref)-1]) {
			return true
		}
		if ref[0] == "needs" {
			need := a.wf.JobByName(ref[1])
			if need == nil {
				return true
			}
			if a.reg.Authorization.MatchString(need.If) || a.reg.GateOutput.MatchString(need.Name) {
				return true
			}
			for _, st := range need.Steps {
				if a.authorizes(st) {
					return true
				}
			}
			return false
		}
		for _, st := range job.Steps[:idx] {
			if strings.EqualFold(st.ID, ref[1]) {
				return a.authorizes(st)
			}
		}
		return true
	}
}

func (a *auditor) stepState(job *workflow.Job, idx int, ctx reach.Context) reach.State {
	s := reach.Combine(a.jobState(job, ctx, map[string]bool{}), reach.Eval(job.Steps[idx].If, ctx))
	for _, prior := range job.Steps[:idx] {
		if a.authorizes(prior) {
			s = reach.Combine(s, reach.Indeterminate)
		}
	}
	return s
}

func (a *auditor) jobState(job *workflow.Job, ctx reach.Context, seen map[string]bool) reach.State {
	s := reach.Eval(job.If, ctx)
	if seen[job.Name] {
		return s
	}
	seen[job.Name] = true
	if statusOverride.MatchString(job.If) {
		return s
	}
	for _, name := range job.Needs {
		need := a.wf.JobByName(name)
		if need == nil {
			continue
		}
		s = reach.Combine(s, a.jobState(need, ctx, seen))
		for _, st := range need.Steps {
			if a.authorizes(st) {
				s = reach.Combine(s, reach.Indeterminate)
			}
		}
	}
	return s
}

func (a *auditor) authorizes(s workflow.Step) bool {
	text := s.Run + " " + s.Uses
	for _, in := range s.With {
		text += " " + in.Value
	}
	return a.reg.Authorization.MatchString(text)
}

func anyWildcard(s workflow.Step, names []string) (int, bool) {
	for _, n := range names {
		in, ok := s.With[n]
		if !ok {
			continue
		}
		for _, part := range strings.Split(in.Value, ",") {
			if strings.TrimSpace(part) == "*" {
				return in.Line, true
			}
		}
	}
	return 0, false
}

func (a *auditor) step(job *workflow.Job, idx int, agent *registry.Agent) []Finding {
	st := job.Steps[idx]
	exp := a.exposure(job, idx)
	wildLine, wildcard := anyWildcard(st, agent.WildcardInputs)
	botLine, botWildcard := anyWildcard(st, agent.BotWildcardInputs)

	state := exp.state
	if agent.ActorCheck && !wildcard {
		state = reach.None
	}
	power := Power(a.reg, agent, st)
	writes := a.writes(job)
	inputLine, inputRef := a.untrustedInput(job, idx, exp.events)
	who := "any GitHub user"
	if exp.contributor {
		who = "anyone with one previously merged commit"
	}

	var out []Finding
	add := func(rule string, sev Severity, line int, msg string) {
		if state == reach.Indeterminate {
			sev = lower(sev)
			msg += " A run-time check may gate this; verify that it does."
		}
		if line == 0 {
			line = st.Line
		}
		out = append(out, Finding{Rule: rule, Severity: sev, File: a.file, Line: line,
			Message: fmt.Sprintf("job %q: %s", job.Name, msg)})
	}
	bySeverity := func(broad, scoped, limited Severity) Severity {
		switch power {
		case registry.Broad:
			return broad
		case registry.Scoped:
			return scoped
		}
		return limited
	}
	writeSplit := func(withWrite, without Severity) Severity {
		if writes {
			return withWrite
		}
		return without
	}

	if state != reach.None {
		switch {
		case wildcard:
			add(RuleOpenInvocation, bySeverity(High, writeSplit(High, Medium), writeSplit(Medium, Low)), wildLine,
				fmt.Sprintf("%s can invoke the %s agent because its actor allowlist is '*'.", who, agent.ID))
		case !agent.ActorCheck && inputRef == "" && power != registry.Limited:
			add(RuleOpenInvocation, bySeverity(High, Medium, Low), st.Line,
				fmt.Sprintf("%s can start the %s agent, which has no built-in actor check, and it can read their content through its tools.", who, agent.ID))
		}
		if inputRef != "" {
			add(RuleUntrustedInput, bySeverity(High, writeSplit(High, Medium), writeSplit(Medium, Low)), inputLine,
				fmt.Sprintf("%s can write %s, which flows into the %s agent's input.", who, inputRef, agent.ID))
		}
		if a.checksOutHead(job, idx) {
			add(RuleUntrustedCheckout, bySeverity(High, High, Medium), st.Line,
				fmt.Sprintf("the %s agent runs after checking out code %s controls, on a trigger with access to secrets.", agent.ID, who))
		}
	}
	if botWildcard && exp.state != reach.None && !wildcard {
		saved := state
		state = exp.state
		add(RuleOpenInvocation, Medium, botLine,
			fmt.Sprintf("any GitHub App can invoke the %s agent because its bot allowlist is '*'.", agent.ID))
		state = saved
	}
	if power == registry.Broad {
		sev := Low
		// add lowers this once when the gate is only unverified.
		if state != reach.None {
			sev = High
		}
		add(RuleBroadTools, sev, st.Line,
			fmt.Sprintf("the %s agent can run arbitrary commands: an exec-equivalent tool, auto-approval or a full-access sandbox is enabled.", agent.ID))
	}
	for _, name := range agent.FullOutputInputs {
		if in, ok := st.With[name]; ok && strings.EqualFold(in.Value, "true") {
			add(RuleFullOutput, Low, in.Line, "full agent output is written to the job log, which can expose tool results and secrets.")
		}
	}
	return out
}

func lower(s Severity) Severity {
	if s == Low {
		return Low
	}
	return s - 1
}

func (a *auditor) writes(job *workflow.Job) bool {
	p := job.Permissions
	if !p.Set {
		p = a.wf.Permissions
	}
	// An absent block inherits the repository default, which may be write.
	return !p.Set || len(p.Writes) > 0
}

func (a *auditor) checksOutHead(job *workflow.Job, idx int) bool {
	for _, s := range job.Steps[:idx] {
		// Fetching a pull request's refs only stores objects; the working tree is
		// what an agent reads config and instructions from.
		if prCheckout.MatchString(s.Run) || (prFetch.MatchString(s.Run) && gitCheckout.MatchString(s.Run)) {
			return true
		}
		if !strings.Contains(strings.ToLower(s.Uses), "actions/checkout") {
			continue
		}
		ref := s.With["ref"].Value
		// `same repo && head.sha || base.sha` checks out the base for a fork.
		if sameRepoRef.MatchString(ref) {
			continue
		}
		if headCheckout.MatchString(ref) || headCheckout.MatchString(s.With["repository"].Value) {
			return true
		}
	}
	return false
}

// untrustedInput finds an attacker-written field in the agent's inputs that an
// event the outsider can reach actually carries, directly or one step away.
func (a *auditor) untrustedInput(job *workflow.Job, idx int, events []string) (int, string) {
	st := job.Steps[idx]
	scopes := []map[string]workflow.Input{st.With, st.Env, job.Env, a.wf.Env}
	for _, scope := range scopes {
		for _, name := range sortedKeys(scope) {
			in := scope[name]
			for _, m := range a.reg.Untrusted.FindAllString(in.Value, -1) {
				if ref := a.carriedRef(m, events); ref != "" {
					return in.Line, ref
				}
			}
		}
	}
	if len(events) == 0 {
		return 0, ""
	}
	return a.fetchedInput(job, idx)
}

// fetchedInput follows one hop: an agent input that names a prior step's output
// or a file that step writes, when that step pulls attacker-written text in.
func (a *auditor) fetchedInput(job *workflow.Job, idx int) (int, string) {
	st := job.Steps[idx]
	for _, name := range sortedKeys(st.With) {
		in := st.With[name]
		for _, prior := range job.Steps[:idx] {
			if !a.fetchesUntrusted(prior) {
				continue
			}
			for _, m := range stepOutput.FindAllStringSubmatch(in.Value, -1) {
				if prior.ID != "" && strings.EqualFold(m[1], prior.ID) {
					return in.Line, fmt.Sprintf("text fetched by step %q", prior.ID)
				}
			}
			if strings.HasSuffix(name, "-file") || name == "file_input" {
				for _, f := range fileToken.FindAllString(in.Value, -1) {
					// A temp directory is spelled differently on each side, so only
					// the file name is comparable.
					if base := path.Base(f); strings.Contains(prior.Run, base) {
						return in.Line, fmt.Sprintf("the file %s, written from fetched text,", base)
					}
				}
			}
		}
	}
	return 0, ""
}

func (a *auditor) fetchesUntrusted(s workflow.Step) bool {
	text := s.Run
	for _, in := range s.With {
		text += " " + in.Value
	}
	for _, in := range s.Env {
		text += " " + in.Value
	}
	return a.reg.UntrustedFetch.MatchString(text)
}

func (a *auditor) carriedRef(tmpl string, events []string) string {
	ref := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(tmpl, "${{"), "}}"))
	if strings.Contains(tmpl, "github.head_ref") {
		for _, e := range events {
			if e == "pull_request_target" {
				return ref
			}
		}
		return ""
	}
	m := contextObject.FindStringSubmatch(tmpl)
	if m == nil {
		return ""
	}
	for _, e := range events {
		if reach.Carries(e, m[1]) {
			return ref
		}
	}
	return ""
}

// Power resolves what an agent step can do from its inputs.
func Power(reg *registry.Registry, agent *registry.Agent, st workflow.Step) registry.Power {
	limited := matchesAny(agent.LimitedWhen, st.With) || readOnlyAllowlist(agent, st)
	if agent.SettingsInput != "" && readOnlySettings(st.With[agent.SettingsInput].Value) {
		limited = true
	}
	broad := matchesAny(agent.BroadWhen, st.With) || matchesAny(agent.BroadWhenEnv, st.Env)
	for _, name := range agent.ToolInputs {
		if len(ExecTools(reg, st.With[name].Value)) > 0 {
			broad = true
		}
	}
	switch {
	case limited:
		return registry.Limited
	case broad:
		return registry.Broad
	case matchesAny(agent.ScopedWhen, st.With):
		return registry.Scoped
	}
	return agent.DefaultPower()
}

// readOnlyAllowlist reports an explicit allowlist, in the arguments or in a
// settings value, that holds only read-only tools. An agent with neither keeps
// its default.
func readOnlyAllowlist(agent *registry.Agent, st workflow.Step) bool {
	found := false
	if agent.AllowlistInput != "" {
		if m := allowedArg.FindStringSubmatch(st.With[agent.AllowlistInput].Value); m != nil {
			tools := splitTools(strings.Trim(m[1], `"'`))
			if len(tools) == 0 || !allReadOnly(agent, tools) {
				return false
			}
			found = true
		}
	}
	if agent.AllowSettingsInput != "" {
		var doc struct {
			Permissions struct {
				Allow []string `json:"allow"`
			} `json:"permissions"`
		}
		raw := templateExpr.ReplaceAllString(st.With[agent.AllowSettingsInput].Value, "null")
		if json.Unmarshal([]byte(raw), &doc) == nil && len(doc.Permissions.Allow) > 0 {
			if !allReadOnly(agent, doc.Permissions.Allow) {
				return false
			}
			found = true
		}
	}
	return found
}

// splitTools splits on commas and spaces outside parentheses, because a Bash
// permission such as `Bash(gh pr view:*)` holds spaces itself.
func splitTools(s string) []string {
	var out []string
	depth, start := 0, 0
	flush := func(end int) {
		if t := strings.TrimSpace(s[start:end]); t != "" {
			out = append(out, t)
		}
	}
	for i, r := range s {
		switch {
		case r == '(':
			depth++
		case r == ')':
			depth--
		case (r == ',' || r == ' ') && depth == 0:
			flush(i)
			start = i + 1
		}
	}
	flush(len(s))
	return out
}

func allReadOnly(agent *registry.Agent, tools []string) bool {
	for _, t := range tools {
		known := false
		for _, ok := range agent.ReadOnlyTools {
			known = known || ok == t
		}
		if !known {
			return false
		}
	}
	return true
}

func matchesAny(rules []registry.Match, inputs map[string]workflow.Input) bool {
	for _, r := range rules {
		if in, ok := inputs[r.Input]; ok && r.Matches(in.Value) {
			return true
		}
	}
	return false
}

// ExecTools returns the tool permissions in text that amount to running any
// program. A permission with a subcommand, such as `git log:*`, is not one.
func ExecTools(reg *registry.Registry, text string) []string {
	text = deniedArg.ReplaceAllString(text, " ")
	var out []string
	for _, m := range bashTool.FindAllStringSubmatch(text, -1) {
		cmd := strings.TrimSpace(strings.TrimSuffix(strings.TrimSuffix(m[1], "*"), ":"))
		if cmd == "" || (!strings.ContainsAny(cmd, " \t") && reg.ExecCommands[cmd]) {
			out = append(out, m[0])
		}
	}
	if bareBash.MatchString(text) {
		out = append(out, "Bash")
	}
	return out
}

// readOnlySettings reports a Gemini settings value whose tools are limited to
// harmless shell commands with no MCP server. Auto-approval then approves
// nothing that matters, which is how Google's triage template is built.
func readOnlySettings(raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return false
	}
	var doc struct {
		Tools struct {
			Core []string `json:"core"`
		} `json:"tools"`
		CoreTools  []string                   `json:"coreTools"`
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	// A template is not JSON until the runner renders it, and none of them decide
	// the tool list in practice.
	rendered := templateExpr.ReplaceAllString(raw, "null")
	if json.Unmarshal([]byte(rendered), &doc) != nil || len(doc.MCPServers) > 0 {
		return false
	}
	tools := append(doc.Tools.Core, doc.CoreTools...)
	if len(tools) == 0 {
		return false
	}
	for _, t := range tools {
		if t != "run_shell_command(echo)" {
			return false
		}
	}
	return true
}
