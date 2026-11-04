// Package audit applies the rules to workflows and agent config files.
package audit

import (
	"encoding/json"
	"fmt"
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
	headCheckout   = regexp.MustCompile(`github\.event\.pull_request\.head\.sha|github\.event\.workflow_run\.head_sha|refs/pull/|(steps|needs)\.[\w-]+\.outputs\.[\w-]*(sha|head|ref)`)
	headRefName    = regexp.MustCompile(`github\.event\.pull_request\.head\.ref|github\.head_ref|github\.event\.workflow_run\.head_branch`)
	headRepo       = regexp.MustCompile(`github\.event\.pull_request\.head\.repo\.|github\.event\.workflow_run\.head_repository\.|steps\.[\w-]+\.outputs\.[\w-]*repo`)
	sameRepoRef    = regexp.MustCompile(`head\.repo\.full_name\s*==\s*github\.repository\s*&&`)
	prCheckout     = regexp.MustCompile(`gh pr checkout`)
	prFetch        = regexp.MustCompile(`refs/pull/|pull/[^ ]*/(head|merge)`)
	gitCheckout    = regexp.MustCompile(`git\s+(checkout|switch|worktree\s+add|reset\s+--hard)`)
	bashTool       = regexp.MustCompile(`\bBash\(([^)]*)\)`)
	bareBash       = regexp.MustCompile(`(^|[\s,"'=])Bash($|[\s,"'])`)
	templateExpr   = regexp.MustCompile(`\$\{\{.*?\}\}`)
	allowedArg     = regexp.MustCompile(`(?i)--allowed-?tools[ =]("[^"]*"|'[^']*'|[^ -][^ ]*(?: [^ -][^ ]*)*)`)
	denyList       = regexp.MustCompile(`(?i)--disallowed-?tools[ =]("[^"]*"|'[^']*'|\S+)`)
	refName        = regexp.MustCompile(`\b(?:env|inputs)\.[\w-]+`)
	deniedArg      = regexp.MustCompile(`(?i)--disallowed-?tools[ =]("[^"]*"|'[^']*'|\S+)|"(deny|disallowedTools)"\s*:\s*\[[^\]]*\]`)
)

type auditor struct {
	reg  *registry.Registry
	file string
	wf   *workflow.Workflow
	src  Source
	// call is the job that called this workflow, nil for a workflow run directly.
	call   *callSite
	warn   func(string)
	budget *budget
	// flats and frames hold each job with its composite actions expanded in place.
	flats  map[*workflow.Job]*workflow.Job
	frames map[*workflow.Job][]*frame
}

func newAuditor(reg *registry.Registry, src Source, file string, wf *workflow.Workflow, call *callSite, warn func(string)) *auditor {
	return &auditor{reg: reg, file: file, wf: wf, src: src, call: call, warn: warn, budget: newBudget(),
		flats: map[*workflow.Job]*workflow.Job{}, frames: map[*workflow.Job][]*frame{}}
}

// Workflow audits one parsed workflow file by itself, following nothing outside
// it.
func Workflow(reg *registry.Registry, file string, wf *workflow.Workflow) []Finding {
	return newAuditor(reg, nil, file, wf, nil, func(string) {}).run()
}

func (a *auditor) run() []Finding {
	var out []Finding
	for _, job := range a.wf.Jobs {
		if job.Uses != "" {
			out = append(out, a.follow(job)...)
			continue
		}
		flat := a.flat(job)
		for i := range flat.Steps {
			if a.budget.exceeded() {
				return out
			}
			for _, agent := range a.agentsAt(flat, i) {
				out = append(out, a.step(flat, i, agent)...)
			}
		}
	}
	return out
}

// agentsAt finds the agents a step runs. A command in a `run:` step becomes an
// input, so the rest of the audit reads it like any action's.
func (a *auditor) agentsAt(job *workflow.Job, i int) []*registry.Agent {
	st := &job.Steps[i]
	if agent := a.reg.Find(st.Uses); agent != nil {
		return []*registry.Agent{agent}
	}
	agents := a.reg.FindRuns(st.Run)
	if len(agents) > 0 {
		st.With = map[string]workflow.Input{registry.RunInput: {Value: st.Run, Line: st.Line}}
	}
	return agents
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
	for event, types := range a.triggers() {
		if !reach.SecretEvents(event) || a.budget.exceeded() {
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
		// An input or env flag is a value the file or its caller sets, not a check.
		if ref[0] == "inputs" || ref[0] == "env" {
			return false
		}
		if ref[0] == "needs" {
			need := a.wf.JobByName(ref[1])
			if need == nil {
				return true
			}
			if a.reg.Authorization.MatchString(need.If) || a.reg.GateOutput.MatchString(need.Name) {
				return true
			}
			for _, st := range a.flat(need).Steps {
				if a.authorizes(st) {
					return true
				}
			}
			return false
		}
		if i := a.priorStep(job, idx, ref[1]); i >= 0 {
			return a.authorizes(job.Steps[i])
		}
		return true
	}
}

func (a *auditor) stepState(job *workflow.Job, idx int, ctx reach.Context) reach.State {
	s := reach.Combine(a.jobState(job, ctx, map[string]bool{}), reach.Eval(job.Steps[idx].If, ctx))
	for fr := a.frameAt(job, idx); fr != nil; fr = fr.parent {
		// A calling step's `if:` reads the step ids of the scope it sits in.
		ctx.IsGate = a.gateOutput(job, fr.at)
		s = reach.Combine(s, reach.Eval(job.Steps[fr.at].If, ctx))
	}
	s = reach.Combine(s, a.callerState(ctx))
	// `if: always()` runs the agent whether or not the check before it passed.
	if statusOverride.MatchString(job.Steps[idx].If) {
		return s
	}
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
		for _, st := range a.flat(need).Steps {
			if a.authorizes(st) {
				s = reach.Combine(s, reach.Indeterminate)
			}
		}
	}
	return s
}

// authorizes reports a step that can stop the job on an authorization check. One
// that may fail without stopping it decides nothing, and a comment checks nothing.
func (a *auditor) authorizes(s workflow.Step) bool {
	if s.ContinueOnError {
		return false
	}
	text := withoutComments(s.Run) + " " + s.Uses
	for _, in := range s.With {
		text += " " + in.Value
	}
	return a.reg.Authorization.MatchString(text)
}

func withoutComments(script string) string {
	var kept []string
	for _, line := range strings.Split(script, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "#") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}

// anyWildcard finds `*` in an allowlist. computed is true when one comes from an
// expression, which can hold `*` only at run time.
func anyWildcard(s workflow.Step, names []string) (line int, wildcard, computed bool) {
	for _, n := range names {
		in, ok := s.With[n]
		if !ok {
			continue
		}
		for _, part := range strings.Split(in.Value, ",") {
			if strings.TrimSpace(part) == "*" {
				return in.Line, true, false
			}
		}
		if strings.Contains(in.Value, "${{") {
			line, computed = in.Line, true
		}
	}
	return line, false, computed
}

func (a *auditor) step(job *workflow.Job, idx int, agent *registry.Agent) []Finding {
	st := job.Steps[idx]
	exp := a.exposure(job, idx)
	wildLine, wildcard, computed := anyWildcard(st, agent.WildcardInputs)
	botLine, botWildcard, _ := anyWildcard(st, agent.BotWildcardInputs)

	state := exp.state
	switch {
	case agent.ActorCheck && computed:
		state = reach.Combine(state, reach.Indeterminate)
	case agent.ActorCheck && !wildcard:
		state = reach.None
	}
	power := Power(a.reg, agent, a.withScopedEnv(job, idx, st))
	if power == registry.Broad && !matchesAny(agent.BroadWhen, st.With) && a.narrowedByConfig(agent) {
		power = registry.Scoped
	}
	writes := a.writes(job)
	inputLine, inputRef := a.untrustedInput(job, idx, exp.events)
	file := a.fileAt(job, idx)
	where := fmt.Sprintf("job %q", job.Name)
	switch {
	case a.frameAt(job, idx) != nil:
		where += " in " + a.file
	case a.call != nil:
		where += " called from " + a.call.a.file
	}
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
		out = append(out, Finding{Rule: rule, Severity: sev, File: file, Line: line,
			Message: where + ": " + msg})
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
		case computed:
			add(RuleOpenInvocation, bySeverity(High, writeSplit(High, Medium), writeSplit(Medium, Low)), wildLine,
				fmt.Sprintf("%s may be able to invoke the %s agent, because an expression sets its actor allowlist and can hold '*'.", who, agent.ID))
		case !agent.ActorCheck && inputRef == "" && power != registry.Limited:
			add(RuleOpenInvocation, bySeverity(High, Medium, Low), st.Line,
				fmt.Sprintf("%s can start the %s agent, which has no built-in actor check, and it can read their content through its tools.", who, agent.ID))
		}
		if inputRef != "" {
			add(RuleUntrustedInput, bySeverity(High, writeSplit(High, Medium), writeSplit(Medium, Low)), inputLine,
				fmt.Sprintf("%s can write %s, which flows into the %s agent's input.", who, inputRef, agent.ID))
		}
		switch a.checkoutOf(job, idx) {
		case headCode:
			add(RuleUntrustedCheckout, bySeverity(High, High, Medium), st.Line,
				fmt.Sprintf("the %s agent runs after checking out code %s controls, on a trigger with access to secrets.", agent.ID, who))
		case headBranch:
			add(RuleUntrustedCheckout, lower(bySeverity(High, High, Medium)), st.Line,
				fmt.Sprintf("the %s agent runs after checking out a branch name %s chooses. It resolves in this repository, unless it is spelled like refs/pull/1/head, which actions/checkout fetches as a pull request.", agent.ID, who))
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

// withScopedEnv gives a step the env it runs with, nearest scope winning, because
// an agent reads a setting from any of them.
func (a *auditor) withScopedEnv(job *workflow.Job, idx int, st workflow.Step) workflow.Step {
	env := map[string]workflow.Input{}
	own, _ := a.stepEnvs(job, idx)
	written := map[string]workflow.Input{}
	for _, prior := range job.Steps[:idx] {
		if strings.Contains(prior.Run, "GITHUB_ENV") {
			for _, m := range shellSet.FindAllStringSubmatch(prior.Run, -1) {
				written[m[1]] = workflow.Input{Value: m[2]}
			}
		}
	}
	scopes := []map[string]workflow.Input{a.wf.Env, job.Env, written}
	for i := len(own) - 1; i >= 0; i-- {
		scopes = append(scopes, own[i])
	}
	for _, scope := range scopes {
		for k, v := range scope {
			env[k] = v
		}
	}
	st.Env = env
	return st
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
	if a.call != nil {
		// A called workflow can narrow the caller's token and cannot widen it.
		caller := a.call.a.writes(a.call.job)
		return caller && (!p.Set || len(p.Writes) > 0)
	}
	// An absent block inherits the repository default, which may be write.
	return !p.Set || len(p.Writes) > 0
}

// checkout is what a job's earlier steps put in the working tree.
type checkout int

const (
	baseCode checkout = iota
	// headBranch is a ref by a name the author chose, in this repository.
	headBranch
	// headCode is the author's commit.
	headCode
)

func (a *auditor) checkoutOf(job *workflow.Job, idx int) checkout {
	found := baseCode
	for i, s := range job.Steps[:idx] {
		// Fetching a pull request's refs only stores objects; the working tree is
		// what an agent reads config and instructions from.
		if prCheckout.MatchString(s.Run) || (prFetch.MatchString(s.Run) && gitCheckout.MatchString(s.Run)) {
			return headCode
		}
		if !strings.Contains(strings.ToLower(s.Uses), "actions/checkout") {
			continue
		}
		ref := a.resolved(s.With["ref"].Value, job, i)
		// `same repo && head.sha || base.sha` checks out the base for a fork, which
		// takes the branch after `||`, so that is the part a fork reaches.
		first, rest, hasOr := strings.Cut(ref, "||")
		if sameRepoRef.MatchString(first) && hasOr && !headCheckout.MatchString(rest) && !headRefName.MatchString(rest) {
			continue
		}
		ref = withPaths(ref)
		if headCheckout.MatchString(ref) || headRepo.MatchString(withPaths(a.resolved(s.With["repository"].Value, job, i))) {
			return headCode
		}
		if headRefName.MatchString(ref) {
			found = headBranch
		}
	}
	return found
}

// resolved writes out what `env.X` and `inputs.X` stand for, so a value set further
// away reads like one written here. Three rounds cover what real workflows chain,
// and the cap keeps a hostile one small.
func (a *auditor) resolved(value string, job *workflow.Job, idx int) string {
	for round := 0; round < 3 && len(value) < maxResolved; round++ {
		value = refName.ReplaceAllStringFunc(value, func(ref string) string {
			scope, name, _ := strings.Cut(ref, ".")
			if scope == "inputs" {
				return a.inputText(name, job, idx, ref)
			}
			envs, _ := a.stepEnvs(job, idx)
			for _, m := range append(envs, job.Env, a.wf.Env) {
				if in, ok := lookup(m, name); ok {
					return in.Value
				}
			}
			return ref
		})
	}
	return value
}

// withPaths appends every path in normalized form, so `head['sha']` reads like
// `head.sha`.
func withPaths(value string) string {
	var paths []string
	for _, body := range templateBodies(value) {
		for _, p := range flowPaths(body) {
			paths = append(paths, strings.Join(p, "."))
		}
	}
	return value + " " + strings.Join(paths, " ")
}

func (a *auditor) inputText(name string, job *workflow.Job, idx int, fallback string) string {
	scopes := []map[string]workflow.Input{}
	if fr := a.frameAt(job, idx); fr != nil {
		scopes = append(scopes, fr.with, fr.defaults)
	} else if a.call != nil {
		scopes = append(scopes, a.call.job.With, a.wf.CallInputs)
	}
	for _, scope := range scopes {
		if in, ok := lookup(scope, name); ok {
			return in.Value
		}
	}
	return fallback
}

// untrustedInput finds attacker-written text in the agent's inputs, for an event
// the outsider can reach: directly, or through what earlier steps and jobs did
// with it.
func (a *auditor) untrustedInput(job *workflow.Job, idx int, events []string) (int, string) {
	if len(events) == 0 {
		return 0, ""
	}
	t, w := newTracer(events, a.budget), where{a: a, job: job, idx: idx}
	st := job.Steps[idx]
	for _, name := range sortedKeys(st.With) {
		if d := t.origin(st.With[name].Value, w); d != "" {
			return st.With[name].Line, d
		}
	}
	// The agent's process inherits these whether or not its inputs name them. A line
	// outside the step's own file would not mean anything next to it, so the finding
	// falls back to the step.
	envs, at := a.stepEnvs(job, idx)
	for level, scope := range envs {
		for _, name := range sortedKeys(scope) {
			if d := t.origin(scope[name].Value, where{a: a, job: job, idx: at[level], envFloor: 1}); d != "" {
				return a.lineIn(job, idx, level == 0, scope[name].Line), d
			}
		}
	}
	for i, scope := range []map[string]workflow.Input{job.Env, a.wf.Env} {
		for _, name := range sortedKeys(scope) {
			if d := t.origin(scope[name].Value, where{a: a, job: job, idx: idx, envFloor: len(envs) + 1 + i}); d != "" {
				return a.lineIn(job, idx, false, scope[name].Line), d
			}
		}
	}
	for _, name := range sortedKeys(st.With) {
		if f := t.tainted(st.With[name].Value, w); f != "" {
			return st.With[name].Line, fmt.Sprintf("the file %s, written from their text", f)
		}
	}
	// A process inherits what an earlier step wrote to $GITHUB_ENV too.
	for i := range job.Steps[:idx] {
		for _, name := range envNames(job.Steps[i]) {
			if !a.reg.ScalarOutput.MatchString(name) && t.step(where{a: a, job: job, idx: i}) {
				return 0, "text written to $" + name + " by an earlier step"
			}
		}
	}
	if st.Run == "" {
		return 0, ""
	}
	// Only the script: its env can hold a permission policy naming the same commands.
	if a.reg.UntrustedFetch.MatchString(st.Run) {
		return st.Line, "text the step fetches itself"
	}
	for _, m := range shellVar.FindAllStringSubmatch(st.Run, -1) {
		if t.env(m[1], w) {
			return st.Line, "text carried by $" + m[1]
		}
	}
	return 0, ""
}

func (a *auditor) lineIn(job *workflow.Job, idx int, ownStep bool, line int) int {
	if !ownStep && a.frameAt(job, idx) != nil {
		return 0
	}
	return line
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

// Power resolves what an agent step can do from its inputs.
func Power(reg *registry.Registry, agent *registry.Agent, st workflow.Step) registry.Power {
	// An allowlist only pre-approves tools, so bypass mode goes around one. A deny
	// list still holds.
	bypass := matchesAny(agent.BroadWhen, st.With) || matchesAny(agent.BroadWhenEnv, st.Env)
	limited := matchesAny(agent.LimitedWhen, st.With) || matchesAny(agent.LimitedWhenEnv, st.Env) ||
		(readOnlyAllowlist(agent, st) && !bypass) || deniesEveryAction(agent, st)
	if agent.SettingsInput != "" && readOnlySettings(st.With[agent.SettingsInput].Value) {
		limited = true
	}
	broad := matchesAny(agent.BroadWhen, st.With) || matchesAny(agent.BroadWhenEnv, st.Env)
	for _, name := range agent.ToolInputs {
		text := st.With[name].Value
		// A shell script names `Bash` in prose too; only its allowlist counts.
		if name == registry.RunInput {
			text = allowlists(text)
		}
		if len(ExecTools(reg, text)) > 0 {
			broad = true
		}
	}
	switch {
	case limited:
		return registry.Limited
	case broad:
		return registry.Broad
	case matchesAny(agent.ScopedWhen, st.With), matchesAny(agent.ScopedWhenEnv, st.Env):
		return registry.Scoped
	}
	return agent.DefaultPower()
}

// deniesEveryAction reports a deny list naming every tool that can act, which
// leaves a model that can only answer however its allowlist reads.
func deniesEveryAction(agent *registry.Agent, st workflow.Step) bool {
	if agent.AllowlistInput == "" || len(agent.LimitingDeny) == 0 {
		return false
	}
	m := denyList.FindStringSubmatch(st.With[agent.AllowlistInput].Value)
	if m == nil {
		return false
	}
	denied := map[string]bool{}
	for _, tool := range splitTools(strings.Trim(m[1], `"'`)) {
		denied[tool] = true
	}
	for _, tool := range agent.LimitingDeny {
		if !denied[tool] {
			return false
		}
	}
	// An allowed tool outside the deny list, such as an MCP one, can still act.
	for _, arg := range allowedArg.FindAllStringSubmatch(st.With[agent.AllowlistInput].Value, -1) {
		tools := splitTools(strings.Trim(arg[1], `"'`))
		if len(tools) > 0 && !allReadOnly(agent, tools) {
			return false
		}
	}
	return true
}

func allowlists(text string) string {
	var out []string
	for _, m := range allowedArg.FindAllStringSubmatch(text, -1) {
		out = append(out, m[1])
	}
	return strings.Join(out, " ")
}

// readOnlyAllowlist reports an explicit allowlist, in the arguments or in a
// settings value, that holds only read-only tools. An agent with neither keeps
// its default.
func readOnlyAllowlist(agent *registry.Agent, st workflow.Step) bool {
	found := false
	if agent.AllowlistInput != "" {
		// The flag can repeat, and every use adds tools.
		for _, m := range allowedArg.FindAllStringSubmatch(st.With[agent.AllowlistInput].Value, -1) {
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
