package audit

import (
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/somaz94/agentic-workflow-guard/internal/expr"
	"github.com/somaz94/agentic-workflow-guard/internal/reach"
	"github.com/somaz94/agentic-workflow-guard/internal/workflow"
)

var (
	dottedPath = regexp.MustCompile(`[A-Za-z_][\w-]*(?:\.(?:\*|[\w-]+))+`)
	shellVar   = regexp.MustCompile(`\$\{?([A-Za-z_]\w*)`)
	shellOnly  = regexp.MustCompile(`^\$\{?([A-Za-z_]\w*)\}?$`)
	shellSet   = regexp.MustCompile(`(?m)(?:^|\s)([A-Za-z_]\w*)=["']?([^\s"';]+)`)
	envWrite   = regexp.MustCompile(`\b([A-Za-z_]\w*)(?:=|<<)`)
	envPrintf  = regexp.MustCompile(`printf\s+(?:'[^']*'|"[^"]*")\s+["']?([A-Za-z_]\w*)`)
	envExport  = regexp.MustCompile(`exportVariable\(\s*["'\x60]([A-Za-z_]\w*)`)
	fileWrite  = regexp.MustCompile("(?:>>?|\\btee(?:\\s+-a)?|\\s-o|--output[= ])\\s*[\"']?([^\\s\"';|&<>()]+)|writeFile(?:Sync)?\\(\\s*[\"'`]([^\"'`]+)")
)

// where is a point in a job: the steps before idx have run.
type where struct {
	a   *auditor
	job *workflow.Job
	idx int
	// envFloor hides the env scopes nearer than it, because a value in an `env:`
	// block reads the scopes outside its own.
	envFloor int
}

// tracer follows attacker-written text through env, step outputs, job outputs,
// inputs and files, for the events an outsider can reach. It stops at the first
// true, which is what makes a key's in-progress false safe to cache, so one
// tracer serves one agent step.
type tracer struct {
	events []string
	memo   map[string]bool
	files  map[string][]string
	budget *budget
}

func newTracer(events []string, b *budget) *tracer {
	return &tracer{events: events, memo: map[string]bool{}, files: map[string][]string{}, budget: b}
}

// once memoizes by key. A key still being computed answers false, which is what
// ends a cycle such as a step output that reads itself.
func (t *tracer) once(key string, compute func() bool) bool {
	if v, ok := t.memo[key]; ok {
		return v
	}
	t.memo[key] = false
	if t.budget.exceeded() {
		return false
	}
	v := compute()
	t.memo[key] = v
	return v
}

// templateBodies returns what each `${{ }}` holds. A `}}` inside a string does not
// close one, which is why this is not a regular expression.
func templateBodies(s string) []string {
	var out []string
	for {
		i := strings.Index(s, "${{")
		if i < 0 {
			return out
		}
		s = s[i+3:]
		inString, end := false, -1
		for j := 0; j+1 < len(s); j++ {
			if s[j] == '\'' {
				inString = !inString
			} else if !inString && s[j] == '}' && s[j+1] == '}' {
				end = j
				break
			}
		}
		if end < 0 {
			return out
		}
		out = append(out, s[:end])
		s = s[end+2:]
	}
}

// origin names the first context path in a value that carries the text.
func (t *tracer) origin(value string, w where) string {
	for _, body := range templateBodies(value) {
		for _, p := range flowPaths(body) {
			if t.ref(p, w) {
				return describe(p)
			}
		}
	}
	return ""
}

// flowPaths falls back to every path in the text when the expression does not
// parse: a wrong guess here costs a false positive, not a missed exposure.
func flowPaths(body string) [][]string {
	if n, err := expr.Parse(strings.TrimSpace(body)); err == nil {
		return expr.Flows(n)
	}
	var out [][]string
	for _, m := range dottedPath.FindAllString(strings.ToLower(body), -1) {
		p := strings.Split(m, ".")
		// `a.b.replace(...)` is not an expression, and its last segment is the method.
		out = append(out, p, p[:len(p)-1])
	}
	return out
}

func describe(p []string) string {
	joined := strings.Join(p, ".")
	if p[0] == "github" {
		return joined
	}
	return "text carried by " + joined
}

// ref follows one path. A path that stops early, as in `toJSON(steps)`, covers
// everything under it.
func (t *tracer) ref(p []string, w where) bool {
	if p[0] != "github" && len(p) > 1 && w.a.reg.ScalarOutput.MatchString(p[len(p)-1]) {
		return false
	}
	switch p[0] {
	case "github":
		return t.github(p, w.a)
	case "env":
		if len(p) == 1 {
			return t.anyEnv(w)
		}
		return t.env(p[1], w)
	case "steps":
		return t.stepRef(p, w)
	case "needs":
		return t.needsRef(p, w)
	case "inputs":
		if len(p) == 1 {
			return t.anyInput(w)
		}
		return t.input(p[1], w)
	case "matrix":
		return t.origin(w.job.Strategy["matrix"].Value, w) != ""
	}
	return false
}

func (t *tracer) github(p []string, a *auditor) bool {
	// `issue[format('body')]` cannot be told from the field, so it counts as the object.
	if i := slices.Index(p, "*"); i >= 0 {
		p = p[:i]
	}
	if len(p) == 0 || !a.reg.Untrusted.MatchString(strings.Join(p, ".")) {
		return false
	}
	if len(p) <= 2 && (len(p) == 1 || p[1] == "event") {
		return len(t.events) > 0
	}
	for _, e := range t.events {
		switch {
		case p[1] == "head_ref":
			if e == "pull_request_target" {
				return true
			}
		case reach.Carries(e, p[2]):
			return true
		}
	}
	return false
}

func (t *tracer) stepRef(p []string, w where) bool {
	if len(p) == 1 {
		fr := w.a.frameAt(w.job, w.idx)
		for i := range w.job.Steps[:min(w.idx, len(w.job.Steps))] {
			if w.a.frameAt(w.job, i) == fr && t.step(where{a: w.a, job: w.job, idx: i}) {
				return true
			}
		}
		return false
	}
	// `steps.x.outcome` and `.conclusion` are the runner's words, not the step's.
	if len(p) > 2 && p[2] != "outputs" {
		return false
	}
	i := w.a.priorStep(w.job, w.idx, p[1])
	return i >= 0 && t.step(where{a: w.a, job: w.job, idx: i})
}

func (t *tracer) needsRef(p []string, w where) bool {
	if len(p) == 1 {
		for _, name := range w.job.Needs {
			if t.jobOutputs(name, w) {
				return true
			}
		}
		return false
	}
	// `needs.x.result` is the runner's word, not the job's.
	if len(p) > 2 && p[2] != "outputs" {
		return false
	}
	if len(p) > 3 {
		return t.jobOutput(p[1], p[3], w)
	}
	return t.jobOutputs(p[1], w)
}

// stepEnvs lists a step's own env and those of the steps that called its composite
// action, nearest first, each with the step it belongs to.
func (a *auditor) stepEnvs(job *workflow.Job, idx int) ([]map[string]workflow.Input, []int) {
	var envs []map[string]workflow.Input
	var at []int
	if idx < len(job.Steps) {
		envs, at = append(envs, job.Steps[idx].Env), append(at, idx)
	}
	for fr := a.frameAt(job, idx); fr != nil; fr = fr.parent {
		envs, at = append(envs, job.Steps[fr.at].Env), append(at, fr.at)
	}
	return envs, at
}

// env resolves a variable the way the runner does: a step's env, then what prior
// steps wrote to $GITHUB_ENV, then the job's and the workflow's. A name only hides
// the same spelling further out: an expression's case is lost in parsing, and Linux
// keeps `PROMPT` and `prompt` apart. Every writer counts because a background step
// can land after a later one.
func (t *tracer) env(name string, w where) bool {
	key := fmt.Sprintf("env/%p/%d/%d/%s", w.job, w.idx, w.envFloor, strings.ToLower(name))
	return t.once(key, func() bool {
		hidden := map[string]bool{}
		carried := func(scope map[string]workflow.Input, at where) bool {
			for _, k := range sortedKeys(scope) {
				if strings.EqualFold(k, name) && !hidden[k] {
					hidden[k] = true
					if t.origin(scope[k].Value, at) != "" {
						return true
					}
				}
			}
			return false
		}
		envs, at := w.a.stepEnvs(w.job, w.idx)
		for level, scope := range envs {
			if level >= w.envFloor && carried(scope, where{a: w.a, job: w.job, idx: at[level], envFloor: 1}) {
				return true
			}
		}
		if w.envFloor <= len(envs) {
			tainted := false
			for i := range w.job.Steps[:min(w.idx, len(w.job.Steps))] {
				for _, written := range envNames(w.job.Steps[i]) {
					if !strings.EqualFold(written, name) || hidden[written] {
						continue
					}
					tainted = tainted || t.step(where{a: w.a, job: w.job, idx: i})
				}
			}
			if tainted {
				return true
			}
			for i := range w.job.Steps[:min(w.idx, len(w.job.Steps))] {
				for _, written := range envNames(w.job.Steps[i]) {
					if strings.EqualFold(written, name) {
						hidden[written] = true
					}
				}
			}
		}
		for i, scope := range []map[string]workflow.Input{w.job.Env, w.a.wf.Env} {
			outer := len(envs) + 1 + i
			if outer > w.envFloor && carried(scope, where{a: w.a, job: w.job, idx: w.idx, envFloor: outer}) {
				return true
			}
		}
		return false
	})
}

// envNames lists the variables a step sets for later steps.
func envNames(s workflow.Step) []string {
	var out []string
	if strings.Contains(s.Run, "GITHUB_ENV") {
		for _, m := range envWrite.FindAllStringSubmatch(s.Run, -1) {
			out = append(out, m[1])
		}
		for _, m := range envPrintf.FindAllStringSubmatch(s.Run, -1) {
			out = append(out, m[1])
		}
	}
	for _, name := range sortedKeys(s.With) {
		for _, m := range envExport.FindAllStringSubmatch(s.With[name].Value, -1) {
			out = append(out, m[1])
		}
	}
	return out
}

func (t *tracer) anyEnv(w where) bool {
	envs, _ := w.a.stepEnvs(w.job, w.idx)
	for _, scope := range append(envs, w.job.Env, w.a.wf.Env) {
		for name := range scope {
			if t.env(name, w) {
				return true
			}
		}
	}
	for i := range w.job.Steps[:min(w.idx, len(w.job.Steps))] {
		if len(envNames(w.job.Steps[i])) > 0 && t.step(where{a: w.a, job: w.job, idx: i}) {
			return true
		}
	}
	return false
}

// step reports whether a step's outputs and the files it writes can hold the
// text. Which output a step sets cannot be told from outside, so one tainted
// input taints all of them.
func (t *tracer) step(w where) bool {
	key := fmt.Sprintf("step/%p/%d", w.job, w.idx)
	return t.once(key, func() bool {
		st := w.job.Steps[w.idx]
		if w.a.fetchesUntrusted(st) || t.origin(st.Run, w) != "" {
			return true
		}
		for _, scope := range []map[string]workflow.Input{st.With, st.Env} {
			for _, in := range scope {
				if t.origin(in.Value, w) != "" {
					return true
				}
			}
		}
		for _, m := range shellVar.FindAllStringSubmatch(st.Run, -1) {
			if t.env(m[1], w) {
				return true
			}
		}
		if t.tainted(st.Run, w) != "" {
			return true
		}
		// A composite action's outputs come from the steps it expanded into.
		for j := w.idx + 1; j < len(w.job.Steps); j++ {
			for fr := w.a.frameAt(w.job, j); fr != nil; fr = fr.parent {
				if fr.at == w.idx && t.step(where{a: w.a, job: w.job, idx: j}) {
					return true
				}
			}
		}
		return false
	})
}

// tainted returns the name of a file mentioned in text that a prior tainted step
// wrote. A temp directory is spelled differently on each side, so only the file
// name is comparable.
func (t *tracer) tainted(text string, w where) string {
	if text == "" {
		return ""
	}
	words := nameWords(text)
	for i := range w.job.Steps[:min(w.idx, len(w.job.Steps))] {
		for _, f := range t.writtenBy(w.job, i) {
			if words[f] && t.step(where{a: w.a, job: w.job, idx: i}) {
				return f
			}
		}
	}
	return ""
}

func (t *tracer) writtenBy(job *workflow.Job, i int) []string {
	key := fmt.Sprintf("%p/%d", job, i)
	files, ok := t.files[key]
	if !ok {
		files = writtenFiles(job.Steps[i])
		t.files[key] = files
	}
	return files
}

func writtenFiles(s workflow.Step) []string {
	text := s.Run
	for _, in := range s.With {
		text += "\n" + in.Value
	}
	seen := map[string]bool{}
	var out []string
	// An artifact lands where its step says, under a name the run that made it chose.
	if strings.Contains(strings.ToLower(s.Uses), "actions/download-artifact") {
		if name := path.Base(s.With["path"].Value); s.With["path"].Value != "" {
			seen[name] = true
			out = append(out, name)
		}
	}
	vars := map[string]string{}
	for _, m := range shellSet.FindAllStringSubmatch(s.Run, -1) {
		vars[m[1]] = m[2]
	}
	for _, m := range fileWrite.FindAllStringSubmatch(text, -1) {
		target := m[1] + m[2]
		// A redirect to one shell variable means what the script assigned to it.
		if v := shellOnly.FindStringSubmatch(target); v != nil && vars[v[1]] != "" {
			target = vars[v[1]]
		}
		name := path.Base(target)
		if strings.HasPrefix(name, "$") || name == "null" || name == "." || name == "/" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

// nameWords splits text into what could be a file name, so looking one up costs
// nothing however many a hostile script claims to write.
func nameWords(text string) map[string]bool {
	words := map[string]bool{}
	start := -1
	for i := 0; i <= len(text); i++ {
		if i < len(text) && isNameByte(text[i]) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			words[text[start:i]] = true
			start = -1
		}
	}
	return words
}

func isNameByte(c byte) bool {
	return c == '_' || c == '.' || c == '-' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

// calledOutput answers for a job that calls a reusable workflow. Which of its steps
// feeds an output is declared a level away, so one tainted step taints them all.
func (t *tracer) calledOutput(need *workflow.Job, w where) bool {
	return t.once(fmt.Sprintf("called/%p", need), func() bool {
		child := w.a.called(need)
		if child == nil {
			return false
		}
		for _, job := range child.wf.Jobs {
			flat := child.flat(job)
			for i := range flat.Steps {
				if t.step(where{a: child, job: flat, idx: i}) {
					return true
				}
			}
		}
		return false
	})
}

func (t *tracer) jobOutput(job, name string, w where) bool {
	need := w.a.wf.JobByName(job)
	if need == nil {
		return false
	}
	if need.Uses != "" {
		return t.calledOutput(need, w)
	}
	out, ok := lookup(need.Outputs, name)
	if !ok {
		return false
	}
	flat := w.a.flat(need)
	key := fmt.Sprintf("output/%p/%s", flat, strings.ToLower(name))
	return t.once(key, func() bool {
		return t.origin(out.Value, where{a: w.a, job: flat, idx: len(flat.Steps)}) != ""
	})
}

func (t *tracer) jobOutputs(job string, w where) bool {
	need := w.a.wf.JobByName(job)
	if need == nil {
		return false
	}
	if need.Uses != "" {
		return t.calledOutput(need, w)
	}
	for name := range need.Outputs {
		if !w.a.reg.ScalarOutput.MatchString(name) && t.jobOutput(job, name, w) {
			return true
		}
	}
	return false
}

// input resolves a composite action's input against its calling step, or a
// reusable workflow's against its calling job, falling back to the default.
func (t *tracer) input(name string, w where) bool {
	key := fmt.Sprintf("input/%p/%d/%s", w.job, w.idx, strings.ToLower(name))
	return t.once(key, func() bool {
		if fr := w.a.frameAt(w.job, w.idx); fr != nil {
			at := where{a: w.a, job: w.job, idx: fr.at}
			if in, ok := lookup(fr.with, name); ok {
				return t.origin(in.Value, at) != ""
			}
			in, _ := lookup(fr.defaults, name)
			return t.origin(in.Value, at) != ""
		}
		if c := w.a.call; c != nil {
			if in, ok := lookup(c.job.With, name); ok {
				return t.origin(in.Value, where{a: c.a, job: c.a.flat(c.job)}) != ""
			}
			in, _ := lookup(w.a.wf.CallInputs, name)
			return t.origin(in.Value, w) != ""
		}
		return false
	})
}

func (t *tracer) anyInput(w where) bool {
	var scopes []map[string]workflow.Input
	if fr := w.a.frameAt(w.job, w.idx); fr != nil {
		scopes = append(scopes, fr.with, fr.defaults)
	} else if c := w.a.call; c != nil {
		scopes = append(scopes, c.job.With, w.a.wf.CallInputs)
	}
	for _, scope := range scopes {
		for name := range scope {
			if !w.a.reg.ScalarOutput.MatchString(name) && t.input(name, w) {
				return true
			}
		}
	}
	return false
}

func lookup(m map[string]workflow.Input, name string) (workflow.Input, bool) {
	for k, v := range m {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return workflow.Input{}, false
}
