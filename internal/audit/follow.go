package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"time"

	"github.com/somaz94/agentic-workflow-guard/internal/reach"
	"github.com/somaz94/agentic-workflow-guard/internal/registry"
	"github.com/somaz94/agentic-workflow-guard/internal/workflow"
)

// The tree can come from a fork, so these bound what a hostile one costs. No real
// repository comes near them, and reaching one fails the scan: a partial scan must
// not read as a clean one. maxDepth exists for a repository that calls itself, and
// the counts for fan-out, where a few short files expand exponentially.
const (
	maxDepth     = 10
	maxFlatSteps = 2000
	maxCalls     = 1000
	maxFileSize  = 1 << 20
	maxResolved  = 1 << 16
	// maxResolveDepth covers what real workflows chain through env and inputs.
	maxResolveDepth = 6
)

// scanTimeout is the backstop for anything the counts do not see.
var scanTimeout = time.Minute

// budget is what one scan has left, shared by every auditor it creates.
type budget struct {
	deadline time.Time
	calls    int
	reason   string
}

func newBudget() *budget { return &budget{deadline: time.Now().Add(scanTimeout)} }

func (b *budget) exceeded() bool {
	if b.reason == "" && time.Now().After(b.deadline) {
		b.reason = fmt.Sprintf("took longer than %s", scanTimeout)
	}
	return b.reason != ""
}

// noteParse records a file refused for its size. Any other parse error is a warning
// about one file, like a workflow GitHub would reject itself.
func (b *budget) noteParse(file string, err error) {
	if errors.Is(err, workflow.ErrTooLarge) {
		b.reason = file + ": " + err.Error()
	}
}

// Source reads a file by its slash-separated path from the repository root.
type Source func(rel string) ([]byte, error)

// callSite is the job that called a reusable workflow.
type callSite struct {
	a   *auditor
	job *workflow.Job
}

// frame is one composite action call inside a flattened job.
type frame struct {
	file     string
	at       int
	parent   *frame
	with     map[string]workflow.Input
	defaults map[string]workflow.Input
	depth    int
}

// triggers are the events this workflow runs on, which for a called workflow are
// those of whatever called it.
func (a *auditor) triggers() map[string][]string {
	if a.call != nil {
		return a.call.a.triggers()
	}
	return a.wf.Triggers
}

// callerState is how far the actor gets through the jobs that lead here. Each
// `if:` is evaluated against its own workflow's outputs.
func (a *auditor) callerState(ctx reach.Context) reach.State {
	if a.call == nil {
		return reach.Reachable
	}
	c := a.call
	ctx.IsGate = c.a.gateOutput(c.job, 0)
	return reach.Combine(c.a.jobState(c.job, ctx, map[string]bool{}), c.a.callerState(ctx))
}

// narrowedByConfig reports a committed config that restricts the agent. Its mere
// presence says nothing: it may allow everything.
func (a *auditor) narrowedByConfig(agent *registry.Agent) bool {
	if a.src == nil {
		return false
	}
	for _, f := range agent.ConfigFiles {
		if data, err := a.src(f); err == nil && agent.NarrowedBy(data) {
			return true
		}
	}
	return false
}

// localRef resolves a `./` reference to a path inside the repository. Anything
// else, or a path that climbs out, is not followed.
func localRef(uses string) (string, bool) {
	if !strings.HasPrefix(uses, "./") {
		return "", false
	}
	rel := path.Clean(uses)
	if rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}

// follow audits a local reusable workflow with its caller's triggers and gates.
func (a *auditor) follow(job *workflow.Job) []Finding {
	child := a.called(job)
	if child == nil {
		return nil
	}
	return child.run()
}

// called opens the workflow a job calls, nil when there is nothing to audit there.
// One on another repository cannot be read without the network, by design, and a
// run no outsider can start exposes nothing.
func (a *auditor) called(job *workflow.Job) *auditor {
	rel, ok := localRef(job.Uses)
	if !ok || a.src == nil || !a.hasSecretTrigger() || a.calling(rel) || a.budget.exceeded() {
		return nil
	}
	if a.budget.calls++; a.budget.calls > maxCalls {
		a.budget.reason = fmt.Sprintf("followed more than %d reusable workflow calls", maxCalls)
		return nil
	}
	data, err := a.src(rel)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			a.warn(fmt.Sprintf("%s: %v", rel, err))
		}
		return nil
	}
	wf, err := workflow.Parse(data)
	if err != nil {
		a.budget.noteParse(rel, err)
		a.warn(fmt.Sprintf("%s: %v", rel, err))
		return nil
	}
	child := newAuditor(a.reg, a.src, rel, wf, &callSite{a, job}, a.warn)
	child.budget = a.budget
	return child
}

func (a *auditor) hasSecretTrigger() bool {
	for event := range a.triggers() {
		if reach.SecretEvents(event) {
			return true
		}
	}
	return false
}

// calling reports whether rel is already on the call stack, which GitHub rejects
// and so is no finding, or the stack is deeper than GitHub allows, which ends the
// scan rather than silently leaving the rest unread.
func (a *auditor) calling(rel string) bool {
	depth := 0
	for p := a; p != nil; depth++ {
		if p.file == rel {
			return true
		}
		if depth >= maxDepth {
			a.budget.reason = fmt.Sprintf("%s is more than %d reusable workflow calls deep", rel, maxDepth)
			return true
		}
		if p.call == nil {
			break
		}
		p = p.call.a
	}
	return false
}

// flat returns the job with its composite actions expanded in place, so a step
// inside one sees the steps before it as the runner would.
func (a *auditor) flat(job *workflow.Job) *workflow.Job {
	if f, ok := a.flats[job]; ok {
		return f
	}
	out := *job
	out.Steps = nil
	var frames []*frame
	a.expand(job.Steps, nil, &out, &frames)
	a.flats[job], a.flats[&out], a.frames[&out] = &out, &out, frames
	return &out
}

func (a *auditor) expand(steps []workflow.Step, parent *frame, out *workflow.Job, frames *[]*frame) {
	for _, st := range steps {
		if len(out.Steps) >= maxFlatSteps {
			a.budget.reason = fmt.Sprintf("job %q expands to more than %d steps", out.Name, maxFlatSteps)
			return
		}
		out.Steps = append(out.Steps, st)
		*frames = append(*frames, parent)
		rel, act := a.composite(st.Uses, parent)
		if act != nil {
			depth := 1
			if parent != nil {
				depth = parent.depth + 1
			}
			a.expand(act.Steps, &frame{file: rel, at: len(out.Steps) - 1, parent: parent, with: st.With, defaults: act.Inputs, depth: depth}, out, frames)
		}
	}
}

// composite loads a local action. A Docker or JavaScript action has no steps and
// a missing one is usually checked out elsewhere, so neither is worth a warning.
func (a *auditor) composite(uses string, parent *frame) (string, *workflow.Action) {
	rel, ok := localRef(uses)
	if !ok || a.src == nil || a.budget.exceeded() {
		return "", nil
	}
	for fr := parent; fr != nil; fr = fr.parent {
		if path.Dir(fr.file) == rel {
			return "", nil
		}
	}
	if parent != nil && parent.depth >= maxDepth {
		a.budget.reason = fmt.Sprintf("%s is more than %d composite actions deep", rel, maxDepth)
		return "", nil
	}
	for _, name := range []string{"action.yml", "action.yaml"} {
		file := path.Join(rel, name)
		data, err := a.src(file)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				a.warn(fmt.Sprintf("%s: %v", file, err))
			}
			continue
		}
		act, err := workflow.ParseAction(data)
		if err != nil {
			a.budget.noteParse(file, err)
			a.warn(fmt.Sprintf("%s: %v", file, err))
			return "", nil
		}
		return file, act
	}
	return "", nil
}

func (a *auditor) frameAt(job *workflow.Job, idx int) *frame {
	fr := a.frames[job]
	if idx < 0 || idx >= len(fr) {
		return nil
	}
	return fr[idx]
}

func (a *auditor) fileAt(job *workflow.Job, idx int) string {
	if fr := a.frameAt(job, idx); fr != nil {
		return fr.file
	}
	return a.file
}

// priorStep finds a step by id among those that ran before idx in the same
// action or job, -1 when none: ids are scoped to their own action.
func (a *auditor) priorStep(job *workflow.Job, idx int, id string) int {
	fr := a.frameAt(job, idx)
	for i := min(idx, len(job.Steps)) - 1; i >= 0; i-- {
		if a.frameAt(job, i) == fr && strings.EqualFold(job.Steps[i].ID, id) {
			return i
		}
	}
	return -1
}
