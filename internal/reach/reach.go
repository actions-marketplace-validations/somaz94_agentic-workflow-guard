// Package reach decides whether someone without write access can make an `if:`
// expression true, one event at a time. A regular expression cannot answer
// this: a gate on one `||` branch says nothing about the other branches.
package reach

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/somaz94/agentic-workflow-guard/internal/expr"
)

// State is how far an outsider gets. The order matters: Combine takes the
// lowest.
type State int

const (
	// None means the expression holds a real gate for this actor.
	None State = iota
	// Indeterminate means the answer depends on a value only known at run time,
	// such as the output of an authorization job.
	Indeterminate
	// Reachable means the actor can satisfy the expression.
	Reachable
)

// Combine is the state of two conditions that must both hold.
func Combine(a, b State) State {
	if a < b {
		return a
	}
	return b
}

// Actor is who is trying to reach the expression.
type Actor int

const (
	// Outsider has no relationship with the repository.
	Outsider Actor = iota
	// PriorContributor has had a commit merged once and holds no other rights.
	// GitHub reports them as CONTRIBUTOR, which is not a trust signal.
	PriorContributor
)

// Context is one way a workflow can run.
type Context struct {
	Event   string
	Actions []string
	Actor   Actor
}

// outsiderActions lists what an outsider can do per event. Labeling, assigning
// and similar actions need triage rights, so they are absent.
var outsiderActions = map[string][]string{
	"issues":              {"opened", "edited", "closed", "reopened"},
	"issue_comment":       {"created", "edited", "deleted"},
	"pull_request_target": {"opened", "edited", "synchronize", "reopened", "closed", "ready_for_review", "converted_to_draft"},
	"discussion":          {"created", "edited"},
	"discussion_comment":  {"created", "edited", "deleted"},
	"workflow_run":        {"requested", "in_progress", "completed"},
}

// defaultActions are the types an event fires on when `types:` is omitted.
// pull_request_target is the only event in scope that does not default to all.
var defaultActions = map[string][]string{
	"pull_request_target": {"opened", "synchronize", "reopened"},
}

// SecretEvents reports whether an event runs in the base repository's context,
// with its secrets, whoever triggered it. pull_request and its review events
// get a read-only token and no secrets on a fork, so they are out of scope.
func SecretEvents(event string) bool {
	_, ok := outsiderActions[event]
	return ok
}

// Actions returns the actions an outsider can fire given a workflow's `types:`.
// An empty result means the event never fires for an outsider.
func Actions(event string, types []string) []string {
	if len(types) == 0 {
		if d, ok := defaultActions[event]; ok {
			return d
		}
		return outsiderActions[event]
	}
	var out []string
	for _, t := range types {
		for _, a := range outsiderActions[event] {
			if strings.EqualFold(t, a) {
				out = append(out, a)
			}
		}
	}
	return out
}

// Eval returns how far ctx.Actor gets through one `if:` value. An empty value
// is always true.
func Eval(src string, ctx Context) State {
	if strings.TrimSpace(src) == "" {
		return Reachable
	}
	inner, ok := expr.Unwrap(src)
	if !ok {
		return Reachable
	}
	n, err := expr.Parse(inner)
	if err != nil {
		return Indeterminate
	}
	v := (&evaluator{ctx: ctx}).eval(n)
	canTrue, _ := v.truth()
	switch {
	case !canTrue:
		return None
	case v.uncertain:
		return Indeterminate
	}
	return Reachable
}

type kind int

const (
	// kConst is a finite set of possible constants.
	kConst kind = iota
	// kTaint is text the actor writes.
	kTaint
	// kIdentity is the actor's own name, which never equals a name someone wrote
	// into the workflow, because that name belongs to somebody trusted.
	kIdentity
	// kSelf is this repository's own name.
	kSelf
	// kFree can be anything and is not an authorization signal: feature flags,
	// matrix values, runner properties.
	kFree
	// kArray is a literal list from fromJSON.
	kArray
)

type constant struct {
	text           string
	isBool, isNull bool
}

type value struct {
	kind      kind
	consts    []constant
	items     []string
	uncertain bool
}

func str(ss ...string) value {
	v := value{kind: kConst}
	for _, s := range ss {
		v.consts = append(v.consts, constant{text: s})
	}
	return v
}

func boolean(canTrue, canFalse bool) value {
	v := value{kind: kConst}
	if canTrue {
		v.consts = append(v.consts, constant{text: "true", isBool: true})
	}
	if canFalse {
		v.consts = append(v.consts, constant{text: "false", isBool: true})
	}
	return v
}

func null() value { return value{kind: kConst, consts: []constant{{isNull: true}}} }

func (c constant) truthy() bool {
	switch {
	case c.isNull:
		return false
	case c.isBool:
		return c.text == "true"
	}
	if n, err := strconv.ParseFloat(c.text, 64); err == nil {
		return n != 0
	}
	return c.text != ""
}

func (v value) truth() (canTrue, canFalse bool) {
	switch v.kind {
	case kConst:
		for _, c := range v.consts {
			if c.truthy() {
				canTrue = true
			} else {
				canFalse = true
			}
		}
		return canTrue, canFalse
	case kIdentity, kSelf, kArray:
		return true, false
	}
	return true, true
}

func (v value) surelyTrue() bool {
	canTrue, _ := v.truth()
	return canTrue && !v.uncertain
}

func union(a, b value) value {
	u := a.uncertain || b.uncertain
	if a.kind == kConst && b.kind == kConst {
		return value{kind: kConst, consts: append(append([]constant{}, a.consts...), b.consts...), uncertain: u}
	}
	if a.kind == b.kind {
		a.uncertain = u
		return a
	}
	// Mixed kinds, such as `event.comment.association || event.issue.association`
	// where one side is null, keep the side that carries information.
	if isNullOnly(a) {
		b.uncertain = u
		return b
	}
	if isNullOnly(b) {
		a.uncertain = u
		return a
	}
	return value{kind: kFree, uncertain: u}
}

func isNullOnly(v value) bool {
	if v.kind != kConst {
		return false
	}
	for _, c := range v.consts {
		if !c.isNull {
			return false
		}
	}
	return true
}

type evaluator struct {
	ctx Context
}

func (e *evaluator) eval(n expr.Node) value {
	switch x := n.(type) {
	case *expr.Literal:
		switch x.Kind {
		case expr.LitNull:
			return null()
		case expr.LitBool:
			return boolean(x.Text == "true", x.Text == "false")
		}
		return str(x.Text)
	case *expr.Ref:
		return e.resolve(x.Path)
	case *expr.Unary:
		v := e.eval(x.X)
		canTrue, canFalse := v.truth()
		out := boolean(canFalse, canTrue)
		out.uncertain = v.uncertain
		return out
	case *expr.Binary:
		return e.binary(x)
	case *expr.Call:
		return e.call(x)
	}
	return value{kind: kFree}
}

func (e *evaluator) binary(b *expr.Binary) value {
	l, r := e.eval(b.L), e.eval(b.R)
	switch b.Op {
	case "&&":
		lt, lf := l.truth()
		switch {
		case !lt:
			return l
		case !lf:
			r.uncertain = r.uncertain || l.uncertain
			return r
		}
		rt, rf := r.truth()
		out := boolean(rt, rf || lf)
		if rt && r.kind != kConst {
			out = union(falsy(l), r)
		}
		out.uncertain = l.uncertain || r.uncertain
		return out
	case "||":
		lt, lf := l.truth()
		if !lf {
			return l
		}
		if !lt {
			return r
		}
		out := union(l, r)
		out.uncertain = !l.surelyTrue() && !r.surelyTrue() && (l.uncertain || r.uncertain)
		return out
	case "==", "!=":
		canEq, canNe := compare(l, r)
		if b.Op == "!=" {
			canEq, canNe = canNe, canEq
		}
		out := boolean(canEq, canNe)
		out.uncertain = l.uncertain || r.uncertain
		return out
	}
	out := boolean(true, true)
	out.uncertain = l.uncertain || r.uncertain
	return out
}

func falsy(v value) value {
	if v.kind != kConst {
		return null()
	}
	out := value{kind: kConst}
	for _, c := range v.consts {
		if !c.truthy() {
			out.consts = append(out.consts, c)
		}
	}
	return out
}

func compare(l, r value) (canEq, canNe bool) {
	if l.kind == kTaint || r.kind == kTaint || l.kind == kFree || r.kind == kFree || l.kind == kArray || r.kind == kArray {
		return true, true
	}
	if r.kind == kIdentity || (r.kind == kSelf && l.kind == kConst) {
		l, r = r, l
	}
	switch l.kind {
	case kIdentity:
		if r.kind == kIdentity {
			return true, true
		}
		return false, true
	case kSelf:
		// A repository name written into the workflow is this repository's.
		return true, false
	}
	for _, a := range l.consts {
		for _, b := range r.consts {
			if strings.EqualFold(a.text, b.text) {
				canEq = true
			} else {
				canNe = true
			}
		}
	}
	return canEq, canNe
}

func (e *evaluator) call(c *expr.Call) value {
	args := make([]value, len(c.Args))
	uncertain := false
	for i, a := range c.Args {
		args[i] = e.eval(a)
		uncertain = uncertain || args[i].uncertain
	}
	var out value
	switch c.Name {
	case "always", "success":
		out = boolean(true, false)
	case "contains":
		out = search(args, containsText)
	case "startswith":
		out = search(args, strings.HasPrefix)
	case "endswith":
		out = search(args, strings.HasSuffix)
	case "fromjson":
		out = fromJSON(c.Args)
		if out.kind == kFree && len(args) == 1 {
			return args[0]
		}
	default:
		out = value{kind: kFree}
	}
	out.uncertain = uncertain
	return out
}

func containsText(s, sub string) bool { return strings.Contains(s, sub) }

func search(args []value, match func(s, sub string) bool) value {
	if len(args) != 2 {
		return boolean(true, true)
	}
	hay, needle := args[0], args[1]
	if hay.kind == kArray {
		return inList(hay.items, needle)
	}
	if hay.kind == kConst && needle.kind == kConst {
		canTrue, canFalse := false, false
		for _, h := range hay.consts {
			for _, n := range needle.consts {
				if match(strings.ToLower(h.text), strings.ToLower(n.text)) {
					canTrue = true
				} else {
					canFalse = true
				}
			}
		}
		if isNullOnly(hay) {
			return boolean(false, true)
		}
		return boolean(canTrue, canFalse)
	}
	return boolean(true, true)
}

func inList(items []string, needle value) value {
	switch needle.kind {
	case kConst:
		canTrue, canFalse := false, len(items) == 0
		for _, c := range needle.consts {
			found := false
			for _, it := range items {
				if strings.EqualFold(it, c.text) {
					found = true
				}
			}
			if found {
				canTrue = true
			} else {
				canFalse = true
			}
		}
		return boolean(canTrue, canFalse)
	case kIdentity:
		return boolean(false, true)
	}
	return boolean(true, true)
}

func fromJSON(args []expr.Node) value {
	if len(args) != 1 {
		return value{kind: kFree}
	}
	lit, ok := args[0].(*expr.Literal)
	if !ok || lit.Kind != expr.LitString {
		return value{kind: kFree}
	}
	var any interface{}
	if json.Unmarshal([]byte(lit.Text), &any) != nil {
		return value{kind: kFree}
	}
	switch x := any.(type) {
	case []interface{}:
		v := value{kind: kArray}
		for _, it := range x {
			if s, ok := it.(string); ok {
				v.items = append(v.items, s)
			}
		}
		return v
	case bool:
		return boolean(x, !x)
	case string:
		return str(x)
	}
	return value{kind: kFree}
}

func (e *evaluator) resolve(path []string) value {
	switch path[0] {
	case "github":
		if len(path) == 1 {
			return value{kind: kFree}
		}
		switch path[1] {
		case "event_name":
			return str(e.ctx.Event)
		case "actor", "triggering_actor":
			return value{kind: kIdentity}
		case "repository", "repository_owner":
			return value{kind: kSelf}
		case "head_ref":
			return value{kind: kTaint}
		case "event":
			return e.resolveEvent(path[2:])
		}
		return value{kind: kFree}
	case "needs", "steps", "env":
		return value{kind: kFree, uncertain: true}
	}
	return value{kind: kFree}
}

// payloadObjects maps each event to the objects its payload carries, with the
// one whose author is the actor first. On issue_comment the issue's author is
// someone else, which is why a check on it does not gate the commenter.
var payloadObjects = map[string][]string{
	"issues":              {"issue"},
	"issue_comment":       {"comment", "issue"},
	"pull_request_target": {"pull_request"},
	"discussion":          {"discussion"},
	"discussion_comment":  {"comment", "discussion"},
	"workflow_run":        {"workflow_run"},
}

// Carries reports whether an event's payload holds the named object.
func Carries(event, object string) bool {
	for _, o := range payloadObjects[event] {
		if o == object {
			return true
		}
	}
	return false
}

// knownObjects are payload keys that are absent, not attacker-written, when an
// event does not carry them. Label and assignee fields only appear on actions
// an outsider cannot fire.
var knownObjects = map[string]bool{
	"issue": true, "comment": true, "pull_request": true, "discussion": true, "workflow_run": true,
	"review": true, "head_commit": true, "commits": true, "release": true, "label": true,
	"assignee": true, "milestone": true, "requested_reviewer": true, "requested_team": true,
}

func (e *evaluator) resolveEvent(rest []string) value {
	if len(rest) == 0 {
		return value{kind: kTaint}
	}
	switch rest[0] {
	case "action":
		return str(e.ctx.Actions...)
	case "sender":
		if len(rest) > 1 && rest[1] == "login" {
			return value{kind: kIdentity}
		}
		if len(rest) > 1 && rest[1] == "type" {
			return str("User")
		}
		return value{kind: kTaint}
	case "repository", "organization":
		return value{kind: kFree}
	}
	objects := payloadObjects[e.ctx.Event]
	idx := -1
	for i, o := range objects {
		if o == rest[0] {
			idx = i
		}
	}
	if idx < 0 {
		if knownObjects[rest[0]] {
			return null()
		}
		return value{kind: kTaint}
	}
	return e.resolveObject(rest, idx == 0)
}

func (e *evaluator) resolveObject(rest []string, ownedByActor bool) value {
	field := strings.Join(rest[1:], ".")
	switch {
	case field == "author_association":
		if ownedByActor {
			if e.ctx.Actor == PriorContributor {
				return str("CONTRIBUTOR")
			}
			return str("NONE", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", "MANNEQUIN")
		}
		return value{kind: kFree}
	case field == "user.login" || field == "actor.login":
		if ownedByActor {
			return value{kind: kIdentity}
		}
		return value{kind: kFree}
	case rest[0] == "pull_request" && field == "head.repo.fork":
		return boolean(true, false)
	case rest[0] == "pull_request" && (field == "head.repo.full_name" || field == "head.repo.owner.login" || field == "head.user.login"):
		return value{kind: kIdentity}
	case rest[0] == "workflow_run" && (field == "head_repository.full_name" || field == "head_repository.owner.login"):
		return value{kind: kIdentity}
	case rest[0] == "workflow_run" && (field == "event" || field == "conclusion" || field == "status"):
		return value{kind: kFree}
	case rest[0] == "pull_request" && field == "labels.*.name":
		// Only a maintainer can label a pull request, and templates cannot.
		return value{kind: kArray}
	case strings.HasPrefix(field, "base.repo."):
		return value{kind: kSelf}
	case strings.HasPrefix(field, "labels"):
		// Issue forms can apply labels on behalf of an outsider.
		return value{kind: kFree}
	}
	return value{kind: kTaint}
}
