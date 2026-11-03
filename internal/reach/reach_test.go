package reach

import (
	"reflect"
	"testing"
)

func ctx(event string, actions ...string) Context {
	if len(actions) == 0 {
		actions = Actions(event, nil)
	}
	return Context{Event: event, Actions: actions}
}

func TestEval(t *testing.T) {
	const assoc = `contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)`
	cases := []struct {
		name, src string
		ctx       Context
		want      State
	}{
		{"empty", "", ctx("issues"), Reachable},
		{"mixed template is always truthy", "${{ github.actor == 'a' }} && ${{ false }}", ctx("issues"), Reachable},
		{"unparsable", "a ==", ctx("issues"), Indeterminate},
		{"wrapped", "${{ github.event_name == 'issues' }}", ctx("issues"), Reachable},
		{"other event", "github.event_name == 'issue_comment'", ctx("issues"), None},
		{"negated event", "github.event_name != 'issues'", ctx("issues"), None},
		{"association gate", assoc, ctx("issue_comment"), None},
		{"association gate including contributor", `contains(fromJSON('["CONTRIBUTOR"]'), github.event.comment.author_association)`, ctx("issue_comment"), None},
		{"association equals owner", "github.event.comment.author_association == 'OWNER'", ctx("issue_comment"), None},
		{"association allows none", "github.event.comment.author_association != 'OWNER'", ctx("issue_comment"), Reachable},
		{"gate on one branch only, issues side open",
			"(github.event_name == 'issues' && github.event.action == 'opened') || (github.event_name == 'issue_comment' && github.event.comment.user.login == 'alice')",
			ctx("issues"), Reachable},
		{"gate on one branch only, comment side gated",
			"(github.event_name == 'issues' && github.event.action == 'opened') || (github.event_name == 'issue_comment' && github.event.comment.user.login == 'alice')",
			ctx("issue_comment"), None},
		{"trigger phrase is not a gate", "contains(github.event.comment.body, '@claude')", ctx("issue_comment"), Reachable},
		{"phrase on an event without comments", "contains(github.event.comment.body, '@claude')", ctx("issues"), None},
		{"phrase plus gate", "startsWith(github.event.comment.body, '/x') && " + assoc, ctx("issue_comment"), None},
		{"issue author does not gate a commenter", "github.event.issue.author_association == 'OWNER'", ctx("issue_comment"), Reachable},
		{"issue author gates its opener", "github.event.issue.author_association == 'OWNER'", ctx("issues"), None},
		{"issue author login does not gate a commenter", "github.event.issue.user.login == 'alice'", ctx("issue_comment"), Reachable},
		{"same repo check", "github.event.pull_request.head.repo.full_name == github.repository", ctx("pull_request_target"), None},
		{"same repo check reversed", "github.repository == github.event.pull_request.head.repo.full_name", ctx("pull_request_target"), None},
		{"fork check", "github.event.pull_request.head.repo.fork == false", ctx("pull_request_target"), None},
		{"fork only", "github.event.pull_request.head.repo.fork == true", ctx("pull_request_target"), Reachable},
		{"negative actor filter is no gate", "github.actor != 'dependabot[bot]'", ctx("pull_request_target"), Reachable},
		{"actor allowlist", "github.actor == 'alice' || github.actor == 'bob'", ctx("issues"), None},
		{"actor in list", `contains(fromJSON('["alice"]'), github.actor)`, ctx("issues"), None},
		{"owner is actor", "github.actor == github.repository_owner", ctx("issues"), None},
		{"actor substring", "contains(github.actor, 'bot')", ctx("issues"), Reachable},
		{"label action needs triage", "github.event.action == 'labeled'", ctx("pull_request_target"), None},
		{"label name absent", "github.event.label.name == 'review'", ctx("pull_request_target"), None},
		{"action in list", `contains(fromJSON('["opened","labeled"]'), github.event.action)`, ctx("pull_request_target"), Reachable},
		{"action not in list", `contains(fromJSON('["labeled"]'), github.event.action)`, ctx("pull_request_target"), None},
		{"pr label needs maintainer", "contains(github.event.pull_request.labels.*.name, 'ok')", ctx("pull_request_target"), None},
		{"issue label can come from a form", "contains(github.event.issue.labels.*.name, 'bug')", ctx("issues"), Reachable},
		{"repo pin holds", "github.repository == 'o/r'", ctx("issues"), Reachable},
		{"repo pin negated", "github.repository != 'o/r'", ctx("issues"), None},
		{"feature flag is no gate", "vars.ENABLED == 'true'", ctx("issues"), Reachable},
		{"needs output", "needs.gate.outputs.ok == 'true'", ctx("issues"), Indeterminate},
		{"step output", "steps.g.outputs.ok == 'true'", ctx("issues"), Indeterminate},
		{"env value", "env.OK == 'true'", ctx("issues"), Indeterminate},
		{"definite or uncertain", "github.event_name == 'issues' || needs.a.outputs.b == 'c'", ctx("issues"), Reachable},
		{"uncertain or definite", "needs.a.outputs.b == 'c' || github.event_name == 'issues'", ctx("issues"), Reachable},
		{"uncertain or false", "needs.a.outputs.b == 'c' || github.event_name == 'push'", ctx("issues"), Indeterminate},
		{"uncertain and false", "needs.a.outputs.b == 'c' && github.event_name == 'push'", ctx("issues"), None},
		{"true and uncertain", "github.event_name == 'issues' && needs.a.outputs.b == 'c'", ctx("issues"), Indeterminate},
		{"always", "always()", ctx("issues"), Reachable},
		{"success", "success()", ctx("issues"), Reachable},
		{"failure is unknown", "failure()", ctx("issues"), Reachable},
		{"not", "!contains(github.event.comment.body, 'x')", ctx("issue_comment"), Reachable},
		{"not of constant", "!true", ctx("issues"), None},
		{"not of uncertain", "!needs.a.outputs.b", ctx("issues"), Indeterminate},
		{"relational", "github.event.issue.number > 1", ctx("issues"), Reachable},
		{"sender type", "github.event.sender.type == 'Bot'", ctx("issues"), None},
		{"sender login", "github.event.sender.login == 'alice'", ctx("issues"), None},
		{"sender other", "github.event.sender.id == 1", ctx("issues"), Reachable},
		{"head ref", "github.head_ref == 'x'", ctx("pull_request_target"), Reachable},
		{"bare github", "github == 'x'", ctx("issues"), Reachable},
		{"bare event", "github.event", ctx("issues"), Reachable},
		{"other github field", "github.ref == 'x'", ctx("issues"), Reachable},
		{"repository payload", "github.event.repository.private == true", ctx("issues"), Reachable},
		{"unknown payload key", "github.event.foo == 'x'", ctx("issues"), Reachable},
		{"base repo", "github.event.pull_request.base.repo.full_name == 'o/r'", ctx("pull_request_target"), Reachable},
		{"workflow run conclusion", "github.event.workflow_run.conclusion == 'success'", ctx("workflow_run"), Reachable},
		{"workflow run same repo", "github.event.workflow_run.head_repository.full_name == github.repository", ctx("workflow_run"), None},
		{"workflow run actor", "github.event.workflow_run.actor.login == 'alice'", ctx("workflow_run"), None},
		{"from json bool", "fromJSON('true')", ctx("issues"), Reachable},
		{"from json string", "fromJSON('\"\"')", ctx("issues"), None},
		{"from json number", "fromJSON('1')", ctx("issues"), Reachable},
		{"from json bad", "fromJSON('{')", ctx("issues"), Reachable},
		{"from json var", "fromJSON(vars.X)", ctx("issues"), Reachable},
		{"from json no args", "fromJSON()", ctx("issues"), Reachable},
		{"starts with const", "startsWith('abc', 'a')", ctx("issues"), Reachable},
		{"ends with const miss", "endsWith('abc', 'x')", ctx("issues"), None},
		{"contains wrong arity", "contains('a')", ctx("issues"), Reachable},
		{"contains empty list", `contains(fromJSON('[]'), github.event.comment.author_association)`, ctx("issue_comment"), None},
		{"contains list taint", `contains(fromJSON('["a"]'), github.event.comment.body)`, ctx("issue_comment"), Reachable},
		{"compare arrays", `fromJSON('["a"]') == 'a'`, ctx("issues"), Reachable},
		{"null literal", "null", ctx("issues"), None},
		{"number zero", "0", ctx("issues"), None},
		{"number one", "1", ctx("issues"), Reachable},
		{"and with free", "vars.A && contains(github.event.issue.body, 'x')", ctx("issues"), Reachable},
		{"and false side", "vars.A && false", ctx("issues"), None},
		{"association fallback through or",
			`contains(fromJSON('["OWNER"]'), github.event.comment.author_association || github.event.review.author_association)`, ctx("issue_comment"), None},
		{"or of taint and identity", "(github.event.issue.body || github.actor) == 'x'", ctx("issues"), Reachable},
		{"and picks both kinds", "(vars.A && github.actor) == 'x'", ctx("issues"), None},
		{"identity versus identity", "github.actor == github.triggering_actor", ctx("issues"), Reachable},
		{"self versus self", "github.repository == github.repository", ctx("issues"), Reachable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Eval(c.src, c.ctx); got != c.want {
				t.Errorf("Eval(%q) on %s = %v; want %v", c.src, c.ctx.Event, got, c.want)
			}
		})
	}
}

func TestEvalPriorContributor(t *testing.T) {
	src := `contains(fromJSON('["OWNER","CONTRIBUTOR"]'), github.event.pull_request.author_association)`
	c := ctx("pull_request_target")
	if got := Eval(src, c); got != None {
		t.Errorf("outsider = %v; want None", got)
	}
	c.Actor = PriorContributor
	if got := Eval(src, c); got != Reachable {
		t.Errorf("prior contributor = %v; want Reachable", got)
	}
}

func TestActions(t *testing.T) {
	if got := Actions("pull_request_target", nil); !reflect.DeepEqual(got, []string{"opened", "synchronize", "reopened"}) {
		t.Errorf("default = %v", got)
	}
	if got := Actions("issues", []string{"labeled"}); len(got) != 0 {
		t.Errorf("labeled only = %v; want none", got)
	}
	if got := Actions("issues", []string{"Opened", "labeled"}); !reflect.DeepEqual(got, []string{"opened"}) {
		t.Errorf("filtered = %v", got)
	}
	if got := Actions("issues", nil); len(got) != 4 {
		t.Errorf("all = %v", got)
	}
}

func TestSecretEvents(t *testing.T) {
	if !SecretEvents("issue_comment") || SecretEvents("pull_request") || SecretEvents("push") {
		t.Error("SecretEvents misclassified an event")
	}
}

func TestCarries(t *testing.T) {
	if !Carries("issue_comment", "issue") || Carries("issues", "comment") || Carries("push", "issue") {
		t.Error("Carries misclassified a payload object")
	}
}

func TestCombine(t *testing.T) {
	if Combine(Reachable, Indeterminate) != Indeterminate || Combine(None, Reachable) != None || Combine(Reachable, Reachable) != Reachable {
		t.Error("Combine must take the lowest state")
	}
}
