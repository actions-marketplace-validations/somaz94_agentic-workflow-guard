# Rules

<br/>

## Who counts as an attacker

The model is someone with no rights on the repository, on an event that runs with the base repository's secrets: `issues`, `issue_comment`, `pull_request_target`, `discussion`, `discussion_comment` and `workflow_run`.

Someone with one previously merged commit is checked too. GitHub reports them as `CONTRIBUTOR`, which is not a trust signal, and a finding reached that way says so.

<br/>

## Severity

Severity combines how far the actor gets with what the agent can do once they get there.

| Agent power | Meaning | Examples |
|---|---|---|
| Limited | Returns text, reads, or posts a comment | A model call with no tools, a read-only sandbox, an allowlist of only read and comment tools |
| Scoped | Tools behind an allowlist or approval | The default for most agents |
| Broad | Can run arbitrary commands | Auto-approval, a full-access sandbox, `Bash(find:*)` |

When the only gate is a run-time one that the file cannot prove, such as a job output or an authorization step, the severity drops one level and the message asks you to verify it.

<br/>

## open-invocation

An outsider can start the agent, either because its actor allowlist is `*` or because the action has no built-in actor check and nothing in front of it stops them.

**Fix**: name users instead of `*`, restrict the trigger, and put an `author_association` check on every branch of `if:`.

<br/>

## untrusted-input

A field such as `github.event.issue.body` reaches the agent through `with:` or `env:`, or one step back through a step's output or a file it writes. Moving the text into an environment variable does not help here, because the model reads the content either way.

**Fix**: gate the workflow to trusted actors. If it must serve outsiders, give the agent no tools that can act, and treat its output as untrusted too.

<br/>

## untrusted-checkout

The agent runs after the job checks out the pull request's code on a trigger that holds secrets. The checkout brings the attacker's agent config, hooks and instructions with it.

**Fix**: check out the base revision and have the agent read the diff.

<br/>

## broad-tools

The agent can run arbitrary commands. That includes permissions that read as narrow but are not: `Bash(find:*)` runs programs through `-exec`, and `Bash(uv:*)` through `uv run`. A permission with a subcommand, such as `Bash(git log:*)`, is not flagged.

This is reported even behind a real gate, at low severity, because a trusted actor can still be handed malicious text to act on.

**Fix**: list specific subcommands, and remove auto-approval and full-access modes.

<br/>

## full-output

The action is set to write the agent's full output to the job log, which is public on a public repository and can hold tool results and secrets.

**Fix**: leave it off.

<br/>

## agent-settings

A committed `.claude/settings.json` sets `bypassPermissions`, approves every project MCP server, or allows an exec-equivalent tool. These apply to anyone or anything running an agent in a checkout, including one from a pull request.

**Fix**: keep these in user-level settings.

<br/>

## mcp-secret

A value in an MCP config has the shape of a credential. The value itself is never written to the report.

**Fix**: revoke the credential, because committing it exposed it, and read it from the environment.

<br/>

## mcp-unpinned

An MCP server runs through `npx`, `bunx` or `uvx` without an exact version, so each run executes whatever was published last.

**Fix**: pin the exact version.
