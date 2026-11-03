package audit

// Rule IDs. These are public: `ignore_rules` and SARIF consumers name them.
const (
	RuleOpenInvocation    = "open-invocation"
	RuleUntrustedInput    = "untrusted-input"
	RuleUntrustedCheckout = "untrusted-checkout"
	RuleBroadTools        = "broad-tools"
	RuleFullOutput        = "full-output"
	RuleAgentSettings     = "agent-settings"
	RuleMCPSecret         = "mcp-secret"
	RuleMCPUnpinned       = "mcp-unpinned"
)

// RuleInfo describes a rule for reports.
type RuleInfo struct {
	ID      string
	Summary string
	Fix     string
}

// Rules is the catalog, in the order reports list them.
var Rules = []RuleInfo{
	{RuleOpenInvocation, "An outsider can start an AI agent",
		"Restrict the trigger, add an author_association gate on every branch of `if:`, and name users instead of '*'."},
	{RuleUntrustedInput, "Attacker-written text flows into an AI agent's input",
		"Gate the workflow to trusted actors, or have the agent fetch the text with no tools that can act on it."},
	{RuleUntrustedCheckout, "An AI agent runs after checking out untrusted code",
		"Check out the base revision; the agent then reads the diff instead of running the pull request's config and hooks."},
	{RuleBroadTools, "An AI agent can run arbitrary commands",
		"Replace exec-equivalent tools with specific subcommands and remove auto-approval and full-access modes."},
	{RuleFullOutput, "Full agent output goes to the job log",
		"Leave full output off on public repositories."},
	{RuleAgentSettings, "A committed agent config relaxes permissions",
		"Keep bypass modes and exec-equivalent allowances out of committed settings."},
	{RuleMCPSecret, "A credential is committed in an MCP config",
		"Revoke the credential and read it from the environment."},
	{RuleMCPUnpinned, "An MCP server runs an unpinned package",
		"Pin the package to an exact version."},
}
