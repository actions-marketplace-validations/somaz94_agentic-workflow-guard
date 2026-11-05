package audit

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/somaz94/agentic-workflow-guard/internal/registry"
)

// ClaudeSettings audits a committed .claude/settings.json.
func ClaudeSettings(reg *registry.Registry, file string, data []byte) ([]Finding, error) {
	var doc struct {
		Permissions struct {
			Allow       []string `json:"allow"`
			DefaultMode string   `json:"defaultMode"`
		} `json:"permissions"`
		EnableAll bool `json:"enableAllProjectMcpServers"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}
	add := func(out []Finding, needle, msg string) []Finding {
		return append(out, Finding{Rule: RuleAgentSettings, Severity: Medium, File: file, Line: lineOf(data, needle), Message: msg})
	}
	var out []Finding
	if strings.EqualFold(doc.Permissions.DefaultMode, "bypassPermissions") {
		out = add(out, "defaultMode", "permissions.defaultMode is bypassPermissions, so an agent in this repository asks before nothing.")
	}
	if doc.EnableAll {
		out = add(out, "enableAllProjectMcpServers", "enableAllProjectMcpServers approves every MCP server the repository declares, including one added by a pull request.")
	}
	for _, tool := range doc.Permissions.Allow {
		if len(ExecTools(reg, tool)) > 0 {
			out = add(out, tool, fmt.Sprintf("permissions.allow holds %s, which runs arbitrary programs.", tool))
		}
	}
	return out, nil
}

type mcpServer struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
	Headers map[string]string `json:"headers"`
	URL     string            `json:"url"`
}

// MCPConfig audits a file holding `mcpServers` or, in VS Code's form, `servers`.
func MCPConfig(reg *registry.Registry, file string, data []byte) ([]Finding, error) {
	var doc struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
		Servers    map[string]json.RawMessage `json:"servers"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse json: %w", err)
	}
	servers := doc.MCPServers
	if servers == nil {
		servers = doc.Servers
	}
	var out []Finding
	for _, name := range sortedKeys(servers) {
		var s mcpServer
		if json.Unmarshal(servers[name], &s) != nil {
			continue
		}
		line := lineOf(data, `"`+name+`"`)
		if hasSecret(reg, s) {
			// The value is deliberately left out: the report may be public.
			out = append(out, Finding{Rule: RuleMCPSecret, Severity: High, File: file, Line: line,
				Message: fmt.Sprintf("MCP server %q holds a value shaped like a credential.", name)})
		}
		if pkg := unpinnedPackage(s); pkg != "" {
			out = append(out, Finding{Rule: RuleMCPUnpinned, Severity: Low, File: file, Line: line,
				Message: fmt.Sprintf("MCP server %q runs %s without an exact version.", name, pkg)})
		}
	}
	return out, nil
}

func hasSecret(reg *registry.Registry, s mcpServer) bool {
	values := append([]string{s.URL}, s.Args...)
	for _, v := range s.Env {
		values = append(values, v)
	}
	for _, v := range s.Headers {
		values = append(values, v)
	}
	for _, v := range values {
		if reg.Secret.MatchString(v) {
			return true
		}
	}
	return false
}

// unpinnedPackage returns the package a runner would fetch at its latest
// version. A scoped npm name starts with `@`, so only a later `@` is a version.
func unpinnedPackage(s mcpServer) string {
	switch s.Command {
	case "npx", "bunx", "uvx":
	default:
		return ""
	}
	for _, arg := range s.Args {
		if strings.HasPrefix(arg, "-") {
			continue
		}
		at := strings.LastIndex(arg, "@")
		pinned := strings.Contains(arg, "==") || (at > 0 && !strings.HasSuffix(arg, "@latest"))
		if pinned {
			return ""
		}
		return arg
	}
	return ""
}

func lineOf(data []byte, needle string) int {
	for i, l := range strings.Split(string(data), "\n") {
		if strings.Contains(l, needle) {
			return i + 1
		}
	}
	return 1
}
