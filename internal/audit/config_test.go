package audit

import (
	"strings"
	"testing"
)

func rulesOf(f []Finding) string {
	var out []string
	for _, x := range f {
		out = append(out, x.Severity.String()+" "+x.Rule)
	}
	return strings.Join(out, ",")
}

func TestClaudeSettings(t *testing.T) {
	cases := []struct{ src, want string }{
		{`{}`, ""},
		{`{"permissions": {"allow": ["Read", "Bash(gh pr view:*)"]}}`, ""},
		{`{"permissions": {"defaultMode": "bypassPermissions"}}`, "medium agent-settings"},
		{`{"enableAllProjectMcpServers": true}`, "medium agent-settings"},
		{`{"permissions": {"allow": ["Bash(find:*)", "Bash"]}}`, "medium agent-settings,medium agent-settings"},
	}
	for _, c := range cases {
		f, err := ClaudeSettings(reg(t), ".claude/settings.json", []byte(c.src))
		if err != nil {
			t.Fatal(err)
		}
		if got := rulesOf(f); got != c.want {
			t.Errorf("%s = %q; want %q", c.src, got, c.want)
		}
	}
	if _, err := ClaudeSettings(reg(t), "x", []byte("{")); err == nil {
		t.Error("bad json accepted")
	}
	f, _ := ClaudeSettings(reg(t), "x", []byte("{\n  \"enableAllProjectMcpServers\": true\n}"))
	if f[0].Line != 2 {
		t.Errorf("line = %d", f[0].Line)
	}
}

func TestMCPConfig(t *testing.T) {
	// Built at run time so the source tree holds nothing shaped like a credential.
	secret := "ghp_" + strings.Repeat("a", 36)
	cases := []struct{ src, want string }{
		{`{}`, ""},
		{`{"mcpServers": {"a": {"command": "npx", "args": ["-y", "pkg"]}}}`, "low mcp-unpinned"},
		{`{"mcpServers": {"a": {"command": "npx", "args": ["-y", "pkg@latest"]}}}`, "low mcp-unpinned"},
		{`{"mcpServers": {"a": {"command": "npx", "args": ["-y", "@scope/pkg"]}}}`, "low mcp-unpinned"},
		{`{"mcpServers": {"a": {"command": "npx", "args": ["-y", "@scope/pkg@1.2.3"]}}}`, ""},
		{`{"mcpServers": {"a": {"command": "uvx", "args": ["pkg==1.2.3"]}}}`, ""},
		{`{"mcpServers": {"a": {"command": "bunx", "args": ["--flag"]}}}`, ""},
		{`{"mcpServers": {"a": {"command": "docker", "args": ["run", "x"]}}}`, ""},
		{`{"servers": {"a": {"command": "uvx", "args": ["pkg"]}}}`, "low mcp-unpinned"},
		{`{"mcpServers": {"a": {"env": {"T": "${TOKEN}"}}}}`, ""},
		{`{"mcpServers": {"a": {"env": {"T": "` + secret + `"}}}}`, "high mcp-secret"},
		{`{"mcpServers": {"a": {"headers": {"Authorization": "Bearer ` + secret + `"}}}}`, "high mcp-secret"},
		{`{"mcpServers": {"a": {"url": "https://x/?k=` + secret + `"}}}`, "high mcp-secret"},
		{`{"mcpServers": {"a": "not an object"}}`, ""},
	}
	for _, c := range cases {
		f, err := MCPConfig(reg(t), ".mcp.json", []byte(c.src))
		if err != nil {
			t.Fatal(err)
		}
		if got := rulesOf(f); got != c.want {
			t.Errorf("%s = %q; want %q", c.src, got, c.want)
		}
		for _, x := range f {
			if strings.Contains(x.Message, secret) {
				t.Errorf("message echoes the credential: %q", x.Message)
			}
		}
	}
	if _, err := MCPConfig(reg(t), "x", []byte("{")); err == nil {
		t.Error("bad json accepted")
	}
}

func TestLineOfFallsBackToOne(t *testing.T) {
	if lineOf([]byte("a\nb"), "zzz") != 1 {
		t.Error("missing needle should report line 1")
	}
}
