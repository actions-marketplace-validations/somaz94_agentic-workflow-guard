package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const risky = "on: issues\njobs:\n  a:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n"

func TestScan(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".github/workflows/risky.yml", risky)
	write(t, root, ".github/workflows/also.yaml", "on: push\njobs: {}\n")
	write(t, root, ".github/workflows/broken.yml", "a: [")
	write(t, root, ".github/workflows/notes.md", "ignored")
	write(t, root, ".github/workflows/sub/nested.yml", risky)
	write(t, root, ".mcp.json", `{"mcpServers": {"a": {"command": "npx", "args": ["pkg"]}}}`)
	write(t, root, ".claude/settings.json", "{")
	r, err := Scan(reg(t), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Files != 5 {
		t.Errorf("files = %d; want 5", r.Files)
	}
	if len(r.Warnings) != 2 {
		t.Errorf("warnings = %v; want the broken workflow and settings", r.Warnings)
	}
	if rulesOf(r.Findings) != "high open-invocation,low mcp-unpinned" {
		t.Errorf("findings = %q", rulesOf(r.Findings))
	}
	if r.Findings[0].File != ".github/workflows/risky.yml" {
		t.Errorf("file = %q", r.Findings[0].File)
	}
	if r.Count(High) != 1 || r.Count(Medium) != 0 || r.Count(Low) != 1 {
		t.Errorf("counts = %d %d %d", r.Count(High), r.Count(Medium), r.Count(Low))
	}
}

func TestScanIgnoreRules(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".github/workflows/risky.yml", risky)
	r, err := Scan(reg(t), root, []string{"Open-Invocation"})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 {
		t.Errorf("findings = %+v", r.Findings)
	}
}

func TestScanEmptyRepository(t *testing.T) {
	r, err := Scan(reg(t), t.TempDir(), nil)
	if err != nil || r.Files != 0 || len(r.Findings) != 0 {
		t.Errorf("empty = %+v, %v", r, err)
	}
}

func TestScanErrors(t *testing.T) {
	root := t.TempDir()
	if _, err := Scan(reg(t), filepath.Join(root, "missing"), nil); err == nil {
		t.Error("missing path accepted")
	}
	write(t, root, "file", "x")
	if _, err := Scan(reg(t), filepath.Join(root, "file"), nil); err == nil {
		t.Error("file path accepted")
	}
	write(t, root, "repo/.github/workflows", "not a directory")
	if _, err := Scan(reg(t), filepath.Join(root, "repo"), nil); err == nil {
		t.Error("unreadable workflows accepted")
	}
}

func TestSortFindings(t *testing.T) {
	f := []Finding{
		{Rule: "b", Severity: Low, File: "b", Line: 2},
		{Rule: "b", Severity: Low, File: "a", Line: 2},
		{Rule: "b", Severity: Low, File: "a", Line: 1},
		{Rule: "a", Severity: Low, File: "a", Line: 1},
		{Rule: "z", Severity: High, File: "z", Line: 9},
	}
	sortFindings(f)
	got := ""
	for _, x := range f {
		got += x.Rule + x.File + " "
	}
	if got != "zz aa ba ba bb " {
		t.Errorf("order = %q", got)
	}
}

func TestExceeds(t *testing.T) {
	r := &Report{Findings: []Finding{{Severity: Medium}}}
	cases := map[string]bool{"high": false, "medium": true, "low": true, "none": false}
	for failOn, want := range cases {
		if got := r.Exceeds(failOn); got != want {
			t.Errorf("Exceeds(%s) = %v", failOn, got)
		}
	}
}
