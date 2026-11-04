package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

func TestScanFollowsAndDedupes(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	called := "on:\n  workflow_call:\n  issues:\njobs:\n  r:\n    steps:\n      - uses: openai/codex-action@v1\n        with:\n          allow-users: '*'\n"
	caller := "on: issue_comment\njobs:\n  a:\n    uses: ./.github/workflows/called.yml\n"
	for name, src := range map[string]string{"called.yml": called, "caller.yml": caller} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Scan(reg(t), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].File != ".github/workflows/called.yml" {
		t.Errorf("findings = %+v", r.Findings)
	}
}

func TestScanRefusesSymlinkOutOfTree(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "secret.yml")
	src := "on: issues\njobs:\n  a:\n    steps:\n      - uses: openai/codex-action@v1\n        with:\n          allow-users: '*'\n"
	if err := os.WriteFile(outside, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "link.yml")); err != nil {
		t.Skip(err)
	}
	r, err := Scan(reg(t), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 0 || len(r.Warnings) != 1 {
		t.Errorf("report = %+v", r)
	}
}

func TestScanSkipsCompiledWorkflows(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".github/workflows/x.lock.yml", "on: issues\njobs:\n  a:\n    steps:\n      - uses: openai/codex-action@v1\n        with:\n          allow-users: '*'\n")
	r, err := Scan(reg(t), root, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Files != 0 || len(r.Findings) != 0 {
		t.Errorf("report = %+v", r)
	}
}

// Each of these is a short file that would otherwise take the scan down, so they
// run as whole scans and must come back with an error rather than a clean report.
func TestScanRefusesHostileTrees(t *testing.T) {
	bomb := func(root string) {
		var b strings.Builder
		b.WriteString("runs:\n  using: composite\n  steps:\n")
		for i := 0; i < 20; i++ {
			b.WriteString("    - uses: ./x\n")
		}
		write(t, root, "x/action.yml", b.String())
		write(t, root, ".github/workflows/w.yml", "on: issues\njobs:\n  a:\n    steps:\n      - uses: ./x\n")
	}
	fanout := func(root string) {
		write(t, root, ".github/workflows/w.yml", "on: issues\njobs:\n  a:\n    uses: ./.github/workflows/w0.yml\n")
		for level := 0; level < maxDepth; level++ {
			var b strings.Builder
			b.WriteString("on: workflow_call\njobs:\n")
			for j := 0; j < 20; j++ {
				fmt.Fprintf(&b, "  j%d:\n    uses: ./.github/workflows/w%d.yml\n", j, level+1)
			}
			write(t, root, fmt.Sprintf(".github/workflows/w%d.yml", level), b.String())
		}
	}
	aliases := func(root string) {
		var b strings.Builder
		b.WriteString("x: &big {a: \"" + strings.Repeat("a", 500_000) + "\"}\nenv:\n")
		for i := 0; i < 50; i++ {
			fmt.Fprintf(&b, "  k%d: *big\n", i)
		}
		write(t, root, ".github/workflows/w.yml", b.String())
	}
	large := func(root string) {
		write(t, root, ".github/workflows/w.yml", "# "+strings.Repeat("a", maxFileSize)+"\n")
	}
	calledAliases := func(root string) {
		aliases(root)
		data, err := os.ReadFile(filepath.Join(root, ".github/workflows/w.yml"))
		if err != nil {
			t.Fatal(err)
		}
		write(t, root, "called/big.yml", string(data))
		write(t, root, "act/action.yml", string(data))
		write(t, root, ".github/workflows/w.yml", "on: issues\njobs:\n  a:\n    uses: ./called/big.yml\n")
	}
	actionAliases := func(root string) {
		calledAliases(root)
		write(t, root, ".github/workflows/w.yml", "on: issues\njobs:\n  a:\n    steps:\n      - uses: ./act\n")
	}
	for name, build := range map[string]func(string){
		"composite fan-out": bomb, "reusable fan-out": fanout, "alias expansion": aliases,
		"oversized file": large, "alias expansion in a called workflow": calledAliases, "alias expansion in an action": actionAliases,
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			build(root)
			done := make(chan error, 1)
			go func() {
				_, err := Scan(reg(t), root, nil)
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "incomplete") {
					t.Errorf("err = %v", err)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("scan did not stop")
			}
		})
	}
}

func TestScanStopsAtItsDeadline(t *testing.T) {
	saved := scanTimeout
	scanTimeout = time.Nanosecond
	defer func() { scanTimeout = saved }()
	root := t.TempDir()
	write(t, root, ".github/workflows/w.yml", "on: issues\njobs:\n  a:\n    steps:\n      - uses: openai/codex-action@v1\n")
	if _, err := Scan(reg(t), root, nil); err == nil || !strings.Contains(err.Error(), "took longer") {
		t.Errorf("err = %v", err)
	}
}

func TestScanStaysFastOnManyClaimedFiles(t *testing.T) {
	var b strings.Builder
	b.WriteString("on: issues\njobs:\n  a:\n    steps:\n      - run: |\n          gh issue view 1\n")
	for i := 0; i < 30000; i++ {
		fmt.Fprintf(&b, "          echo x >a%d\n", i)
	}
	b.WriteString("      - uses: actions/ai-inference@v2\n        with:\n          prompt: " + strings.Repeat("word ", 50000) + "\n")
	root := t.TempDir()
	write(t, root, ".github/workflows/w.yml", b.String())
	start := time.Now()
	if _, err := Scan(reg(t), root, nil); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("took %s", d)
	}
}

func TestScanRefusesSpecialFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".github/workflows/d.yml"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".claude/settings.json"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(reg(t), root, nil); err != nil {
		t.Fatal(err)
	}
}

func TestScanStaysFastOnDoubledReferences(t *testing.T) {
	var b strings.Builder
	b.WriteString("on: issues\npermissions: {}\njobs:\n  j0:\n    outputs:\n      x: ${{ github.event.issue.number }}\n    steps:\n      - run: echo\n")
	for i := 1; i < 60; i++ {
		fmt.Fprintf(&b, "  j%d:\n    needs: j%d\n    outputs:\n      x: ${{ needs.j%d.outputs.x }}${{ needs.j%d.outputs.x }}\n    steps:\n      - run: echo\n", i, i-1, i-1, i-1)
	}
	b.WriteString("  a:\n    needs: j59\n    steps:\n      - uses: actions/ai-inference@v2\n        with:\n          prompt: ${{ needs.j59.outputs.x }}\n")
	root := t.TempDir()
	write(t, root, ".github/workflows/w.yml", b.String())
	r, err := Scan(reg(t), root, nil)
	if err != nil || len(r.Findings) != 0 {
		t.Errorf("report = %+v, err = %v", r, err)
	}
}

// Go randomizes map order, and a tracer walks maps, so a result that depended on
// the walk would differ between runs of the same commit.
func TestScanIsDeterministic(t *testing.T) {
	root := t.TempDir()
	write(t, root, ".github/workflows/w.yml", "on: issues\npermissions: {}\njobs:\n  a:\n    env:\n      A: ${{ env.B }}\n      B: ${{ github.event.issue.body }}\n      C: ${{ env.A }}\n    steps:\n      - id: s\n        env:\n          X: ${{ env.C }}\n          Y: ${{ steps.t.outputs.z }}\n        run: echo\n      - id: t\n        env:\n          Z: ${{ steps.s.outputs.q }}\n        run: echo\n      - uses: actions/ai-inference@v2\n        with:\n          a: ${{ steps.t.outputs.z }}\n          b: ${{ steps.s.outputs.q }}\n")
	var first string
	for i := 0; i < 50; i++ {
		r, err := Scan(reg(t), root, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := fmt.Sprintf("%+v", r.Findings)
		if first == "" {
			first = got
		} else if got != first {
			t.Fatalf("run %d differs:\n%s\n%s", i, first, got)
		}
	}
}
