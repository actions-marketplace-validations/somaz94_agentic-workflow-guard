package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/somaz94/agentic-workflow-guard/internal/registry"
	"github.com/somaz94/agentic-workflow-guard/internal/workflow"
)

// Report is the result of scanning one repository.
type Report struct {
	Findings []Finding
	Warnings []string
	Files    int
}

type configFile struct {
	path  string
	audit func(*registry.Registry, string, []byte) ([]Finding, error)
}

var configFiles = []configFile{
	{".claude/settings.json", ClaudeSettings},
	{".mcp.json", MCPConfig},
	{".cursor/mcp.json", MCPConfig},
	{".vscode/mcp.json", MCPConfig},
	{".gemini/settings.json", MCPConfig},
}

// Scan audits the workflows and agent configs under root. A file that cannot be
// read as what its name promises is a warning: a broken workflow fails on its
// own, and one bad file should not hide findings in the others.
func Scan(reg *registry.Registry, root string, ignore []string) (*Report, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, fmt.Errorf("scan path: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("scan path %s is not a directory", root)
	}
	r := &Report{}
	entries, err := os.ReadDir(filepath.Join(root, ".github", "workflows"))
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read workflows: %w", err)
	}
	for _, e := range entries {
		ext := filepath.Ext(e.Name())
		if e.IsDir() || (ext != ".yml" && ext != ".yaml") {
			continue
		}
		rel := filepath.ToSlash(filepath.Join(".github", "workflows", e.Name()))
		data, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s: %v", rel, err))
			continue
		}
		r.Files++
		wf, err := workflow.Parse(data)
		if err != nil {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s: %v", rel, err))
			continue
		}
		r.Findings = append(r.Findings, Workflow(reg, rel, wf)...)
	}
	for _, c := range configFiles {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(c.path)))
		if err != nil {
			continue
		}
		r.Files++
		found, err := c.audit(reg, c.path, data)
		if err != nil {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s: %v", c.path, err))
			continue
		}
		r.Findings = append(r.Findings, found...)
	}
	r.Findings = filter(r.Findings, ignore)
	sortFindings(r.Findings)
	return r, nil
}

func filter(in []Finding, ignore []string) []Finding {
	skip := map[string]bool{}
	for _, id := range ignore {
		skip[strings.ToLower(id)] = true
	}
	out := in[:0]
	for _, f := range in {
		if !skip[f.Rule] {
			out = append(out, f)
		}
	}
	return out
}

func sortFindings(f []Finding) {
	sort.SliceStable(f, func(i, j int) bool {
		a, b := f[i], f[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.Rule < b.Rule
	})
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Count returns how many findings have the severity.
func (r *Report) Count(s Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

// Exceeds reports whether any finding is at or above the fail_on threshold.
func (r *Report) Exceeds(failOn string) bool {
	var limit Severity
	switch failOn {
	case "high":
		limit = High
	case "medium":
		limit = Medium
	case "low":
		limit = Low
	default:
		return false
	}
	for _, f := range r.Findings {
		if f.Severity >= limit {
			return true
		}
	}
	return false
}
