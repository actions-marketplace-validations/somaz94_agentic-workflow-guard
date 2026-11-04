package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
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
	// The tree can come from a fork, and os.Root refuses a symlink out of it.
	repo, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("scan path: %w", err)
	}
	defer func() { _ = repo.Close() }()
	r := &Report{}
	warned := map[string]bool{}
	warn := func(m string) {
		if !warned[m] {
			warned[m] = true
			r.Warnings = append(r.Warnings, m)
		}
	}
	b := newBudget()
	read := func(rel string) ([]byte, error) {
		info, err := repo.Stat(rel)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", rel)
		}
		if info.Size() > maxFileSize {
			b.reason = fmt.Sprintf("%s is larger than %d bytes", rel, maxFileSize)
			return nil, b.limitError()
		}
		return repo.ReadFile(rel)
	}
	entries, err := fs.ReadDir(repo.FS(), ".github/workflows")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("read workflows: %w", err)
	}
	for _, e := range entries {
		ext := path.Ext(e.Name())
		if e.IsDir() || (ext != ".yml" && ext != ".yaml") {
			continue
		}
		// GitHub Agentic Workflows compiles x.md to x.lock.yml: nobody can fix a finding
		// in the output, and that compiler decides its gating. Without the source next
		// to it, the name alone says nothing and the file runs like any other.
		if base, ok := strings.CutSuffix(e.Name(), ".lock.yml"); ok {
			if _, err := repo.Stat(".github/workflows/" + base + ".md"); err == nil {
				continue
			}
		}
		if b.exceeded() {
			break
		}
		b.calls = 0
		rel := ".github/workflows/" + e.Name()
		data, err := read(rel)
		if err != nil {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s: %v", rel, err))
			continue
		}
		wf, err := workflow.Parse(data)
		if err != nil {
			b.noteParse(rel, err)
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s: %v", rel, err))
			continue
		}
		r.Files++
		a := newAuditor(reg, read, rel, wf, nil, warn)
		a.budget = b
		r.Findings = append(r.Findings, a.run()...)
	}
	if b.exceeded() {
		return nil, b.limitError()
	}
	for _, c := range configFiles {
		data, err := read(c.path)
		if err != nil {
			continue
		}
		found, err := c.audit(reg, c.path, data)
		if err != nil {
			r.Warnings = append(r.Warnings, fmt.Sprintf("%s: %v", c.path, err))
			continue
		}
		r.Files++
		r.Findings = append(r.Findings, found...)
	}
	r.Findings = filter(r.Findings, ignore)
	if b.exceeded() {
		return nil, b.limitError()
	}
	sortFindings(r.Findings)
	r.Findings = dedupe(r.Findings)
	return r, nil
}

func (b *budget) limitError() error {
	return fmt.Errorf("scan stopped, its result would be incomplete: %s", b.reason)
}

// dedupe keeps the worst report of each location: a workflow audited by itself
// and again through a caller reports the same step twice. Findings are sorted, so
// the first seen is the worst.
func dedupe(in []Finding) []Finding {
	seen := map[string]bool{}
	out := in[:0]
	for _, f := range in {
		key := fmt.Sprintf("%s/%s/%d", f.Rule, f.File, f.Line)
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	return out
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
