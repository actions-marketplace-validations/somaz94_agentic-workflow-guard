// Package report renders findings as annotations, a job summary and SARIF.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/somaz94/agentic-workflow-guard/internal/audit"
)

// Annotations writes one workflow command per finding.
func Annotations(w io.Writer, r *audit.Report) {
	levels := map[audit.Severity]string{audit.High: "error", audit.Medium: "warning", audit.Low: "notice"}
	for _, f := range r.Findings {
		fmt.Fprintf(w, "::%s file=%s,line=%d,title=%s::%s\n",
			levels[f.Severity], escapeProperty(f.File), f.Line, escapeProperty(f.Rule), escapeData(f.Message))
	}
	for _, m := range r.Warnings {
		fmt.Fprintf(w, "::warning::%s\n", escapeData(m))
	}
}

func escapeData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

func escapeProperty(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C").Replace(s)
}

// Summary renders the Markdown job summary.
func Summary(r *audit.Report) string {
	var b strings.Builder
	b.WriteString("## Agentic Workflow Audit\n\n")
	fmt.Fprintf(&b, "Scanned %d file(s): %d high, %d medium, %d low.\n",
		r.Files, r.Count(audit.High), r.Count(audit.Medium), r.Count(audit.Low))
	if len(r.Findings) > 0 {
		b.WriteString("\n| Severity | Rule | Location | Finding |\n|---|---|---|---|\n")
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "| %s | `%s` | `%s:%d` | %s |\n", f.Severity, f.Rule, f.File, f.Line, strings.ReplaceAll(f.Message, "|", "\\|"))
		}
	}
	if len(r.Warnings) > 0 {
		b.WriteString("\nNot audited, so the counts above say nothing about these:\n\n")
		for _, m := range r.Warnings {
			fmt.Fprintf(&b, "- %s\n", strings.ReplaceAll(m, "\n", " "))
		}
	}
	return b.String()
}

// SARIF renders SARIF 2.1.0 for GitHub code scanning.
func SARIF(r *audit.Report, version string) ([]byte, error) {
	type message struct {
		Text string `json:"text"`
	}
	type rule struct {
		ID   string  `json:"id"`
		Name string  `json:"name"`
		Desc message `json:"shortDescription"`
		Help message `json:"help"`
	}
	type artifact struct {
		URI string `json:"uri"`
	}
	type region struct {
		StartLine int `json:"startLine"`
	}
	type physical struct {
		Artifact artifact `json:"artifactLocation"`
		Region   region   `json:"region"`
	}
	type location struct {
		Physical physical `json:"physicalLocation"`
	}
	type result struct {
		RuleID    string     `json:"ruleId"`
		Level     string     `json:"level"`
		Message   message    `json:"message"`
		Locations []location `json:"locations"`
	}
	levels := map[audit.Severity]string{audit.High: "error", audit.Medium: "warning", audit.Low: "note"}
	rules := make([]rule, 0, len(audit.Rules))
	for _, ri := range audit.Rules {
		rules = append(rules, rule{ri.ID, ri.ID, message{ri.Summary}, message{ri.Fix}})
	}
	results := make([]result, 0, len(r.Findings))
	for _, f := range r.Findings {
		results = append(results, result{f.Rule, levels[f.Severity], message{f.Message},
			[]location{{physical{artifact{f.File}, region{f.Line}}}}})
	}
	driver := map[string]interface{}{
		"name":           "agentic-workflow-guard",
		"informationUri": "https://github.com/somaz94/agentic-workflow-guard",
		"rules":          rules,
	}
	// SARIF makes this optional, and `dev` on a released image would name no version.
	if version != "" && version != "dev" {
		driver["version"] = version
	}
	doc := map[string]interface{}{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]interface{}{{
			"tool":    map[string]interface{}{"driver": driver},
			"results": results,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}
