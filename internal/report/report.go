// Package report renders findings as annotations, a job summary and SARIF.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/somaz94/agentic-workflow-guard/internal/audit"
	"github.com/somaz94/agentic-workflow-guard/internal/output"
)

// summaryText renders text from a hostile tree as text: a file name or config value
// quoted in a finding could otherwise start a heading, a table cell, a link or HTML
// in the summary. An entity shows its character and can never act as Markdown. An
// email address links even from entities, so an empty comment splits it.
var summaryText = strings.NewReplacer(
	"\r", " ", "\n", " ",
	"&", "&amp;", "<", "&lt;", ">", "&gt;", "|", "&#124;", "\\", "&#92;", "`", "&#96;",
	"*", "&#42;", "_", "&#95;", "~", "&#126;", "[", "&#91;", "]", "&#93;", "(", "&#40;", ")", "&#41;",
	"!", "&#33;", "#", "&#35;", ":", "&#58;", ".", "&#46;", "$", "&#36;", "@", "<!-- -->&#64;",
)

// summaryLimit keeps a hostile tree from erasing the summary: GitHub drops one over
// 1 MiB whole, and an entity is longer than the character it shows.
const summaryLimit = 1 << 19

// warningLimit keeps findings from pushing out the list of what was not audited.
const warningLimit = summaryLimit + summaryLimit/2

// Annotations writes one workflow command per finding.
func Annotations(w io.Writer, r *audit.Report) {
	levels := map[audit.Severity]string{audit.High: "error", audit.Medium: "warning", audit.Low: "notice"}
	for _, f := range r.Findings {
		fmt.Fprintf(w, "::%s file=%s,line=%d,title=%s::%s\n",
			levels[f.Severity], escapeProperty(f.File), f.Line, escapeProperty(f.Rule), output.EscapeData(f.Message))
	}
	for _, m := range r.Warnings {
		fmt.Fprintf(w, "::warning::%s\n", output.EscapeData(m))
	}
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
		omitted := 0
		for _, f := range r.Findings {
			row := fmt.Sprintf("| %s | `%s` | <code>%s:%d</code> | %s |\n", f.Severity, f.Rule, summaryText.Replace(f.File), f.Line, summaryText.Replace(f.Message))
			if b.Len()+len(row) > summaryLimit {
				omitted++
				continue
			}
			b.WriteString(row)
		}
		if omitted > 0 {
			fmt.Fprintf(&b, "\n%d more finding(s) are in the log, and in the SARIF file when one is written; this summary reached its size limit.\n", omitted)
		}
	}
	if len(r.Warnings) > 0 {
		b.WriteString("\nNot audited, so the counts above say nothing about these:\n\n")
		omitted := 0
		for _, m := range r.Warnings {
			line := fmt.Sprintf("- %s\n", summaryText.Replace(m))
			if b.Len()+len(line) > warningLimit {
				omitted++
				continue
			}
			b.WriteString(line)
		}
		if omitted > 0 {
			fmt.Fprintf(&b, "\n%d more warning(s) are in the log; this summary reached its size limit.\n", omitted)
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
			[]location{{physical{artifact{(&url.URL{Path: f.File}).String()}, region{f.Line}}}}})
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
