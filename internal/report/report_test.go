package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/somaz94/agentic-workflow-guard/internal/audit"
)

func sample() *audit.Report {
	return &audit.Report{
		Files: 2,
		Findings: []audit.Finding{
			{Rule: audit.RuleBroadTools, Severity: audit.High, File: "a,b:c.yml", Line: 3, Message: "100% bad\nnext | pipe"},
			{Rule: audit.RuleFullOutput, Severity: audit.Medium, File: "b.yml", Line: 4, Message: "m"},
			{Rule: audit.RuleMCPUnpinned, Severity: audit.Low, File: "c.json", Line: 5, Message: "l"},
		},
		Warnings: []string{"d.yml: broken"},
	}
}

func TestAnnotations(t *testing.T) {
	var b bytes.Buffer
	Annotations(&b, sample())
	want := []string{
		"::error file=a%2Cb%3Ac.yml,line=3,title=broad-tools::100%25 bad%0Anext | pipe",
		"::warning file=b.yml,line=4,title=full-output::m",
		"::notice file=c.json,line=5,title=mcp-unpinned::l",
		"::warning::d.yml: broken",
	}
	got := strings.Split(strings.TrimSpace(b.String()), "\n")
	if len(got) != len(want) {
		t.Fatalf("lines = %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q; want %q", i, got[i], want[i])
		}
	}
}

func TestSummary(t *testing.T) {
	s := Summary(sample())
	for _, want := range []string{"Scanned 2 file(s): 1 high, 1 medium, 1 low.", "`broad-tools`", "`b.yml:4`", `next \| pipe`} {
		if !strings.Contains(s, want) {
			t.Errorf("summary missing %q:\n%s", want, s)
		}
	}
	if clean := Summary(&audit.Report{Files: 1}); strings.Contains(clean, "| Severity") {
		t.Errorf("clean summary has a table:\n%s", clean)
	}
}

func TestSARIF(t *testing.T) {
	data, err := SARIF(sample(), "v1")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Version string           `json:"version"`
					Rules   []map[string]any `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID string `json:"ruleId"`
				Level  string `json:"level"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	run := doc.Runs[0]
	if doc.Version != "2.1.0" || run.Tool.Driver.Version != "v1" || len(run.Tool.Driver.Rules) != len(audit.Rules) {
		t.Errorf("doc = %+v", doc)
	}
	levels := []string{"error", "warning", "note"}
	for i, r := range run.Results {
		if r.Level != levels[i] {
			t.Errorf("result %d level = %s; want %s", i, r.Level, levels[i])
		}
	}
}

func TestSummaryNamesWhatWasNotAudited(t *testing.T) {
	got := Summary(&audit.Report{Warnings: []string{"bad.yml: parse\nerror"}})
	if !strings.Contains(got, "Not audited") || !strings.Contains(got, "bad.yml: parse error") {
		t.Errorf("summary = %s", got)
	}
	if strings.Contains(Summary(&audit.Report{}), "Not audited") {
		t.Error("nothing to say without warnings")
	}
}

func TestSARIFNamesOnlyARealVersion(t *testing.T) {
	version := func(v string) interface{} {
		t.Helper()
		data, err := SARIF(&audit.Report{}, v)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Runs []struct {
				Tool struct {
					Driver map[string]interface{} `json:"driver"`
				} `json:"tool"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		return doc.Runs[0].Tool.Driver["version"]
	}
	if got := version("v1.2.3"); got != "v1.2.3" {
		t.Errorf("version = %v", got)
	}
	for _, v := range []string{"dev", ""} {
		if got := version(v); got != nil {
			t.Errorf("version(%q) = %v; want none", v, got)
		}
	}
}
