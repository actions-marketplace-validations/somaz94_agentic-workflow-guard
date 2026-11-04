package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setup(t *testing.T, failOn string) (string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	src := "on: issues\njobs:\n  a:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: '*'\n"
	if err := os.WriteFile(filepath.Join(dir, "w.yml"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "out")
	t.Setenv("INPUT_PATH", root)
	t.Setenv("INPUT_FAIL_ON", failOn)
	t.Setenv("INPUT_SARIF_FILE", "")
	t.Setenv("INPUT_IGNORE_RULES", "")
	t.Setenv("GITHUB_OUTPUT", out)
	t.Setenv("GITHUB_STEP_SUMMARY", filepath.Join(t.TempDir(), "summary"))
	return root, out
}

func TestRunFailsOnThreshold(t *testing.T) {
	setup(t, "high")
	var b bytes.Buffer
	if err := run(&b); err == nil || !strings.Contains(err.Error(), "fail_on=high") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(b.String(), "::error file=.github/workflows/w.yml") {
		t.Errorf("output = %s", b.String())
	}
}

func TestRunReportsBelowThreshold(t *testing.T) {
	_, out := setup(t, "none")
	var b bytes.Buffer
	if err := run(&b); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"findings=1", "high=1", "medium=0", "low=0", "warnings=0", "sarif_file="} {
		if !strings.Contains(string(data), want) {
			t.Errorf("outputs missing %q:\n%s", want, data)
		}
	}
}

func TestRunBadConfig(t *testing.T) {
	setup(t, "critical")
	if err := run(&bytes.Buffer{}); err == nil {
		t.Error("bad fail_on accepted")
	}
}

func TestRunBadPath(t *testing.T) {
	setup(t, "none")
	t.Setenv("INPUT_PATH", filepath.Join(t.TempDir(), "missing"))
	if err := run(&bytes.Buffer{}); err == nil {
		t.Error("missing path accepted")
	}
}

func TestRunSurvivesUnwritableOutputs(t *testing.T) {
	setup(t, "none")
	bad := filepath.Join(t.TempDir(), "no", "dir", "x")
	t.Setenv("GITHUB_OUTPUT", bad)
	t.Setenv("GITHUB_STEP_SUMMARY", bad)
	var b bytes.Buffer
	if err := run(&b); err != nil {
		t.Fatal(err)
	}
}

// The fixtures back the CI jobs, so a change in what they produce shows here first.
func TestFixtures(t *testing.T) {
	cases := []struct {
		dir, want string
	}{
		{"../testdata/clean", "findings=0"},
		{"../testdata/risky", "high=5"},
		{"../testdata/risky", "medium=3"},
		{"../testdata/risky", "low=1"},
		{"../testdata/indirect", "high=2"},
		{"../testdata/indirect", "medium=1"},
		{"../testdata/indirect", "low=2"},
	}
	for _, c := range cases {
		_, out := setup(t, "none")
		t.Setenv("INPUT_PATH", c.dir)
		if err := run(&bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), c.want) {
			t.Errorf("%s: outputs missing %q:\n%s", c.dir, c.want, data)
		}
	}
}
