package action

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/somaz94/agentic-workflow-guard/internal/config"
)

func repo(t *testing.T) string {
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
	return root
}

func TestRunWritesSARIF(t *testing.T) {
	root := repo(t)
	path := filepath.Join(t.TempDir(), "out.sarif")
	r, err := Run(&config.Config{Path: root, SARIFFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 {
		t.Errorf("findings = %+v", r.Findings)
	}
	data, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(data), `"ruleId": "open-invocation"`) {
		t.Errorf("sarif = %s, %v", data, err)
	}
}

func TestRunWithoutSARIF(t *testing.T) {
	if _, err := Run(&config.Config{Path: repo(t)}); err != nil {
		t.Fatal(err)
	}
}

func TestRunErrors(t *testing.T) {
	if _, err := Run(&config.Config{Path: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Error("missing path accepted")
	}
	bad := filepath.Join(t.TempDir(), "no", "dir", "out.sarif")
	if _, err := Run(&config.Config{Path: repo(t), SARIFFile: bad}); err == nil {
		t.Error("unwritable sarif accepted")
	}
}

func TestRepoName(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "acme/app")
	t.Setenv("GITHUB_WORKSPACE", "/w")
	for path, want := range map[string]string{".": "acme/app", "/w": "acme/app", "testdata/x": "", "/other": ""} {
		if got := repoName(path); got != want {
			t.Errorf("repoName(%q) = %q; want %q", path, got, want)
		}
	}
}
