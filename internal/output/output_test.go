package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSetOutput_File(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "github-output-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	t.Setenv("GITHUB_OUTPUT", tmpFile.Name())

	if err := SetOutput("key", "value"); err != nil {
		t.Fatalf("SetOutput() error = %v", err)
	}

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(data), "key=value") {
		t.Errorf("output file contains %q, want key=value", string(data))
	}
}

func TestSetOutput_Multiline(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "github-output-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	t.Setenv("GITHUB_OUTPUT", tmpFile.Name())

	if err := SetOutput("body", "line1\nline2"); err != nil {
		t.Fatalf("SetOutput() error = %v", err)
	}

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	content := string(data)
	if !strings.Contains(content, "body<<EOF") {
		t.Errorf("output file contains %q, want heredoc format", content)
	}
}

func TestSetOutput_Fallback(t *testing.T) {
	t.Setenv("GITHUB_OUTPUT", "")

	r, w, _ := os.Pipe()
	oldStdout := os.Stdout
	os.Stdout = w

	err := SetOutput("key", "value")

	w.Close()
	os.Stdout = oldStdout

	if err != nil {
		t.Fatalf("SetOutput() error = %v", err)
	}

	buf := make([]byte, 256)
	n, _ := r.Read(buf)
	if got := string(buf[:n]); got != "key=value\n" {
		t.Errorf("stdout = %q, want %q", got, "key=value\n")
	}
}

func TestAppendSummary(t *testing.T) {
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	if err := AppendSummary("x"); err != nil {
		t.Errorf("no summary file: %v", err)
	}
	path := filepath.Join(t.TempDir(), "s.md")
	t.Setenv("GITHUB_STEP_SUMMARY", path)
	for _, part := range []string{"a", "b"} {
		if err := AppendSummary(part); err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(path)
	if err != nil || !strings.Contains(string(got), "ab") {
		t.Errorf("summary = %q, %v", got, err)
	}
	t.Setenv("GITHUB_STEP_SUMMARY", filepath.Join(path, "nested", "s.md"))
	if err := AppendSummary("x"); err == nil {
		t.Error("expected an error for an unwritable path")
	}
}
