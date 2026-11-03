package config

import (
	"reflect"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	for _, k := range []string{"INPUT_PATH", "INPUT_FAIL_ON", "INPUT_SARIF_FILE", "INPUT_IGNORE_RULES"} {
		t.Setenv(k, "")
	}
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Path != "." || c.FailOn != "high" || c.SARIFFile != "" || c.IgnoreRules != nil {
		t.Errorf("defaults = %+v", c)
	}
}

func TestLoadValues(t *testing.T) {
	t.Setenv("INPUT_PATH", "sub")
	t.Setenv("INPUT_FAIL_ON", "MEDIUM")
	t.Setenv("INPUT_SARIF_FILE", "out.sarif")
	t.Setenv("INPUT_IGNORE_RULES", " a, ,b ")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Path != "sub" || c.FailOn != "medium" || c.SARIFFile != "out.sarif" || !reflect.DeepEqual(c.IgnoreRules, []string{"a", "b"}) {
		t.Errorf("values = %+v", c)
	}
}

func TestLoadRejectsBadFailOn(t *testing.T) {
	t.Setenv("INPUT_FAIL_ON", "critical")
	if _, err := Load(); err == nil {
		t.Error("Load accepted an unknown fail_on")
	}
}
