package main

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/somaz94/agentic-workflow-guard/internal/action"
	"github.com/somaz94/agentic-workflow-guard/internal/audit"
	"github.com/somaz94/agentic-workflow-guard/internal/config"
	"github.com/somaz94/agentic-workflow-guard/internal/output"
	"github.com/somaz94/agentic-workflow-guard/internal/report"
)

func main() {
	if err := run(os.Stdout); err != nil {
		output.LogError(err.Error())
		os.Exit(1)
	}
}

func run(w io.Writer) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	rep, err := action.Run(cfg)
	if err != nil {
		return err
	}
	report.Annotations(w, rep)
	fmt.Fprintf(w, "Scanned %d file(s): %d high, %d medium, %d low\n",
		rep.Files, rep.Count(audit.High), rep.Count(audit.Medium), rep.Count(audit.Low))

	outputs := []struct{ name, value string }{
		{"findings", strconv.Itoa(len(rep.Findings))},
		{"high", strconv.Itoa(rep.Count(audit.High))},
		{"medium", strconv.Itoa(rep.Count(audit.Medium))},
		{"low", strconv.Itoa(rep.Count(audit.Low))},
		{"warnings", strconv.Itoa(len(rep.Warnings))},
		{"sarif_file", cfg.SARIFFile},
	}
	for _, o := range outputs {
		if err := output.SetOutput(o.name, o.value); err != nil {
			output.LogWarning(fmt.Sprintf("Failed to set %s output: %v", o.name, err))
		}
	}
	if err := output.AppendSummary(report.Summary(rep)); err != nil {
		output.LogWarning(fmt.Sprintf("Failed to write job summary: %v", err))
	}
	if rep.Exceeds(cfg.FailOn) {
		return fmt.Errorf("findings at or above fail_on=%s", cfg.FailOn)
	}
	return nil
}
