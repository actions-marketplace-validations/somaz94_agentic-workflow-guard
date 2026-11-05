package output

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// LogWarning prints a warning in GitHub Actions format.
func LogWarning(msg string) {
	fmt.Printf("::warning::%s\n", EscapeData(msg))
}

// LogError prints an error in GitHub Actions format.
func LogError(msg string) {
	fmt.Printf("::error::%s\n", EscapeData(msg))
}

// EscapeData keeps text on one workflow command, so it cannot start another.
func EscapeData(s string) string {
	return strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
}

// SetOutput writes a key-value pair to the GITHUB_OUTPUT file.
func SetOutput(name, value string) error {
	outputFile := os.Getenv("GITHUB_OUTPUT")
	if outputFile == "" {
		fmt.Printf("%s=%s\n", name, value)
		return nil
	}

	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open GITHUB_OUTPUT: %w", err)
	}

	if strings.Contains(value, "\n") {
		delimiter := "EOF"
		_, err = fmt.Fprintf(f, "%s<<%s\n%s\n%s\n", name, delimiter, value, delimiter)
	} else {
		_, err = fmt.Fprintf(f, "%s=%s\n", name, value)
	}
	return errors.Join(err, f.Close())
}

// AppendSummary adds Markdown to the job summary. Outside a runner there is no
// summary file and nothing to do.
func AppendSummary(markdown string) error {
	path := os.Getenv("GITHUB_STEP_SUMMARY")
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return fmt.Errorf("failed to open GITHUB_STEP_SUMMARY: %w", err)
	}
	_, err = f.WriteString(markdown)
	return errors.Join(err, f.Close())
}
