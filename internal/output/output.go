package output

import (
	"fmt"
	"os"
	"strings"
)

// LogInfo prints an info-level message in GitHub Actions format.
func LogInfo(msg string) {
	fmt.Println(msg)
}

// LogWarning prints a warning in GitHub Actions format.
func LogWarning(msg string) {
	fmt.Printf("::warning::%s\n", msg)
}

// LogError prints an error in GitHub Actions format.
func LogError(msg string) {
	fmt.Printf("::error::%s\n", strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(msg))
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
	defer func() { _ = f.Close() }()

	if strings.Contains(value, "\n") {
		delimiter := "EOF"
		_, err = fmt.Fprintf(f, "%s<<%s\n%s\n%s\n", name, delimiter, value, delimiter)
	} else {
		_, err = fmt.Fprintf(f, "%s=%s\n", name, value)
	}
	return err
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
	defer func() { _ = f.Close() }()
	_, err = f.WriteString(markdown)
	return err
}
